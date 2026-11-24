# Parrot: agent API (Portal API, `/portal/api/…_agent_…`)

What the native agent needs from parrot. `riot-stub-parrot` (`core/riot-daemon/src/bin/stub_parrot.rs`)
implements it for local runs and tests; `core/riot-api` is the client. Wire shapes reuse the
browser extension's where they exist, so one admin policy drives both products.

## Overview

```
 ADMIN (parrot portal)          MDM                 MAC (daemon, root)                       PARROT                 KMS
 1. enable the agent ──────────────────────────────────────────────────────────────────────▶ org root ────────▶ CreateKey P-256
 2. enrollment key rae_… ◀────────────────────────────────────────────────────────────────── SHA-256 kept
 3. root certificate (public)
 4. profile: root + ApiUrl + EnrollmentKey ─▶ push ─▶ root trusted by the system
                                                    generates, once: device key, gateway key
                                                    5. enroll_agent_device ───────────────▶ rae_ ok, proof ok
                                                       rae_ + proof + JWK + CSR             signs the intermediate ─▶ Sign
                                                    ◀── device_id, status, intermediate
                                                    6. config, heartbeat, reports ───────▶ proof against the JWK
                                                    7. ~20 days: renew_agent_intermediate_ca ▶ new intermediate ─────▶ Sign
```

One call enrolls the Mac and gets its intermediate. Nothing on the Mac is a bearer credential
for the device: a stolen `enrollment.json` or log line authenticates nothing.

## Auth

| Call | Credential |
|---|---|
| `POST enroll_agent_device` | `Authorization: Bearer rae_<key_id>_<secret>` (the workspace's agent enrollment key) and `X-Device-Proof: <proof>` signed by the key being registered, `sub` = `hardware_uuid` |
| everything else | `Authorization: Bearer <proof>` signed by the device key, `sub` = `device_id` |

Every call also sends `X-Agent-Version`.

**Enrollment keys (`rae_<uuid>_<base64url secret>`)** are not the browser extension's `rbx_` secret: they only enroll, so a
leak (the MDM's managed preferences are readable by every local user) gives no access to the
extension's API nor to any enrolled device. A workspace has as many as the admin creates, each
with a label and an optional expiry, and revoked on its own; rotating one breaks no
extension and no enrolled Mac. `rae_<key_id>_<secret>`: parrot finds the key by `key_id` (indexed),
compares SHA-256(`secret`) in constant time, and takes the workspace from the key. `rbx_` is
refused.

**Proofs** are ES256 JWTs (`core/riot-api/src/device_key.rs`): header
`{"alg":"ES256","typ":"riot-agent+jwt"}`, claims `sub`, `htm` and `htu` (the request's method and
path, e.g. `GET` `/portal/api/get_agent_config`), `iat`, `exp` (at most 300 s later), `jti`. Parrot
checks the signature against the device's registered JWK, `typ`, `sub`, `htm`, `htu`, `exp`, `iat`
(60 s skew), and refuses a `jti` it saw before its `exp`. The device must be active.

A 401 on a device call makes the agent enroll again at once, with the same device key (it gets
its device back). If enrolling is refused too, it retries with the extension's backoff
(15 → 30 → 60 min). Rate-limit enrollment per workspace (`Parrot.RateLimiter`) and alert on a burst.

## `POST /api/enroll_agent_device`

```json
{
  "hardware_uuid": "…", "serial_number": "C02…", "hostname": "…",
  "os": "macos", "os_version": "27.2", "agent_version": "0.1.0",
  "employee_email": "camille.martin@acme.com",
  "device_public_key": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" },
  "ca_csr": "-----BEGIN CERTIFICATE REQUEST-----…"
}
```
→ `200 {"device_id": "uuid", "status": "active", "intermediate_pem": "-----BEGIN CERTIFICATE-----…"}`,
or `{"device_id": "uuid", "status": "pending_approval", "intermediate_pem": null}`.

Decided on `(workspace_id, hardware_uuid)`, the workspace being the enrollment key's:

| This Mac in the workspace | Outcome |
|---|---|
| none | new device, `active` |
| a device with the same key (thumbprint) | that device, its status; nothing rotates |
| an active device with another key, seen in the last 30 days | new device, `pending_approval`: an admin approves it (the old one is then revoked) |
| an active device with another key, silent for 30 days | new device, `active`; the old one is revoked |

A new device that would be `active` is `pending_approval` instead unless `employee_email` names
an employee of the workspace who has no other active device seen in the last 30 days. The
enrollment key is readable by every user of every Mac (managed preferences are world-readable),
and any active device gets an intermediate that every Mac of the organization trusts
([the risk](network-interception.md#the-ca-in-production-decided)): without this rule a copied key
would enroll invented Macs at will. With it, a copied key gets at most one device per employee
who has none yet (an email of a colleague not enrolled yet), and the real Mac that finds its
employee taken waits for an admin, who then sees the impostor. An employee's second Mac, and a
Mac whose email the MDM did not substitute, also wait for an admin.

So a leaked enrollment key cannot take over a Mac that is in use: at worst it queues a device for
approval. A pending device gets no intermediate and every other call is refused; the agent
enrolls again every 5 minutes and shows "waiting for an admin" meanwhile.

- `employee_email` comes from the MDM's variable substitution and may be absent. It is a claim:
  resolve the employee by email (active employees of the workspace); `employee_verified` is for
  when the MDM's inventory confirms it (not done, see Tables). Keep `employee_id` null when
  unmatched.
- `ca_csr`: parrot checks its signature (proof of the gateway key) and signs an intermediate for
  its key; nothing else in the request is used (see below).

## `POST /api/renew_agent_intermediate_ca`

`{"ca_csr": "-----BEGIN CERTIFICATE REQUEST-----…"}` → `200 {"intermediate_pem": "…"}`, `422` on an
invalid CSR. The agent calls it when its intermediate has less than 3 days left (every ~4 days).

The chain (`core/riot-api/src/ca.rs`):

| | Key | Issued by | Content |
|---|---|---|---|
| organization root | KMS (`ECC_NIST_P256`, `SIGN_VERIFY`), never exported | itself | `CA:TRUE, pathlen:1`, 10 years |
| intermediate | generated on the Mac, never leaves it | the root, `KMS.Sign` | `CA:TRUE, pathlen:0`, 7 days, `CN=Riot AI gateway <device_id>` |
| leaf | the daemon's, in memory | the intermediate | one per AI host, 7 days |

Root and intermediate carry critical name constraints (`anthropic.com`, `claude.ai`, `openai.com`,
`chatgpt.com`): nothing they sign is valid for another site. One root per organization, created
when the agent is enabled; the MDM profile carries its certificate. Revoking
a device stops its renewals: its intermediate dies within 7 days (clients do not check
revocation for a private root, so the short life is the revocation). Keep each intermediate's
serial, fingerprint, device and expiry (audit).

## Admin (Riot API, `sonar:write`, `get_agent_root_certificate` `sonar:read`)

| Route | Does |
|---|---|
| `POST /v3/generate_agent_mdm_profile` | returns `{profile, filename, enrollment_key_id}`: the whole MDM profile, filled (below), with a new key that does not expire, labelled "MDM profile" |
| `POST /v3/generate_agent_enrollment_key` `{label, expires_in_days?}` | returns `{id, label, enrollment_key, expires_at}`, the key shown once; creates the organization's root on the first call |
| `POST /v3/revoke_agent_enrollment_key` `{id}` | the key stops enrolling; enrolled Macs keep working |
| `GET /v3/get_agent_root_certificate` | `{certificate_pem}`, for the profile; 404 until the first key |
| `POST /v3/approve_agent_device` `{id}` | a pending device becomes active, the Mac's other devices are revoked |
| `POST /v3/revoke_agent_device` `{id}` | the device's calls are refused, its intermediate is not renewed |

Each one is audit-logged (`agent_enrollment_key.generate`, `.revoke`, `agent_device.approve`,
`.revoke`, internal actions like `browser_extension_secret.generate`).

### The MDM profile

What an admin deploys is the agent app from the MDM's catalog (it carries nothing specific to a
customer, so one package serves them all, and the MDM updates it) and this profile, uploaded once.
The profile lives in parrot only (`priv/desktop_agent/riot-agent.mobileconfig.eex`), which fills
it with:

- the Apple team that signs the agent (`DESKTOP_AGENT_APPLE_TEAM_ID`; without it the route answers
  `agent_not_distributed`) and the app's bundle id (`DESKTOP_AGENT_APP_BUNDLE_ID`, default
  `com.tryriot.agent`);
- the organization's root, created on the way if needed;
- a new enrollment key: it does not expire, since an expired key would silently stop new Macs from
  enrolling, and it only enrolls new Macs. Each call mints one; earlier profiles keep working until
  their key is revoked;
- `EmployeeEmail` `$EMAIL`, which Iru, Kandji and Jamf substitute;
- `ApiUrl` only when parrot is not production (`https://albert.tryriot.com/portal`, the agent's
  default, `DEFAULT_API_URL`): the URL then moves with the app, which the MDM updates, not with
  the profile, which nobody re-uploads.

The profile changes only when its key is revoked or the root is replaced. It names the app's
pieces (the extensions' bundle ids, the daemon's path and signing identifier), so a change to
them, or a new permission, is made in parrot's template with the agent release; older agents ignore
a payload they do not use. An agent version that needs a new payload must keep working without it
until the admin uploads the new profile.

## Tables (parrot: `Parrot.DesktopAgent`)

- `agent_enrollment_keys`: `id` (the `key_id`), `workspace_id`, `organization_id`, `secret_hash`,
  `label`, `expires_at`, `revoked_at`, `uses`, `last_used_at`, timestamps.
- `agent_devices`: `id`, `workspace_id`, `organization_id`, `employee_id` (nullable),
  `employee_verified`, `enrollment_key_id`, `hardware_uuid`, `serial_number`, `hostname`, `os`,
  `os_version`, `agent_version`, `public_key` (JWK), `public_key_thumbprint`, `approval_status`
  (`active`, `pending_approval`, `revoked`), `last_seen_at`, `status` (last heartbeat),
  timestamps. Unique `(workspace_id, public_key_thumbprint)`; index `(workspace_id, hardware_uuid)`.
- `organization_agent_cas`: `organization_id`, `key_ref` (the KMS key id), `root_cert_der`, `not_after`.
- `agent_intermediates`: `agent_device_id`, `workspace_id`, `organization_id`, `serial_number`,
  `sha256`, `not_after`, `created_at`.

Proofs already accepted are kept until they expire in `Parrot.DesktopAgent.ProofReplayCache`
(Nebulex, replicated), so a `jti` is accepted once across the cluster.

**Not done:** `employee_verified` stays false. Parrot's device inventory (`employee_devices`, from
Intune and Google) has no serial number column to match the Mac against, so the employee is
attributed from the MDM's email, as the extension's `X-Employee-Email` is.

## `GET /api/get_agent_config`

One call for what the extension gets in three (identity, workspace info, policies):

```json
{
  "employee": { "id": "…", "name": "Camille Martin", "emails": ["…"], "redactions_last_30_days": 12, "locale": "fr" },
  "workspace": { "id": "…", "branding_name": "Acme", "logo_url": null, "portal_url": "https://…",
                 "default_locale": "fr", "bot_branding": { "name": "Albert", "icon_url": null } },
  "policies": [ SonarPolicy ]
}
```

`employee` is `null` when the device has no matching employee (the popup then shows
"Account not recognized"). `redactions_last_30_days` should count the employee's redactions from
both the extension and the agent.

### Policy: two additions

`SensitiveDataMonitoringService` gains `desktop_apps` and `api_hosts`; everything else is the
extension's `browser_extension_sensitive_data_monitoring` policy unchanged (`enabled`,
`allow_bypass_redaction`, `data_types`). Parrot sends both on every service, empty for a service
the agent does not cover, and to the extension too, which ignores them.

```json
"desktop_apps": [
  { "platform": "macos", "bundle_id": "com.openai.codex", "team_id": "2DC432GLL2",
    "executable_prefixes": ["/Applications/ChatGPT.app/"] }
]
```

| Field | Use |
|---|---|
| `platform` | `macos` now, `windows` later (`bundle_id` then becomes an AUMID / exe name) |
| `bundle_id` | clipboard guard: which frontmost app is protected |
| `team_id` | network extension: a process signed by this team is the app's; otherwise, one under `executable_prefixes` |
| `executable_prefixes` | ES extension: the processes whose file opens are checked (app + helpers) |

`api_hosts`: the API hosts the local gateway redacts requests to
([network-interception.md](network-interception.md#local-gateway)). The network extension
claims a protected app's flows to them only, so a host does nothing without its app in
`desktop_apps`, except through the development `HTTPS_PROXY`.

```json
"api_hosts": ["api.anthropic.com", "claude.ai"]
```

`api.anthropic.com` covers Claude Code, `claude.ai` Claude Desktop's conversations
([Connect RPC](network-interception.md#connect-rpc-claude-desktop)). Every host must sit under
the CA's name constraints (anthropic.com, claude.ai, openai.com, chatgpt.com): a test of the
catalog checks it.

Parrot's catalog (`browser_extension_sensitive_data_monitoring_services.ex`, next to the
extension's) covers Claude and ChatGPT, with the values `dev/stub-policy.json` has, seen on a
real Mac (Nov 2026): ChatGPT is `com.openai.codex`, Claude Desktop is
`com.anthropic.claudefordesktop`.

**Open product question:** services marked `authorized` get account detection in the browser
(work vs personal account). The agent cannot tell which account a desktop app is signed into, so
it currently guards every listed desktop app. Options: keep guarding, or let admins mark a
desktop app as trusted.

## `POST /api/send_agent_heartbeat`

```json
{ "agent_version": "0.1.0", "os_version": "27.2",
  "components": { "daemon": "running", "monitoring": true, "paused": false, "engineHeapMib": 10.9,
                  "pendingReports": 0, "esExtension": null, "menuBarApp": null } }
```
→ `204`. Updates `last_seen_at` and `status`. This is the base of the future MDM inventory:
admins see which Macs run the agent, its version, and whether every component is healthy.
`paused`: root paused the agent on the Mac (`riotctl pause`, development), which then applies
no policy.

## `POST /api/send_agent_sensitive_data_report`

Exactly the extension's `SendSensitiveDataReportInput` (counts only, never values), with
`service_id` from the service owning the desktop app. Upsert on `session_id`: the agent re-sends
the same report with `text.redacted: false` when the user pastes the original. File `key` is the
extension's `fileKey` (SHA-256 of `[name, size, lastModified, type]`). `authorization_status` is
omitted (see the open question above). → `200 {"recorded": true}`, `422` on invalid input (the
agent then drops the report).
