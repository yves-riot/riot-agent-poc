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

**Enrollment keys (`rae_`)** are not the browser extension's `rbx_` secret: they only enroll, so a
leak (the MDM's managed preferences are readable by every local user) gives no access to the
extension's API nor to any enrolled device. A workspace has as many as the admin creates, each
with a label, an optional expiry and usage cap, and revoked on its own; rotating one breaks no
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

So a leaked enrollment key cannot take over a Mac that is in use: at worst it queues a device for
approval. A pending device gets no intermediate and every other call is refused; the agent
enrolls again every 5 minutes and shows "waiting for an admin" meanwhile.

- `employee_email` comes from the MDM's variable substitution and may be absent. It is a claim:
  resolve the employee by email (active employees of the workspace), and set `employee_verified`
  only when the MDM's inventory (`Parrot.Devices`, Intune or Google) assigns this serial number to
  that employee. Keep `employee_id` null when unmatched.
- Link to `Parrot.Devices` (`employee_devices`) by serial number / hardware id when the device is
  already known from Intune or Google.
- `ca_csr`: parrot checks its signature (proof of the gateway key) and signs an intermediate for
  its key; nothing else in the request is used (see below).

## `POST /api/renew_agent_intermediate_ca`

`{"ca_csr": "-----BEGIN CERTIFICATE REQUEST-----…"}` → `200 {"intermediate_pem": "…"}`, `422` on an
invalid CSR. The agent calls it when its intermediate has less than 10 days left (every ~20 days).

The chain (`core/riot-api/src/ca.rs`):

| | Key | Issued by | Content |
|---|---|---|---|
| organization root | KMS (`ECC_NIST_P256`, `SIGN_VERIFY`), never exported | itself | `CA:TRUE, pathlen:1`, 10 years |
| intermediate | generated on the Mac, never leaves it | the root, `KMS.Sign` | `CA:TRUE, pathlen:0`, 30 days, `CN=Riot AI gateway <device_id>` |
| leaf | the daemon's, in memory | the intermediate | one per AI host, 7 days |

Root and intermediate carry critical name constraints (`anthropic.com`, `claude.ai`, `openai.com`,
`chatgpt.com`): nothing they sign is valid for another site. One root per organization, created
when the agent is enabled; the admin portal serves its certificate for the MDM profile. Revoking
a device stops its renewals: its intermediate dies within 30 days (clients do not check
revocation for a private root, so the short life is the revocation). Keep each intermediate's
serial, fingerprint, device and expiry (audit).

## Tables

- `agent_enrollment_keys`: `id` (the `key_id`), `workspace_id`, `organization_id`, `secret_hash`,
  `label`, `expires_at`, `max_uses`, `uses`, `revoked_at`, `created_by`, timestamps.
- `agent_devices`: `id`, `workspace_id`, `organization_id`, `employee_id` (nullable),
  `employee_verified`, `hardware_uuid`, `serial_number`, `hostname`, `os`, `os_version`,
  `agent_version`, `public_key` (JWK), `public_key_thumbprint`, `approval_status` (`active`,
  `pending_approval`, `revoked`), `enrollment_key_id`, `last_seen_at`, `status` (jsonb, last
  heartbeat), `employee_device_id` (nullable), timestamps. Unique `(workspace_id,
  public_key_thumbprint)`; index `(workspace_id, hardware_uuid)`.
- `organization_agent_cas`: `organization_id`, `kms_key_id`, `root_cert_der`, `not_after`.
- `agent_intermediates`: `device_id`, `serial`, `sha256`, `not_after`, `inserted_at`.

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

### Policy: one addition

`SensitiveDataMonitoringService` gains an optional `desktop_apps`; everything else is the
extension's `browser_extension_sensitive_data_monitoring` policy unchanged (`enabled`,
`allow_bypass_redaction`, `data_types`).

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
| `team_id` | signing team, to check before trusting a bundle id (ES side, later) |
| `executable_prefixes` | ES extension: the processes whose file opens are checked (app + helpers) |

It also gains an optional `api_hosts`: the API hosts the local gateway redacts requests to
([network-interception.md](network-interception.md#local-gateway)).

```json
"api_hosts": ["api.anthropic.com", "claude.ai"]
```

`api.anthropic.com` covers Claude Code, `claude.ai` Claude Desktop's conversations
([Connect RPC](network-interception.md#connect-rpc-claude-desktop)).

Catalog values seen on a real Mac (Nov 2026): ChatGPT is `com.openai.codex`, Claude Desktop is
`com.anthropic.claudefordesktop`. The catalog lives next to the extension's
(`browser_extension_sensitive_data_monitoring_services.ex`).

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
