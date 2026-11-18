# Parrot: agent API (`/portal/api/agent/*`)

What the native agent needs from parrot. `dev/stub-parrot.mjs` implements it for local runs;
`core/riot-api` is the client. Wire shapes reuse the browser extension's where they exist, so
one admin policy drives both products.

## Auth

| Call | Credential |
|---|---|
| `POST enroll` | `Authorization: Bearer rbx_…` (the workspace secret the extension already uses) + `X-Workspace-Id` |
| everything else | `Authorization: Bearer <device_token>` from `enroll` |

Every call also sends `X-Agent-Version`. A 401 on the device token makes the agent drop it and
enroll again at once; if enrolling is refused too (bad `rbx_` secret), it retries with the
extension's backoff (15 → 30 → 60 min). Reuse `browser_extension_auth_plug.ex` for the `rbx_` check;
the device token is new (store its SHA-256, like the workspace secret).

## `POST /api/agent/enroll`

```json
{
  "workspace_id": "…", "hardware_uuid": "…", "serial_number": "C02…", "hostname": "…",
  "os": "macos", "os_version": "27.2", "agent_version": "0.1.0",
  "employee_email": "camille.martin@acme.com"
}
```
→ `200 {"device_id": "uuid", "device_token": "rad_…"}`

- Idempotent on `(workspace_id, hardware_uuid)`: re-enrolling the same Mac returns the same
  `device_id` and rotates the token.
- `employee_email` comes from the MDM's variable substitution and may be absent. Resolve the
  employee by email (active employees of the workspace); keep `employee_id` null when unmatched.
- Link to `Parrot.Devices` (`employee_devices`) by serial number / hardware id when the device is
  already known from Intune or Google.

New table `agent_devices`: `id`, `workspace_id`, `organization_id`, `employee_id` (nullable),
`hardware_uuid`, `serial_number`, `hostname`, `os`, `os_version`, `agent_version`,
`device_token_hash`, `last_seen_at`, `status` (jsonb, last heartbeat), `employee_device_id`
(nullable), timestamps. Unique `(workspace_id, hardware_uuid)`.

## `GET /api/agent/config`

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

## `POST /api/agent/heartbeat`

```json
{ "agent_version": "0.1.0", "os_version": "27.2",
  "components": { "daemon": "running", "monitoring": true, "engineHeapMib": 10.9,
                  "pendingReports": 0, "esExtension": null, "menuBarApp": null } }
```
→ `204`. Updates `last_seen_at` and `status`. This is the base of the future MDM inventory:
admins see which Macs run the agent, its version, and whether every component is healthy.

## `POST /api/agent/sensitive_data_report`

Exactly the extension's `SendSensitiveDataReportInput` (counts only, never values), with
`service_id` from the service owning the desktop app. Upsert on `session_id`: the agent re-sends
the same report with `text.redacted: false` when the user pastes the original. File `key` is the
extension's `fileKey` (SHA-256 of `[name, size, lastModified, type]`). `authorization_status` is
omitted (see the open question above). → `200 {"recorded": true}`, `422` on invalid input (the
agent then drops the report).
