# riotctl

`riotctl` talks to a running daemon from a terminal: it sends one request over the daemon's
socket (the same line-delimited JSON as Riot.app, `core/riot-ipc`) and prints the reply as JSON.
It is built with the daemon (`core/target/release/riotctl`) and shipped in
`Riot.app/Contents/MacOS/riotctl`.

```sh
riotctl <command> [args]
```

| Env           | Default                                  | Notes                                                |
| ------------- | ---------------------------------------- | ---------------------------------------------------- |
| `RIOT_SOCKET` | `/var/run/com.tryriot.agent/agent.sock`  | `dev/run-dev.sh` listens on `$TMPDIR/riot-dev.sock`. |

Exit codes: `0` success, `1` cannot connect or the daemon returned an error
(`badRequest`, `forbidden`, `unavailable`, `internal`, printed on stderr), `2` bad usage.

Against the dev daemon:

```sh
export RIOT_SOCKET=$TMPDIR/riot-dev.sock
core/target/release/riotctl status
```

## Commands

### State

| Command     | Does                                                                                     |
| ----------- | ---------------------------------------------------------------------------------------- |
| `status`    | Version, configured, device id, monitoring, paused, last sync and error, engine heap, protected apps (installed or not), reports waiting to be sent. |
| `popup`     | What the menu bar popup shows: view (`loading`, `notConfigured`, `standby`, `signedIn`, `reconnect`, `error`), bot name and icon, company, bypass allowed, protected apps, recent events (content-free). |
| `refresh`   | Refetch config and policies from parrot now, instead of waiting for the next sync.        |
| `watch`     | Subscribe and print each pushed event, one JSON line each, until interrupted: `stateChanged`, `fileBlocked` (file name, app, types, bypass allowed). |
| `es-config` | What the ES extension watches: protected apps' bundle ids, team ids and executable path prefixes, and the file extensions scanned. Empty `watched` when monitoring is off. |
| `pause [pid]` | Root only. Stop applying the policy until `resume`, the daemon's next start, or, with a pid, the end of that process (checked every second): no protected app, so no clipboard guard, no flow taken by the network extension, nothing redacted; the popup shows `standby`, `status` and the heartbeat `paused`. `dev/run-dev.sh` pauses an installed agent with its own pid. |
| `resume`    | Root only. Apply the policy again.                                                       |

### Text

| Command                        | Does                                                                     |
| ------------------------------ | ------------------------------------------------------------------------ |
| `redact <bundle-id> <text>`    | Redact `text` as if it were pasted into that app. `action` is `redacted` (with `text`, `types`, `eventId`), `clean`, `skipped` (not a protected app, or monitoring off) or `error` (engine failure). Nothing is reported: the clipboard guard calls this ahead of a paste that may never come. |
| `detok <bundle-id> <text>`     | Put back the values of the tokens in `text` (`[IBAN_1]` → the IBAN), as for a copy out of that app. Returns `text` and the number `replaced`. |
| `paste <event-id>`             | Report a paste of a `redact` event's text: queues a report for parrot and adds a recent event. Returns a `pasteId`. Each call is a separate paste and report. |
| `override <paste-id>`          | "Paste without redaction": re-sends that paste's report as not redacted. `forbidden` if the policy does not allow bypass. |

Token memory is per user and per app: tokens from `redact` resolve with `detok` only for the
same bundle id, and only from the same user. As riotctl runs as you, it shares that memory
with Riot.app.

### Files

| Command                    | Does                                                                          |
| -------------------------- | ----------------------------------------------------------------------------- |
| `scan <bundle-id> <path>`  | Scan a file as if that app opened it, with a 10 s deadline: `decision` (`allow`, `deny`), `reason` (`clean`, `detections`, `bypass`, `unsupported`, `notTarget`, `disabled`, `error`, `timeout`), `types`, `eventId`. A `deny` is pushed to `watch` as `fileBlocked`. Reserved to root (the ES extension), unless the daemon runs with `RIOT_DEV_ALLOW_SCAN=1`, as `dev/run-dev.sh` does. |
| `bypass <event-id>`        | "Send anyway" for a blocked file: the next open of that same file (same inode and mtime) within 60 s is allowed. `forbidden` if the policy does not allow bypass. |

## Walkthrough

A paste into ChatGPT, then the original pasted instead:

```sh
$ riotctl redact com.openai.codex "Mon IBAN FR76 3000 6000 0112 3456 7890 189"
{
  "action": "redacted",
  "text": "Mon IBAN [IBAN_1]",
  "types": [{ "flag": "…", "label": "…", "count": 1 }],
  "eventId": "<event-id>",
  "allowBypass": true
}
$ riotctl paste <event-id>          # → { "pasteId": "<paste-id>" }, a report is queued
$ riotctl override <paste-id>       # the same report, now redacted: false
$ riotctl detok com.openai.codex "Ton IBAN est [IBAN_1]"
```

A blocked file, then "send anyway" (in another shell, `riotctl watch` shows `fileBlocked`):

```sh
$ riotctl scan com.anthropic.claudefordesktop ~/Documents/payslip.pdf   # deny, eventId
$ riotctl bypass <event-id>
```

`paste` and `override` send real reports to the configured parrot (the stub's
`/portal/_stub/state` lists them in dev).
