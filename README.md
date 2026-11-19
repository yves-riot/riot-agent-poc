# Riot agent (POC, macOS)

The browser extension's sensitive-data protection, at the OS level, for AI desktop apps
(ChatGPT, Claude…): sensitive text copied into them is tokenized before it can be pasted, and
documents holding sensitive data are blocked from being opened by them. Installed and authorized
entirely by MDM; the daemon is the base of Riot's future MDM agent.

```
Riot.app (menu bar, SwiftUI)  ── clipboard guard + HUD + popup
      │  Unix socket, line-delimited JSON (core/riot-ipc)
riot-daemon (Rust, root)      ── detection engine, policy, parrot sync, report outbox
      ▲  same socket (scanFile with deadline)
RiotES.systemextension        ── Endpoint Security AUTH_OPEN on the protected apps' processes
```

**Detection is the extension's own code.** `js/` bundles `@tryriot/sonar-detection` (and the
token memory of `@tryriot/sonar-guard-core`) from the extension's `feat/shared-sonar-packages`
branch; `core/riot-detect` runs it on an embedded QuickJS. What the browser provided natively
is provided by Rust: UTF-8 decoding and pdf text extraction (`pdf-extract` + `lopdf`, standing
in for pdf.js).

Why Rust, QuickJS and native apps: [docs/stack-choices.md](docs/stack-choices.md).

## Layout

| Path                                 | What                                                                                                                                    |
| ------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------- |
| `js/`                                | esbuild bundle of the extension's engine + QuickJS polyfills (`dist/detection.js`), and its conformance runner (`dist/conformance.js`)  |
| `core/riot-detect`                   | QuickJS host: `redact` (numbered tokens per app), `detokenize`, `detect`, `scan_bytes`/`scan_path`, deadlines via the interrupt handler |
| `core/riot-api`                      | parrot client (`docs/parrot-agent-api.md`)                                                                                              |
| `core/riot-ipc`                      | local protocol types + blocking client                                                                                                  |
| `core/riot-daemon`                   | the daemon (`riot-daemon`), its local API gateway (`src/gateway/`), and a CLI (`riotctl`)                                               |
| `apple/RiotAgent`                    | menu bar app (SwiftPM): popup, clipboard guard, HUD, installer                                                                          |
| `apple/RiotES`                       | Endpoint Security system extension                                                                                                      |
| `apple/RiotNE`                       | network system extension: transparent proxy handing protected apps' TLS flows to the daemon                                             |
| `apple/build-app.sh`, `build-pkg.sh` | `Riot.app` and the MDM `.pkg`                                                                                                           |
| `mdm/`                               | configuration profile template + renderer, a test fleet's CA ([docs/deploy-iru.md](docs/deploy-iru.md))                                 |
| `dev/`                               | the stub parrot's policy (`stub-policy.json`, for `riot-stub-parrot`), dev settings, `run-dev.sh`                                       |

## Run it locally

Needs Rust, Node + pnpm, Xcode (for the SwiftUI macros), and a checkout of
`tryriot/riot-browser-extension` on branch `feat/shared-sonar-packages` (`SONAR_PACKAGES_DIR`,
default `~/dev/riot/riot-browser-extension/packages`):

```sh
git clone -b feat/shared-sonar-packages git@github.com:tryriot/riot-browser-extension.git \
  ~/dev/riot/riot-browser-extension
(cd js && pnpm install && node build.mjs)
dev/run-dev.sh      # builds apple/build/Riot.app (build-app.sh, ad-hoc), then runs the stub parrot,
                    # the daemon (unprivileged) and the menu bar app (its icon says "DEV")
```

`RIOT_DEV_APP=0` runs without the menu bar app, `RIOT_DEV_BUILD=0` runs the last build as it is.

On a Mac where the agent is installed (a test fleet's, [docs/deploy-iru.md](docs/deploy-iru.md)),
`run-dev.sh` pauses it for the run (`sudo riotctl pause`, the password once) and resumes it when
the run ends, however it ends (`riotctl pause <pid>`: the installed daemon resumes once the
script is gone), so that only the dev agent guards the clipboard and the AI apps; the installed
menu bar app shows "standby" meanwhile, next to the dev one, whose icon says "DEV". Its daemon still holds the gateway's port, 7591: the
dev gateway takes 7601, and says so. Everything else of a dev run is its own (socket, data
folder, CA, stub on 8787).

`RIOT_SOCKET=$TMPDIR/riot-dev.sock core/target/release/riotctl status|popup|watch|…`
talks to the daemon directly; `scan` works unprivileged because `run-dev.sh` sets
`RIOT_DEV_ALLOW_SCAN=1`. Every command: [docs/riotctl.md](docs/riotctl.md).

## Tests

```sh
cd core && cargo test                      # incl. the extension's conformance corpus on QuickJS
cargo run -p riot-detect --release --example bench    # latency / memory
cd apple/RiotAgent && DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer swift test
```

## Results so far (MacBook Air M2, release builds)

- **Parity:** the extension's conformance corpus (236 cases: every rule, pipeline, real-world
  documents, NLP names, txt/csv/docx/xlsx/pdf) passes 236/236 on QuickJS, pdf through the native
  extractor.
- **Memory:** daemon 16 MB, menu bar app 21 MB (`phys_footprint`), 0 % CPU idle.
  `Riot.app` is 9.8 MB.
- **Latency:** paste 1 KB 20 ms, 10 KB 160 ms, 64 KB 330 ms; a 1 MiB text file 3.3 s.
  Redaction runs on the switch to the AI app, before the paste, so it is not in the user's way.
  The floor on small pastes is `compromise` (about 130 ms per 10k-char chunk).
- **QuickJS and slicing:** the phone detector used to slice the whole remaining text per match,
  O(1) on V8 but a copy on QuickJS: a 1 MiB scan took 12.3 s. Its currency check is now a sticky
  regex tested at the match end, upstream in `sonar-detection`: 3.3 s, the engine bundled
  unpatched. Any `text.slice(i)` in a per-match loop has the same cost here.
- **Clipboard:** verified on macOS 27.2 against TextEdit: swap on activation, restore on leave,
  detokenize of copied answers, HUD. No pasteboard-privacy alert was raised on this Mac.
  Since then, the redacted text is a promised pasteboard item: the HUD and the report wait for
  the read that a paste does (⌘V, Edit menu, context menu). A read 150 ms or more after the
  promise was written is a paste; an earlier one is a clipboard manager or a sync reacting to
  the write. Claude Desktop reads only to paste (no read on activation in 2 to 6 s), 0.3 to
  1.8 s after the write. The promise is re-armed 0.5 s after a read (done at once, it emptied 6 reads in
  20), and a re-armed promise counts a read as a paste only while ⌘ is held.
  Guessing the gesture from `CGEventSource.secondsSinceLastEventType` did not work: without
  Input Monitoring those counters move in 0.5 s steps and late, so a ⌘V read 0.3 s later still
  looked like the gesture before it.

## Clipboard and drag guard

- **"Paste without redaction"** puts the original back on the clipboard, then sends ⌘Z and ⌘V
  to the AI app (the HUD takes no focus), so the original replaces the redacted paste. Sending
  keys needs the Accessibility permission: grant it with a PPPC profile under MDM; otherwise
  the first click asks for it. The keys are looked up in the current keyboard layout (⌘Z is
  not on the same key in AZERTY). Nothing is sent, and the HUD tells the user to undo and paste
  again, without the permission, once the AI app is no longer frontmost, or if a key was
  pressed more than 1 s after the paste (⌘Z would undo that typing). Only the last paste is
  replaced. A message sent with the mouse since the paste is not detected: ⌘Z then has
  nothing to undo, and the original lands in the empty field. Builds signed ad hoc
  (`SIGN_IDENTITY` unset) lose the permission on each rebuild.
- **Drag and drop of text** (`DragGuard`): a text drag is replaced with a
  promise on the drag pasteboard, read by the app under the pointer: a protected app gets the
  text redacted at that moment (a blocking daemon call, 2 s at most), others the original, or
  the values back for a drag out of a protected app. HUD and report on release over the
  protected app. The text of every text drag is read when it starts (detection runs only for a
  protected app). Files and images are left to RiotES. Verified with Claude and ChatGPT.
- **File blocking** (`RiotES`, Endpoint Security): verified in a macOS 26 VM against Claude
  Desktop. A protected app is recognised by its signing team id (the policy's `team_id`), or by
  its executable's folder for apps without one; its descendants are protected too. That covers
  Claude Code, which Claude Desktop runs from `~/Library/Application Support/Claude/claude-code/`
  and which reads attached files itself in Code mode, and the commands it runs (`cat` included),
  and Claude Code started from a terminal (same signature). Exec is an AUTH event, answered from
  memory and never cached, so a child is protected before it opens anything (no measurable cost
  on 500 execs). Opens are answered with every flag allowed (`UInt32.max`): echoing the request's
  flags let only an app's first open of a file through. Documents with detections, and documents
  that cannot be read, are denied; the app shows a read error and Riot the "file blocked" card.
  Not covered: a forked child that opens a file before its fork notification is handled (no
  exec), and work handed to a system service (the file picker only displays the file).
- **Copy out of the AI app:** plain text, HTML and RTF get the real values back, each with its
  escaping (markdown-escaped tokens such as `\[IBAN\_1\]` included); other representations of
  the copy are dropped.
- **Paste detection limits:** promises carry the nspasteboard.org markers
  (`org.nspasteboard.TransientType`, `AutoGeneratedType`), so clipboard managers that honour
  them skip them unread (Maccy 2.8: 1 read in 3 s unmarked, 0 marked). One that ignores them
  and reads 150 ms or more after our write counts as a paste (HUD and report without one).
  After the first paste, a paste from the Edit or context menu (no ⌘) is redacted but shows no
  HUD. A second ⌘V within 0.5 s of the first gets the cached text without a HUD of its own.

## How a file open is decided

From a protected app's `open()` to the kernel's answer. The JS engine never sees the path, only
the file's name and bytes; every policy decision (target, bypass, cache, fail open or closed) is
taken in the daemon.

```
 AI app (e.g. ChatGPT)        kernel
        │ open("report.pdf")    │
        └──────────────────────►│ ES_EVENT_TYPE_AUTH_OPEN (with a deadline)
                                ▼
┌─ RiotES (root, Swift) ──────────────────────────────────────────────────────────┐
│ ESGuard.handleOpen                                                              │
│   protected app? candidate extension? ── no ──► allow (cached by the kernel)    │
│   budget = ES deadline − margin ;  es_retain_message                            │
│   queue.async ─► DaemonLink.scanFile(path, bundleId, timeout: budget)           │
│                    Task { client.call("scanFile") }  +  semaphore.wait(budget)  │
└────────────────────────────────┬────────────────────────────────────────────────┘
                                 │ {"id":42,"method":"scanFile",
                                 │  "params":{"path","bundleId","deadlineMs"}}\n
                                 ▼  Unix socket agent.sock (line-delimited JSON)
┌─ riot-daemon (Rust, tokio) ─────────────────────────────────────────────────────┐
│ server.rs   connection() ─► tokio::spawn(handle)   uid ≠ 0 ? ──► "forbidden"    │
│ agent.rs    scan_file()                                                         │
│               target? ─ bypass? ─ cache? ── hit ──► cached result               │
│               deadline = now + deadlineMs                                       │
│               spawn_blocking ─► engine.scan_path(path, options, deadline)       │
└────────────────────────────────┬────────────────────────────────────────────────┘
                                 │ Job over an mpsc channel, blocks on the reply
                                 ▼
┌─ riot-detect: the single "riot-detect-js" thread (QuickJS) ─────────────────────┐
│ scan_path: supportedFileFormat(name)? ─ size ≤ 25 MB? ─ std::fs::read           │
│ scan_bytes ─► call_json("scanFile", deadline,                                   │
│                         [name, mime "", Uint8Array, optionsJson])               │
│   with_deadline: AtomicU64 ◄── read by the interrupt handler (aborts the JS)    │
│   host_fn: globalThis.Sonar.host.scanFile(...)                                  │
│                │                                     ▲                          │
│                ▼                                     │ settle(): promise.finish │
│  ┌─ JS (js/dist/detection.js) ───────────────────┐   │                          │
│  │ host.ts scanFile                              │   │                          │
│  │   engine.scanFile(fileLike(name, mime, bytes))│───┘ JSON string              │
│  │   @tryriot/sonar-detection                    │                              │
│  │     pdf ─► __riot.pdfText ─► pdf.rs (native)  │                              │
│  └───────────────────────────────────────────────┘                              │
│ serde_json ─► FileScan { Scanned | Unsupported | Oversized | Error }            │
└────────────────────────────────┬────────────────────────────────────────────────┘
                                 ▼
┌─ riot-daemon: the decision ─────────────────────────────────────────────────────┐
│   Scanned with detections ─► deny "detections"  (+ report, + notification)      │
│   Scanned clean / Unsupported ─► allow                                          │
│   Oversized / Error ─► deny "error"             (fail closed)                   │
│   Timeout ─► allow "timeout"                    (fail open, not cached)         │
│   ─► cache ─► {"id":42,"ok":{"decision","reason","types","eventId"}}\n          │
└────────────────────────────────┬────────────────────────────────────────────────┘
                                 ▼
┌─ RiotES ────────────────────────────────────────────────────────────────────────┐
│ semaphore.signal ─► Verdict (.allow on timeout, error or no daemon)             │
│ es_respond_flags_result(deny ? 0 : UInt32.max, cache: false)                    │
│ es_release_message                                                              │
└─────────────────────────────────────────────────────────────────────────────────┘
```

One time budget runs through every layer:

```
ES deadline ─► budget (Swift: semaphore + call timeout)
            ─► deadlineMs (IPC)
            ─► Instant (daemon)
            ─► AtomicU64 read by QuickJS's interrupt handler
```

## Network interception

Redacting at the network level instead (text typed in the app included): the measurements on
Claude Code, Codex, Claude Desktop and ChatGPT, the plan, and the local gateway that already
redacts Claude Code's API requests (`ANTHROPIC_BASE_URL=http://127.0.0.1:7591/anthropic`):
[docs/network-interception.md](docs/network-interception.md).

## Not done / open

- **ES extension in production:** verified only as a root binary in a VM with SIP off
  ([docs/es-vm.md](docs/es-vm.md)). Shipping it needs Apple's
  `com.apple.developer.endpoint-security.client` entitlement (request it now; it takes weeks), then
  the system extension path (activation, MDM approval, Full Disk Access) to be run once. Still to
  check: the AUTH_OPEN deadline against large scans (3.3 s per MiB of text today), and ChatGPT.
- **Parrot endpoints:** specified in `docs/parrot-agent-api.md`, implemented only by the stub.
- **Production hardening:**
  - device token in the System keychain (now a 0600 file);
  - IPC peer code-signature check (now uid only, and `scanFile` is root-only);
  - Developer ID signing + notarization (`build-pkg.sh` takes the identities).
  - Building the pkg from a shell that marks its files leaves `._*` AppleDouble entries for
    `com.apple.provenance` (the installer folds them back into attributes); build on CI.
- **Pasteboard privacy:** no PPPC key is known to pre-approve "Paste from Other Apps". The popup
  shows the state (`NSPasteboard.accessBehavior`) and links to Settings.
- **Product:** authorized services (account detection has no desktop equivalent), and whether to
  guard browsers too (today: the extension does).
- **Windows** (phase 2): the daemon becomes a service on a named pipe; UI in WinUI 3 / WPF on the
  same protocol; minifilter for files.

## Deviations from the plan

- **UI ↔ daemon:** the apps speak the daemon's JSON protocol directly (Swift `DaemonClient`)
  instead of a UniFFI binding. The binding would only have wrapped this socket, all logic is in
  the daemon, and a C# client is as small.
- **pdf:** `pdf-extract` + `lopdf` (pure Rust, no 5 MB pdfium) passes the corpus; revisit if
  real-world pdfs disagree with pdf.js.
- **Report outbox:** one JSON file per report rather than SQLite.
