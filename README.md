# Riot agent (POC, macOS)

The browser extension's sensitive-data protection, at the OS level, for AI desktop apps
(ChatGPT, Claude…): sensitive text copied into them is tokenized before it can be pasted, and
documents holding sensitive data are blocked from being opened by them. Installed and authorized
entirely by MDM; the daemon is the base of Riot's future MDM agent.

A second path is being validated to replace those OS hooks: the daemon's local proxy checks what
the AI apps send, on the network. It also sees what the hooks cannot (typed text, a file chosen
in the picker). See [Network interception](#network-interception-being-validated).

```
Riot.app (menu bar, SwiftUI)  ── clipboard guard + HUD + popup
      │  Unix socket, line-delimited JSON (core/riot-ipc)
riot-daemon (Rust, root)      ── detection engine, policy, parrot sync, report outbox,
      ▲                          local proxy (core/riot-proxy)
      │  same socket (scanFile with deadline, netConfig), and CONNECT to the proxy
RiotES.systemextension        ── Endpoint Security AUTH_OPEN on the protected apps' processes
RiotNet.systemextension       ── transparent proxy: relays the protected apps' HTTPS to the daemon
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
| `core/riot-proxy`                    | local TLS-intercepting proxy: device CA, SNI routing, request rules, JSON text redaction, upload gating, record mode                    |
| `core/riot-daemon`                   | the daemon (`riot-daemon`) and a CLI (`riotctl`)                                                                                        |
| `apple/RiotAgent`                    | menu bar app (SwiftPM): popup, clipboard guard, HUD, installer                                                                          |
| `apple/RiotES`                       | Endpoint Security system extension                                                                                                      |
| `apple/RiotNet`                      | network system extension (`NETransparentProxyProvider`)                                                                                 |
| `apple/build-app.sh`, `build-pkg.sh` | `Riot.app` and the MDM `.pkg`                                                                                                           |
| `mdm/`                               | configuration profile template + renderer                                                                                               |
| `dev/`                               | stub parrot, dev settings, `run-dev.sh`                                                                                                 |

## Run it locally

Needs Rust, Node + pnpm, Xcode (for the SwiftUI macros), and a checkout of
`tryriot/riot-browser-extension` on branch `feat/shared-sonar-packages` (`SONAR_PACKAGES_DIR`,
default `~/dev/riot/riot-browser-extension-pkgs/packages`):

```sh
git clone -b feat/shared-sonar-packages git@github.com:tryriot/riot-browser-extension.git \
  ~/dev/riot/riot-browser-extension-pkgs
(cd js && pnpm install && node build.mjs)
dev/run-dev.sh                                   # stub parrot + daemon, unprivileged
apple/build-app.sh                               # → apple/build/Riot.app (ad-hoc signed)
RIOT_SOCKET=$TMPDIR/riot-dev.sock apple/build/Riot.app/Contents/MacOS/RiotAgent
```

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

## Network interception (being validated)

Instead of guarding the clipboard, drags and file opens, check the requests themselves. The
daemon runs a proxy on loopback (`127.0.0.1:47610`); the network extension hands it the
protected apps' TCP 443 connections and refuses their QUIC, so they stay on HTTP/2.

- **What is decrypted.** The proxy reads the server name of each TLS ClientHello. A host of a
  protected service is intercepted, with a leaf certificate signed by the device's own CA
  (`<data dir>/ca/ca.pem`, key `0600`, created on first run). Any other connection is relayed
  byte for byte to the address it asked for, still encrypted.
- **What is changed.** Only requests a rule matches (`network_rules`, served with the policy:
  [docs/parrot-agent-api.md](docs/parrot-agent-api.md)). `json_text` redacts the selected
  strings of a JSON body, with the same token memory as the clipboard guard, so a copy out of
  the app still gets the values back. `multipart_file` and `raw_file` have the upload scanned,
  and answer `403` instead of forwarding a file with sensitive data; so does `json_text` for a
  file the body embeds in base64. Everything else, responses and WebSockets included, is
  forwarded as it came, streamed.
- **Protobuf.** The Claude app sends a chat message as a Connect call
  (`…ConversationService/PerformAction`, `application/proto`). `proto_text` redacts strings in
  such a body without its schema: a rule names them by field numbers (`2.3`), and the lengths
  around a changed string are recomputed.
- **Claude Code.** The Claude app's Code tab runs a separate binary that calls
  `api.anthropic.com/v1/messages` itself: the files its tools read travel there, a text file as
  the text of a tool result, a PDF as a base64 document. One rule covers both. Each request
  repeats the conversation, so the daemon remembers what it decided for each text (`history`):
  a text is scanned, shown and reported once, and redacted the same way in every later request.
- **What the user sees.** The message is already sent when the HUD shows what was redacted: the
  app displays the original, the service received the tokens, and the answer uses them. "Send
  without redaction" allows the next message with sensitive data from that app, within 60 s,
  and reports it as not redacted. A refused upload shows as the app's own upload error plus the
  file HUD; "send anyway" then allows the same content for 60 s.
- **When something fails.** No daemon or no proxy: the extension claims nothing and the apps
  connect directly. An engine failure leaves text as it is; a file that cannot be read (over
  32 MiB, compressed, broken envelope) is refused, as for the ES path.

Try it without the extension: the proxy accepts any HTTP `CONNECT`.

```sh
RIOT_PROXY_RECORD=1 dev/run-dev.sh          # record mode logs the shape of each request
riotctl status                              # proxy.addr, proxy.caCert, counters
ca=$(riotctl status | sed -n 's/.*"caCert": "\(.*\)",/\1/p')
curl -x http://127.0.0.1:47610 --cacert "$ca" https://claude.ai/api/bootstrap
```

`RIOT_PROXY_ADDR` moves the listener (`off` disables it). Record mode writes one
`riot_proxy::record` line per request to a protected host: method, path, content type, size and
the shape of a JSON or protobuf body (`{prompt:str(57),files:[0×]}`, `{1:str(36),2:{3:str(43)}}`),
never a value; and one line per host relayed without being decrypted. It is how the rules are
written. `dev/run-dev.sh` keeps the log in `$RIOT_DEV_DIR/daemon.log`.

Checked so far, with `curl` through the proxy against the real hosts: interception of
`claude.ai` and `chatgpt.com` over HTTP/2 with the device CA, refusal without it
(`handshakeFailures` counts it), `example.com` relayed with its own certificate, a message with
an IBAN redacted and reported, an upload with an IBAN refused then allowed after "send anyway".
A request on a warm connection took 60 ms end to end. The first request after one daemon start
took 9.8 s; it did not happen again on the next start, and the cause is not known.

Checked with Claude Code 2.1.325 (the binary the Claude app runs for its Code tab, started by
hand with `HTTPS_PROXY`): it trusts the device CA from the keychain; a text file with an IBAN
reaches the model as `[IBAN_1]`; a PDF with an IBAN is refused (Claude Code prints
`API Error: 403 Riot blocked this upload.`); a second turn of the same conversation reports
nothing new.

## Not done / open

- **Network interception:**
  - Claude (5.11492.5) has been run through the proxy with `--proxy-server`, the device CA
    trusted in the keychain: it accepts the CA, Cloudflare lets the proxy's TLS through, and a
    PDF with an IBAN attached in the chat is refused. A message with an IBAN is rewritten in
    its `PerformAction` call, accepted by the service (`200`), answered with the token, and
    reported. ChatGPT has not been run.
  - The `network_rules` in `dev/stub-parrot.mjs` for ChatGPT are candidates, not read from the
    app. Record mode is there to confirm or replace them. Claude's follow the app's private
    protobuf schema by field number: an update of the app can move them.
  - Claude Code works on what it is sent: a redacted file is tokens to the model, so an edit
    it writes back holds `[IBAN_1]`, not the value. Answers are not detokenized yet.
  - Claude Code puts the user's own e-mail and names in its context: every new conversation
    starts with a "message redacted" for them. Its system prompt (`/system`) is not looked at.
  - A PDF refused in a conversation stays in it: every later request is refused too, until
    "send anyway" or a new conversation. The `403` shows as "Failed to authenticate".
  - `RiotNet` claims connections by bundle id. Claude Code is signed `com.anthropic.claude-code`,
    not as a helper of the Claude app: it needs its own entry in `desktop_apps` to be routed.
    With `--proxy-server` the Claude app hands its proxy to the Code tab itself, which is how it
    was tested; the `claude` CLI run from a terminal does not go through it.
  - `RiotNet` type-checks against the SDK but is not built into the app or run: it needs a
    Developer ID identity and provisioning profiles with the Network Extensions capability
    (`WITH_NET=1`, see `apple/build-app.sh`). The MDM payload for it is written, not exercised.
    Whether a network system extension may run unsandboxed (it talks to the daemon's Unix
    socket) is to confirm at that point.
  - CA trust in production: a per-device CA cannot be trusted without a prompt. The intended
    shape is a per-workspace root in the MDM profile, constrained to the AI hosts, signing a
    per-device intermediate through parrot.
  - The loopback listener takes any local `CONNECT` and believes the `X-Riot-*` headers. A
    process that lies only gets its own traffic inspected, but the peer should be checked.
  - Out of scope for now: code in the apps that does not use the keychain's trust (the Codex
    CLI, Claude Code), redacting files instead of refusing them, and putting the values back
    in the answers.
  - Until both apps pass end to end, the clipboard guard, the drag guard and RiotES stay.
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
  - Building the pkg from this sandboxed shell leaves `._*` AppleDouble entries for
    `com.apple.provenance`; build on CI.
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
