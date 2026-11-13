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
RiotES.systemextension        ── Endpoint Security AUTH_OPEN on the protected apps only
```

**Detection is the extension's own code.** `js/` bundles `@tryriot/sonar-detection` (and the
token memory of `@tryriot/sonar-guard-core`) from the shared-packages branch; `core/riot-detect`
runs it on an embedded QuickJS. What the browser provided natively is provided by Rust: UTF-8
decoding and pdf text extraction (`pdf-extract` + `lopdf`, standing in for pdf.js).

## Layout

| Path                                 | What                                                                                                                                    |
| ------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------- |
| `js/`                                | esbuild bundle of the extension's engine + QuickJS polyfills (`dist/detection.js`), and its conformance runner (`dist/conformance.js`)  |
| `core/riot-detect`                   | QuickJS host: `redact` (numbered tokens per app), `detokenize`, `detect`, `scan_bytes`/`scan_path`, deadlines via the interrupt handler |
| `core/riot-api`                      | parrot client (`docs/parrot-agent-api.md`)                                                                                              |
| `core/riot-ipc`                      | local protocol types + blocking client                                                                                                  |
| `core/riot-daemon`                   | the daemon (`riot-daemon`) and a CLI (`riotctl`)                                                                                        |
| `apple/RiotAgent`                    | menu bar app (SwiftPM): popup, clipboard guard, HUD, installer                                                                          |
| `apple/RiotES`                       | Endpoint Security system extension                                                                                                      |
| `apple/build-app.sh`, `build-pkg.sh` | `Riot.app` and the MDM `.pkg`                                                                                                           |
| `mdm/`                               | configuration profile template + renderer                                                                                               |
| `dev/`                               | stub parrot, dev settings, `run-dev.sh`                                                                                                 |

## Run it locally

Needs Rust, Node + pnpm, Xcode (for the SwiftUI macros), and a checkout of
`riot-browser-extension` with the shared packages (`SONAR_PACKAGES_DIR`, default
`~/dev/riot/riot-browser-extension-pkgs/packages`).

```sh
(cd js && pnpm install && node build.mjs)
dev/run-dev.sh                                   # stub parrot + daemon, unprivileged
apple/build-app.sh                               # → apple/build/Riot.app (ad-hoc signed)
RIOT_SOCKET=$TMPDIR/riot-dev.sock apple/build/Riot.app/Contents/MacOS/RiotAgent
```

Then copy text with an IBAN and switch to TextEdit (the stub's demo app): nothing shows yet.
Paste: you get `[IBAN_1]`, and the HUD shows and the report goes out then, once per paste. Switch
away: the original is back. Copy `[IBAN_1]` from TextEdit, paste elsewhere: the real value. `RIOT_SOCKET=$TMPDIR/riot-dev.sock core/target/release/riotctl status|popup|watch|…`
talks to the daemon directly; `scan` works unprivileged because `run-dev.sh` sets
`RIOT_DEV_ALLOW_SCAN=1`.

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
- **QuickJS patch:** one source patch is applied at bundle time (`js/build.mjs`, `PATCHES`): the phone
  detector sliced the whole remaining text per match. That is O(1) on V8 but a copy on QuickJS.
  It took a 1 MiB scan from 12.3 s to 3.3 s. It is behaviour-preserving and should be upstreamed.
- **Clipboard:** verified on macOS 27.2 against TextEdit: swap on activation, restore on leave,
  detokenize of copied answers, HUD. No pasteboard-privacy alert was raised on this Mac.
  Since then, the redacted text is a promised pasteboard item: the HUD and the report wait for
  the read that a paste does (⌘V, Edit menu, context menu). A read counts as a paste when a
  ⌘ shortcut or a click came after our write (`CGEventSource` counters, no permission).

## Not done / open

- **ES extension:** compiles and links, but is not run. It needs Apple's
  `com.apple.developer.endpoint-security.client` entitlement (request it now; it takes weeks).
  Until then, test in a VM with SIP off and `systemextensionsctl developer on`. Still to check:
  which ChatGPT/Claude processes open uploaded files (picker, drag, paste), and the AUTH_OPEN
  deadline against large scans.
- **Parrot endpoints:** specified in `docs/parrot-agent-api.md`, implemented only by the stub.
- **Production hardening:**
  - device token in the System keychain (now a 0600 file);
  - IPC peer code-signature check (now uid only, and `scanFile` is root-only);
  - Developer ID signing + notarization (`build-pkg.sh` takes the identities).
  - Building the pkg from this sandboxed shell leaves `._*` AppleDouble entries for
    `com.apple.provenance`; build on CI.
- **Paste detection limits:** a read with no fresh gesture (an Electron app reading on
  activation, a clipboard manager) gets the redacted text silently, and the promise is re-armed
  once. An app that reads on every clipboard change uses that up, and its real paste is then
  redacted but shows no HUD and sends no report. Still to verify on Claude Desktop; the fallback
  is a ⌘V event tap with Accessibility (PPPC). Dragging text into the app is not covered.
  "Paste the original" puts it on the clipboard: the user undoes and pastes again.
- **Copy out of the AI app:** only the plain text is detokenized; the rich formatting of the
  copied answer is dropped.
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
