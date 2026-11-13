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
token memory of `@tryriot/sonar-guard-core`) from the extension's `feat/shared-sonar-packages`
branch; `core/riot-detect` runs it on an embedded QuickJS. What the browser provided natively
is provided by Rust: UTF-8 decoding and pdf text extraction (`pdf-extract` + `lopdf`, standing
in for pdf.js).

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
- **Copy out of the AI app:** plain text, HTML and RTF get the real values back, each with its
  escaping (markdown-escaped tokens such as `\[IBAN\_1\]` included); other representations of
  the copy are dropped.
- **Paste detection limits:** promises carry the nspasteboard.org markers
  (`org.nspasteboard.TransientType`, `AutoGeneratedType`), so clipboard managers that honour
  them skip them unread (Maccy 2.8: 1 read in 3 s unmarked, 0 marked). One that ignores them
  and reads 150 ms or more after our write counts as a paste (HUD and report without one).
  After the first paste, a paste from the Edit or context menu (no ⌘) is redacted but shows no
  HUD. A second ⌘V within 0.5 s of the first gets the cached text without a HUD of its own.

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
