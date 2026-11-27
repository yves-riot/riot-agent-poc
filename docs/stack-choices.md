# Stack choices

_Version française : [stack-choices.fr.md](stack-choices.fr.md)._

Why the agent is a Rust daemon, the extension's TypeScript engine on embedded QuickJS (until a
Rust engine replaces it), and native apps per OS (Swift on macOS, C# and WPF on Windows).

## Constraints

- **Same results as the browser extension.** A text redacted one way when pasted into Chrome and
  another way when pasted into ChatGPT Desktop is a product bug.
- **Light.** Always running on every managed Mac and PC: low RAM, no CPU at idle.
- **Installed and authorized entirely by MDM**, no user step.
- **macOS first, Windows next**, without rewriting the core.
- **The base of Riot's future MDM agent**: a privileged daemon that talks to the server.

## Shape

```
Riot.app (Swift: menu bar, HUD, clipboard and drag guards)     UI and OS hooks, per OS
      │  Unix socket, line-delimited JSON (core/riot-ipc)
riot-daemon (Rust, root)                                        shared by every OS
      ├─ riot-detect: QuickJS running @tryriot/sonar-detection
      ├─ native file text extraction (txt, csv, docx, xlsx, pdf)
      └─ policy, token memory, parrot sync, report outbox
      ▲  same socket (scanFile with a deadline)
RiotES.systemextension (Swift: Endpoint Security)               file blocking, per OS
```

All decisions and logic live in the daemon; the apps are thin clients that show what it says and
hook what only the OS can hook.

## Rust for the daemon

- **One daemon for both OSes**: a LaunchDaemon on macOS, a service on Windows, same code and
  protocol. Only the UI and the hooks are per OS.
- **It runs as root and parses untrusted files** (pdf, docx, xlsx). Memory safety matters there.
- **Small and idle**: 16 MB (`phys_footprint`), 0 % CPU at rest.
- **Good fit for the rest**: `rquickjs` to host the engine, `pdf-extract` + `lopdf` for pdf text
  (pure Rust, no 5 MB pdfium), `tokio` for the socket and the server sync.

### Why not Go, C++ or another language

What decides is the likely Rust engine (see below): one code base running natively in the daemon
and as WASM in the extension, and Rust's WASM output is small, with no runtime, built by the
standard toolchain.

- **Go** would have been a fair choice for the daemon alone: memory safe, simple, common for
  agents. Against it here: its WASM carries the Go runtime and garbage collector (several MB;
  TinyGo is smaller but supports only part of the language), embedding QuickJS goes through cgo
  (harder cross-compiling, a cost per call), and the garbage collector adds memory over today's
  16 MB.
- **C++**: no memory safety, in a root daemon that parses untrusted files, the classic source of
  exploitable bugs. Heavier tooling across macOS, Windows and WASM (dependencies, Emscripten). Its
  one strength, calling C APIs (QuickJS, Endpoint Security, Win32) directly, Rust has too.
- **Swift everywhere**: right on macOS, still immature on Windows; phase 2 would need another
  daemon.
- **C#/.NET everywhere**: a heavier runtime on macOS, and heavy WASM.
- **Zig**: too young an ecosystem for an agent deployed to whole fleets.

What Rust costs: a steeper learning curve, slower builds, fewer people who know it than Go. If
the engine were never to run as WASM, Go would be a serious contender for the daemon.

## Detection: the extension's engine on QuickJS today, Rust next

### Today: the TypeScript engine on QuickJS

- **Parity.** The daemon runs `@tryriot/sonar-detection` itself: same detectors,
  same tokens (`[EMAIL_1]`), same false-positive fixes. The extension's conformance corpus passes
  236/236 on QuickJS.
- **Nothing to port first**: `compromise` (person names) and `libphonenumber-js` run as they are.
- **One rule base, one team**: a detector change ships to the extension and the agent alike.
- **The risk was speed** (QuickJS has no JIT). Measured: paste 1 KB 20 ms, 64 KB 330 ms; a 1 MiB
  text file 3.3 s. Code that is cheap on V8 can be slow here: slicing a string copies it on
  QuickJS (the phone detector's tail slice took a 1 MiB scan to 12.3 s until fixed upstream).
- Not reused: pdf.js (workers, heavy, slow without a JIT; pdf text is extracted natively), and the
  extension's DOM interception and Vue UI.

### Next, likely: one Rust engine, WASM in the extension

The engine is likely to be ported to Rust, then imported by the extension as WASM. One
implementation everywhere: native in the daemon (no JS runtime, no V8/QuickJS performance gap,
one language fewer to debug), WASM in the browser.

- **The boundary is already there**: the daemon calls the engine through a Rust API
  (`riot_detect::Engine`: `redact`, `detokenize`, `detect`, `scan_path`); swapping QuickJS for
  Rust code changes nothing for the apps, the ES extension or the protocol.
- **The corpus is the gate**: the same conformance cases (236 today) must pass on the Rust engine,
  natively and in WASM, before it replaces the TypeScript one.
- **To solve in the port**: person names (`compromise` has no Rust equivalent: port its
  heuristics, or a small NER model at a RAM cost) and phones (the `phonenumber` crate does not
  match `libphonenumber-js` exactly; the corpus shows the gaps).
- **pdf text** is already Rust in the daemon; the extension keeps pdf.js or moves to the same
  extractor in WASM.

## Native apps per OS, whatever the UI grows into

The UI stays native even as it gets richer. The per-OS apps:

- **macOS: Swift** (SwiftUI and AppKit). The Endpoint Security extension has to be a system
  extension anyway. Measured: app 21 MB, `Riot.app` 9.8 MB.
- **Windows: C#** with WPF for the UI ([below](#windows-wpf)) and a minifilter for files, on the
  same daemon and protocol.

### Windows: WPF

Three native toolkits could carry the notification icon, the popup and the HUD:

|          | Deployed with                                                                        | Windows 11 look                                     | A HUD that never takes the focus     | Memory, idle                                         |
| -------- | ------------------------------------------------------------------------------------ | --------------------------------------------------- | ------------------------------------ | ---------------------------------------------------- |
| **WPF**  | the .NET Desktop Runtime only                                                        | Fluent theme built in since .NET 9, light and dark  | `WS_EX_NOACTIVATE` on its window     | measured: 93 MB working set, 44 MB private           |
| WinUI 3  | the .NET runtime and the Windows App SDK runtime, on every PC, kept in step with it  | native                                              | no direct support: Win32 interop     | not measured; the same .NET runtime plus WinUI       |
| WinForms | the .NET Desktop Runtime only                                                        | dated controls: the cards would be drawn by hand    | `WS_EX_NOACTIVATE`                   | not measured; expected lower than WPF                |

Why WPF:

- **One runtime to deploy.** The MDM installs the app and .NET (or the app bundles it). WinUI 3
  adds the Windows App SDK runtime, whose version has to match the app's on every PC of a fleet.
- **The guard's OS behaviour is plain Win32, and WPF gives direct access to it.** One hidden
  window (`HwndSource`) receives the clipboard notifications, the delayed-render requests, the
  raw keyboard events and the notification icon's clicks; the HUD is a window with
  `WS_EX_NOACTIVATE`, so the AI app keeps the focus and gets the Ctrl+Z/Ctrl+V.
- **It looks like Windows 11**, light or dark as Windows is set, with the Fluent theme, and it
  renders the cards with the extension's own strings.
- **Mature and stable**: maintained in .NET, known to most C# developers. The cards are XAML,
  as a WPF developer expects them, with the Visual Studio designer and Hot Reload; the C# only
  picks what a card shows.

What it costs:

- **Memory: 93 MB working set, 44 MB private, idle**, against 21 MB for the macOS app (Release
  build, measured on Windows 11). Most of it is the .NET runtime and WPF itself (DirectX
  rendering, the theme), shared with other .NET apps where there are; the agent's own state is
  small. Turning off the background GC saved 8 MB of private memory.
- **No trimming and no Native AOT** with WPF: the .NET runtime comes with the app.
- **The Fluent theme switch (`ThemeMode`) is still marked experimental** in .NET 10.

Revisit if memory becomes a blocker (WinForms, or a Win32 UI compiled with Native AOT: the
clipboard and Win32 code stays, the cards are redrawn), or if the app grows screens rich enough
to justify WinUI 3 and its runtime.

### Native over web

- **Memory and processes.** One process, 21 MB. A webview is a browser engine with its own
  processes: the app as first built on Tauri (Rust shell, system webview) passed 100 MB of RAM
  across 4 subprocesses; Electron ships a whole Chromium per app on top.
- **The guard is OS behaviour, not pages.** A HUD that never takes focus from the AI app
  (non-activating `NSPanel`), pasteboard promises, the drag pasteboard, the menu bar, keystrokes
  into the frontmost app. A web UI still needs native code for all of it, plus a bridge between
  the two: two stacks for one feature.
- **At once.** The HUD has to show the moment the user pastes; there is no webview to start or
  wake.
- **Looks and behaves like the OS** for free: system controls, dark mode, fonts, keyboard
  navigation, VoiceOver, right-to-left layouts, system menus.
- **Smaller attack surface** for an agent on every managed machine: no engine running HTML and JS
  next to a root daemon, no web runtime to keep patched (WebView2 updates on its own schedule on
  Windows).
- **One signed binary** to notarize and deploy by MDM, no embedded runtime.
- **Web stays possible where needed**: a native window can host a webview (`WKWebView`, WebView2
  on Windows) for one screen, created when it opens and talking to the daemon through the native
  app. Switching a screen to web later does not change the rest of the app.

What it costs: the UI is written per OS (Swift, then C#), and the extension's Vue components
(`sonar-ui`) are not reused. Its strings are: the app loads the extension's locale files, so both
products say the same thing.

## Apps ↔ daemon: JSON over a socket, not generated bindings

The plan was a UniFFI binding from Rust to Swift. The apps speak the daemon's JSON protocol
directly instead (`DaemonClient.swift`): the binding would only have wrapped this socket, all
logic is in the daemon, and a C# client is as small. `riotctl` is one more client of the same
socket ([riotctl.md](riotctl.md)).

## The cost

- **Three languages** (Rust, Swift, then C#) instead of one; until the Rust engine, debugging also
  crosses into JS.
- **Engine performance needs watching** while it runs on QuickJS: a pattern that is free on V8 can
  be quadratic there. The bench (`cargo run -p riot-detect --release --example bench`) is the
  check.

## Revisit if

- QuickJS gets too slow for the Endpoint Security deadline on large files before the Rust engine
  lands: port the hot detectors first, or JavaScriptCore (system provided, with a JIT) on macOS.
