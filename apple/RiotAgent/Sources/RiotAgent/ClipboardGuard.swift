import AppKit
import os

/// Events and timings only, never clipboard content:
/// `log stream --level debug --predicate 'subsystem == "com.tryriot.agent"'`.
private let log = Logger(subsystem: "com.tryriot.agent", category: "clipboard")

/// What the guard needs from the system pasteboard (a protocol so tests can drive it).
protocol PasteboardAccess: AnyObject {
    var changeCount: Int { get }
    /// The first item's types (reading them triggers no privacy alert).
    var types: [String] { get }
    func plainText() -> String?
    func hasType(_ type: String) -> Bool
    /// Every item with every representation, to put back exactly what the user copied.
    func snapshot() -> [[String: Data]]
    func restore(_ snapshot: [[String: Data]], marker: String)
    /// The first item's representations among `types`, as text.
    func texts(_ types: [String]) -> [String: String]
    /// One item with these representations (type → text).
    func writeTexts(_ texts: [String: String])
    /// Writes `markers` as real (empty) data and the plain text as a promise: `provide` runs on
    /// the main thread when an app actually reads the text, i.e. when it pastes.
    func writePromisedText(markers: [String], provide: @escaping () -> String)
}

/// Whether ⌘ is down right now (the window server's state: no permission involved).
protocol KeyboardState: AnyObject {
    var commandHeld: Bool { get }
    /// Time since the last key press, anywhere. Coarse without Input Monitoring (0.5 s steps),
    /// enough to tell whether the user typed in the seconds after a paste.
    var secondsSinceKeyDown: TimeInterval { get }
}

/// Keystrokes into the frontmost app (needs the Accessibility permission).
protocol KeystrokeSender: AnyObject {
    /// Sends ⌘Z then ⌘V. False, with nothing sent, without the permission.
    func undoThenPaste() -> Bool
}

/// What the guard asks the daemon.
protocol GuardBackend: AnyObject {
    func redactText(_ text: String, bundleId: String) async throws -> RedactTextResult
    func reportPaste(eventId: String) async throws -> String
    func detokenize(_ text: String, bundleId: String) async throws -> DetokenizeResult
    func reportOverride(pasteId: String) async throws
}

/// The clipboard side of the agent, polling like a clipboard manager (Maccy, Paste):
///
/// * `changeCount` is polled every 0.5 s. Reading it triggers no privacy alert.
/// * Content is read only when a protected AI app is frontmost: when it is activated, or when
///   the clipboard changes while it is. Elsewhere the guard never looks.
/// * Sensitive text is redacted ahead of time, then put back on the clipboard as a *promise*:
///   macOS asks us for the text only when an app reads it, whatever the paste gesture (⌘V,
///   Edit menu, context menu). That read is the paste: the HUD shows and the daemon reports
///   then, not when the app is merely activated. The original is kept in memory only.
/// * Which reads are pastes: a read 150 ms or more after the promise was written. Earlier,
///   it is a clipboard manager or a sync reacting to our write. ChatGPT and Claude read only
///   to paste, never on activation.
/// * The promise is re-armed after each read, so every paste is seen. A re-armed promise
///   counts a read as a paste only while ⌘ is held (⌘V): a clipboard manager reading each
///   new promise must not loop the HUD.
/// * Leaving the app puts the original back; text copied *out of* the app gets its tokens
///   swapped back to the real values, in plain text, HTML and RTF (the native counterpart of
///   the extension's restore-dom).
@MainActor
final class ClipboardGuard {
    struct Swap {
        let bundleId: String
        let original: [[String: Data]]
        let result: RedactTextResult
        let redacted: String
        /// The change count of our promise on the clipboard.
        var changeCount: Int
        /// When the promise was written: an earlier read than 150 ms after is not a paste.
        var armedAt: Date
        /// The redacted text has been pasted at least once; later promises are re-arms.
        var pasted = false
        /// Silent re-arms left after reads that were not pastes (bounds a loop with an app
        /// that reads on every clipboard change).
        var silentRearms = 1
        /// The report of the last paste, for "paste the original".
        var lastPaste: Task<String?, Never>?
        var lastPasteAt: Date?
    }

    /// What "paste the original" could do.
    enum OriginalOutcome {
        /// Nothing to put back (the clipboard changed, or bypass is not allowed).
        case unavailable
        /// The original is on the clipboard: the user undoes and pastes again.
        case onClipboard
        /// The redacted paste was undone and the original pasted in its place.
        case pasted
    }

    /// Our own writes carry this type, so the next tick recognises them (Maccy's `.fromMaccy`).
    static let marker = "com.tryriot.agent.redacted"
    /// Our promises also carry the nspasteboard.org markers: clipboard managers (Maccy, Paste,
    /// Raycast…) then skip them from the types alone, without reading the text. Unmarked, Maccy
    /// read each promise 0 to 0.5 s after it was written, which looked like a paste.
    static let promiseMarkers = [marker, "org.nspasteboard.TransientType", "org.nspasteboard.AutoGeneratedType"]
    /// The engine's tokens (`[IBAN_1]`, `[API_KEY_2]`), also as a markdown copy escapes them
    /// (`\[IBAN\_1\]`).
    static let tokenPattern = try! NSRegularExpression(
        pattern: #"\\?\[([A-Z][A-Z0-9]*(?:\\?_[A-Z][A-Z0-9]*)*\\?_\d+)\\?\]"#)
    /// Readers this soon after our write are reacting to the write, not pasting.
    static let earlyRead: TimeInterval = 0.15
    /// A key press later than this after the paste means the user typed: ⌘Z would undo their
    /// typing, not the paste. (Covers the ⌘V itself, seen late by the coarse counter.)
    static let typedAfterPaste: TimeInterval = 1
    /// The text representations restored on a copy out of the app; others are dropped, they
    /// could still hold the tokens.
    static let textTypes = [NSPasteboard.PasteboardType.string.rawValue, "public.html", "public.rtf"]

    private let pasteboard: PasteboardAccess
    private let backend: GuardBackend
    private let keyboard: KeyboardState
    private let keys: KeystrokeSender
    private let now: () -> Date
    var targets: Set<String> = []
    /// A paste of redacted text into a protected app: show the HUD.
    var onPasted: ((RedactTextResult, String) -> Void)?

    private(set) var frontmost: String?
    private(set) var swap: Swap?
    private var lastSeen: Int
    /// The clipboard changed while a protected app was frontmost (an answer was copied).
    private var copiedInside = false
    private var timer: Timer?
    private var inFlight: Task<Void, Never>?
    /// Re-arming clears the clipboard. Done at once, it can land while the reading app is still
    /// receiving the data, and that paste then gets nothing (6 reads in 20 in a test; none
    /// with a 0.5 s delay).
    private let rearmDelay: TimeInterval
    private var pendingRearm: Task<Void, Never>?

    init(pasteboard: PasteboardAccess, backend: GuardBackend,
         keyboard: KeyboardState = SystemKeyboardState(), keys: KeystrokeSender = SystemKeystrokes(),
         now: @escaping () -> Date = Date.init, rearmDelay: TimeInterval = 0.5) {
        self.pasteboard = pasteboard
        self.backend = backend
        self.keyboard = keyboard
        self.keys = keys
        self.now = now
        self.rearmDelay = rearmDelay
        self.lastSeen = pasteboard.changeCount
    }

    func start() {
        let timer = Timer(timeInterval: 0.5, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.tick() }
        }
        timer.tolerance = 0.2 // let the system coalesce wake-ups
        RunLoop.main.add(timer, forMode: .common)
        self.timer = timer
        NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didActivateApplicationNotification, object: nil, queue: .main
        ) { [weak self] note in
            let app = note.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication
            MainActor.assumeIsolated { self?.activated(bundleId: app?.bundleIdentifier) }
        }
        activated(bundleId: NSWorkspace.shared.frontmostApplication?.bundleIdentifier)
    }

    private var isTargetFrontmost: Bool { frontmost.map(targets.contains) ?? false }

    // MARK: events

    func activated(bundleId: String?) {
        // Our own popup or HUD taking focus is not "leaving the AI app".
        if bundleId == Bundle.main.bundleIdentifier { return }
        let previous = frontmost
        guard bundleId != previous else { return }
        log.debug("activate \(bundleId ?? "-", privacy: .public)")
        // A copy made just before switching, that the timer has not seen yet, belongs to the
        // app being left: without this, ⌘C then ⌘Tab would skip its detokenization.
        _ = noteClipboardChange()
        frontmost = bundleId
        enqueue { [weak self] in
            guard let self else { return }
            if let previous, self.targets.contains(previous) { await self.leave(previous) }
            if let bundleId, self.targets.contains(bundleId) { await self.inspect(for: bundleId) }
        }
    }

    func tick() {
        guard noteClipboardChange(), let bundleId = frontmost else { return }
        // New content while the AI app is frontmost: an answer copied out, or a background copy.
        enqueue { [weak self] in await self?.inspect(for: bundleId) }
    }

    /// Records a clipboard change. True when it is new content (not ours) while a protected
    /// app is frontmost.
    private func noteClipboardChange() -> Bool {
        let count = pasteboard.changeCount
        guard count != lastSeen else { return false }
        lastSeen = count
        guard isTargetFrontmost else { return false }
        if swap?.changeCount == count || pasteboard.hasType(Self.marker) { return false }
        copiedInside = true
        swap = nil
        return true
    }

    /// Serialise the async steps: a leave must finish before the next app's inspection.
    private func enqueue(_ step: @escaping @MainActor () async -> Void) {
        let previous = inFlight
        inFlight = Task { @MainActor in
            await previous?.value
            await step()
        }
    }

    func waitIdle() async {
        // A step may enqueue another one (a read classified after a paste), or schedule a re-arm.
        while true {
            let (step, rearm) = (inFlight, pendingRearm)
            await step?.value
            await rearm?.value
            if inFlight == step && pendingRearm == rearm { return }
        }
    }

    // MARK: steps

    private func inspect(for bundleId: String) async {
        guard !pasteboard.hasType(Self.marker), let text = pasteboard.plainText(), !text.isEmpty else { return }
        let countAtRead = pasteboard.changeCount
        let original = pasteboard.snapshot()
        guard let result = try? await backend.redactText(text, bundleId: bundleId) else { return }
        log.debug("inspect \(result.action, privacy: .public)")
        // The user copied something else meanwhile, or left the app: that newer state wins.
        guard result.action == "redacted", let redacted = result.text,
              pasteboard.changeCount == countAtRead, frontmost == bundleId else { return }
        swap = Swap(bundleId: bundleId, original: original, result: result, redacted: redacted,
                    changeCount: 0, armedAt: now())
        arm()
    }

    /// Puts (back) the promise of the redacted text on the clipboard.
    private func arm() {
        guard var swap else { return }
        let plainOriginal = swap.original.first?[NSPasteboard.PasteboardType.string.rawValue]
            .map { String(decoding: $0, as: UTF8.self) }
        let redacted = swap.redacted
        pasteboard.writePromisedText(markers: Self.promiseMarkers) { [weak self] in
            MainActor.assumeIsolated { self?.provide(redacted: redacted, original: plainOriginal) ?? redacted }
        }
        swap.changeCount = pasteboard.changeCount
        swap.armedAt = now()
        lastSeen = swap.changeCount
        self.swap = swap
    }

    /// An app reads our promise. Answer at once (it is waiting), decide what the read was after.
    private func provide(redacted: String, original: String?) -> String {
        // Safety net, should the read beat `leave`: a non-protected app gets the original.
        if let reader = frontmost, !targets.contains(reader), let original { return original }
        let count = pasteboard.changeCount
        let readAt = now()
        let commandHeld = keyboard.commandHeld
        enqueue { [weak self] in self?.classifyRead(changeCount: count, at: readAt, commandHeld: commandHeld) }
        return redacted
    }

    private func classifyRead(changeCount: Int, at readAt: Date, commandHeld: Bool) {
        guard var swap, swap.changeCount == changeCount, frontmost == swap.bundleId,
              pasteboard.changeCount == changeCount else { return }
        let early = readAt.timeIntervalSince(swap.armedAt) < Self.earlyRead
        let pasted = !early && (!swap.pasted || commandHeld)
        log.debug("read \(Int(readAt.timeIntervalSince(swap.armedAt) * 1000))ms after arm, cmd=\(commandHeld), rearm=\(swap.pasted): \(pasted ? "paste" : "not a paste", privacy: .public)")
        if pasted {
            if let eventId = swap.result.eventId {
                let backend = self.backend
                swap.lastPaste = Task { try? await backend.reportPaste(eventId: eventId) }
            }
            swap.pasted = true
            swap.lastPasteAt = readAt
            swap.silentRearms = 1
            self.swap = swap
            onPasted?(swap.result, swap.bundleId)
            scheduleRearm(of: changeCount) // the server caches what we gave: re-arm to see the next paste
        } else if swap.silentRearms > 0 {
            swap.silentRearms -= 1
            self.swap = swap
            scheduleRearm(of: changeCount)
        }
    }

    /// Re-arms once the reading app has its data, if our promise is still the clipboard.
    /// A paste within the delay gets the cached redacted text, without a HUD of its own.
    private func scheduleRearm(of changeCount: Int) {
        pendingRearm?.cancel()
        let delay = rearmDelay
        pendingRearm = Task { @MainActor [weak self] in
            if delay > 0 { try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000)) }
            guard !Task.isCancelled, let self, let swap = self.swap, swap.changeCount == changeCount,
                  self.pasteboard.changeCount == changeCount, self.frontmost == swap.bundleId else { return }
            self.arm()
        }
    }

    private func leave(_ bundleId: String) async {
        defer { copiedInside = false }
        if let swap, swap.bundleId == bundleId {
            self.swap = nil
            if pasteboard.changeCount == swap.changeCount {
                // Still our tokenized text: give the user their original back.
                pasteboard.restore(swap.original, marker: "")
                lastSeen = pasteboard.changeCount
            }
        }
        if copiedInside { await restoreValues(copiedFrom: bundleId) }
    }

    /// An answer copied inside the app may carry tokens: hand out the real values, in each
    /// text representation with its own escaping, so a paste into Mail or Notes keeps the
    /// formatting.
    private func restoreValues(copiedFrom bundleId: String) async {
        let texts = pasteboard.texts(Self.textTypes)
        let tokens = Set(texts.values.flatMap(Self.tokens(in:)))
        guard !tokens.isEmpty else { return }
        let countAtRead = pasteboard.changeCount
        var values: [String: String] = [:]
        for token in tokens {
            if let result = try? await backend.detokenize(token, bundleId: bundleId), result.replaced > 0 {
                values[token] = result.text
            }
        }
        guard !values.isEmpty, pasteboard.changeCount == countAtRead else { return }
        var restored: [String: String] = [:]
        for (type, text) in texts {
            restored[type] = Self.replacingTokens(in: text, with: values, escape: Self.escape(for: type))
        }
        pasteboard.writeTexts(restored)
        lastSeen = pasteboard.changeCount
        log.debug("copy out: \(values.count) token(s) restored in \(restored.count) representation(s)")
    }

    /// "Paste without redaction", after the user confirmed: the original goes back on the
    /// clipboard for this app, and the last paste is re-reported as not redacted. Then, if the
    /// app is still frontmost (the HUD does not take focus) and the user has not typed since
    /// the paste, ⌘Z undoes the redacted paste and ⌘V pastes the original.
    @discardableResult
    func pasteOriginal() -> OriginalOutcome {
        guard let swap, swap.result.allowBypass, pasteboard.changeCount == swap.changeCount else { return .unavailable }
        self.swap = nil
        pendingRearm?.cancel()
        pasteboard.restore(swap.original, marker: Self.marker) // marked: not re-inspected
        lastSeen = pasteboard.changeCount
        if let lastPaste = swap.lastPaste {
            let backend = self.backend
            Task {
                guard let pasteId = await lastPaste.value else { return }
                try? await backend.reportOverride(pasteId: pasteId)
            }
        }
        guard frontmost == swap.bundleId, let pastedAt = swap.lastPasteAt else { return .onClipboard }
        let sincePaste = now().timeIntervalSince(pastedAt)
        let sinceKey = keyboard.secondsSinceKeyDown
        guard sincePaste - sinceKey < Self.typedAfterPaste else {
            log.debug("original on the clipboard: typed \(Int(sincePaste - sinceKey))s after the paste")
            return .onClipboard
        }
        guard keys.undoThenPaste() else {
            log.debug("original on the clipboard: no Accessibility permission")
            return .onClipboard
        }
        log.debug("original pasted over the redacted paste")
        return .pasted
    }

    // MARK: tokens

    /// The canonical tokens in `text` (markdown escapes removed).
    static func tokens(in text: String) -> [String] {
        tokenPattern.matches(in: text, range: NSRange(text.startIndex..., in: text)).compactMap { match in
            Range(match.range(at: 1), in: text).map { "[" + text[$0].replacingOccurrences(of: "\\", with: "") + "]" }
        }
    }

    static func replacingTokens(in text: String, with values: [String: String], escape: (String) -> String) -> String {
        var out = ""
        var last = text.startIndex
        for match in tokenPattern.matches(in: text, range: NSRange(text.startIndex..., in: text)) {
            guard let whole = Range(match.range, in: text), let name = Range(match.range(at: 1), in: text),
                  let value = values["[" + text[name].replacingOccurrences(of: "\\", with: "") + "]"] else { continue }
            out += text[last..<whole.lowerBound]
            out += escape(value)
            last = whole.upperBound
        }
        return out + text[last...]
    }

    static func escape(for type: String) -> (String) -> String {
        switch type {
        case "public.html": return escapeHTML
        case "public.rtf": return escapeRTF
        default: return { $0 }
        }
    }

    static func escapeHTML(_ s: String) -> String {
        s.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;").replacingOccurrences(of: "\"", with: "&quot;")
    }

    /// RTF is 7-bit: escape its control characters, write non-ASCII as `\uN?` (UTF-16, signed).
    static func escapeRTF(_ s: String) -> String {
        var out = ""
        for scalar in s.unicodeScalars {
            switch scalar {
            case "\\", "{", "}": out += "\\" + String(scalar)
            case _ where scalar.isASCII: out.unicodeScalars.append(scalar)
            default:
                for unit in String(scalar).utf16 { out += "\\u\(Int16(bitPattern: unit))?" }
            }
        }
        return out
    }
}

/// The real pasteboard: the general one, or the drag one (`NSPasteboard(name: .drag)`).
final class SystemPasteboard: PasteboardAccess {
    private let pb: NSPasteboard
    /// Promises still on the clipboard (`NSPasteboardItem` does not retain its provider).
    private var providers: [ObjectIdentifier: PromiseProvider] = [:]

    init(_ pb: NSPasteboard = .general) { self.pb = pb }

    var changeCount: Int { pb.changeCount }

    var types: [String] { pb.pasteboardItems?.first?.types.map(\.rawValue) ?? [] }

    func plainText() -> String? { pb.string(forType: .string) }

    func hasType(_ type: String) -> Bool {
        pb.types?.contains(NSPasteboard.PasteboardType(type)) ?? false
    }

    func snapshot() -> [[String: Data]] {
        (pb.pasteboardItems ?? []).map { item in
            var reps: [String: Data] = [:]
            for type in item.types { reps[type.rawValue] = item.data(forType: type) }
            return reps
        }
    }

    func restore(_ snapshot: [[String: Data]], marker: String) {
        pb.clearContents()
        let items = snapshot.map { reps -> NSPasteboardItem in
            let item = NSPasteboardItem()
            for (type, data) in reps { item.setData(data, forType: NSPasteboard.PasteboardType(type)) }
            return item
        }
        if !marker.isEmpty, let first = items.first {
            first.setData(Data(), forType: NSPasteboard.PasteboardType(marker))
        }
        pb.writeObjects(items)
    }

    func texts(_ types: [String]) -> [String: String] {
        guard let item = pb.pasteboardItems?.first else { return [:] }
        var out: [String: String] = [:]
        for type in types {
            if let text = item.string(forType: NSPasteboard.PasteboardType(type)) { out[type] = text }
        }
        return out
    }

    func writeTexts(_ texts: [String: String]) {
        pb.clearContents()
        let item = NSPasteboardItem()
        for (type, text) in texts { item.setString(text, forType: NSPasteboard.PasteboardType(type)) }
        pb.writeObjects([item])
    }

    func writePromisedText(markers: [String], provide: @escaping () -> String) {
        pb.clearContents()
        let item = NSPasteboardItem()
        for marker in markers { item.setData(Data(), forType: NSPasteboard.PasteboardType(marker)) }
        let provider = PromiseProvider(provide: provide) { [weak self] finished in
            self?.providers[ObjectIdentifier(finished)] = nil
        }
        providers[ObjectIdentifier(provider)] = provider
        item.setDataProvider(provider, forTypes: [.string])
        pb.writeObjects([item])
    }

    /// macOS 15.4+: whether reading triggers the "Paste from Other Apps" alert.
    static var accessState: String {
        if #available(macOS 15.4, *) {
            switch NSPasteboard.general.accessBehavior {
            case .alwaysAllow: return "allow"
            case .alwaysDeny: return "deny"
            case .ask: return "ask"
            default: return "default"
            }
        }
        return "allow"
    }
}

/// Answers a read of promised text. AppKit calls it on the main thread.
private final class PromiseProvider: NSObject, NSPasteboardItemDataProvider {
    private let provide: () -> String
    private let finished: (PromiseProvider) -> Void

    init(provide: @escaping () -> String, finished: @escaping (PromiseProvider) -> Void) {
        self.provide = provide
        self.finished = finished
    }

    func pasteboard(_ pasteboard: NSPasteboard?, item: NSPasteboardItem, provideDataForType type: NSPasteboard.PasteboardType) {
        let text = Thread.isMainThread ? provide() : DispatchQueue.main.sync { provide() }
        item.setString(text, forType: type)
    }

    func pasteboardFinishedWithDataProvider(_ pasteboard: NSPasteboard) {
        finished(self)
    }
}

/// The system-wide modifier state. (The event *counters*, `secondsSinceLastEventType`, are no
/// use here: without Input Monitoring they move in 0.5 s steps and late.)
final class SystemKeyboardState: KeyboardState {
    var commandHeld: Bool { CGEventSource.flagsState(.combinedSessionState).contains(.maskCommand) }
    var secondsSinceKeyDown: TimeInterval {
        CGEventSource.secondsSinceLastEventType(.combinedSessionState, eventType: .keyDown)
    }
}
