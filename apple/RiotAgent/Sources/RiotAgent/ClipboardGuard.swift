import AppKit

/// What the guard needs from the system pasteboard (a protocol so tests can drive it).
protocol PasteboardAccess: AnyObject {
    var changeCount: Int { get }
    func plainText() -> String?
    func hasType(_ type: String) -> Bool
    /// Every item with every representation, to put back exactly what the user copied.
    func snapshot() -> [[String: Data]]
    func restore(_ snapshot: [[String: Data]], marker: String)
    func writePlainText(_ text: String, marker: String)
    /// Writes `marker` as real data and the plain text as a promise: `provide` runs on the main
    /// thread when an app actually reads the text, i.e. when it pastes.
    func writePromisedText(marker: String, provide: @escaping () -> String)
}

/// Whether the user just did something that pastes: a ⌘ shortcut or a click (Edit menu,
/// context menu). Readable without any permission.
protocol GestureProbe: AnyObject {
    /// Seconds since that gesture, or nil if there was none in the last second.
    func secondsSincePasteGesture() -> TimeInterval?
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
///   then, not when the app is merely activated. The promise is re-armed after each paste, so
///   every paste is seen. The original is kept in memory only.
/// * A read with no fresh user gesture (an Electron app reading on activation, a clipboard
///   manager) still gets the redacted text, silently.
/// * Leaving the app puts the original back; text copied *out of* the app gets its tokens
///   swapped back to the real values (the native counterpart of the extension's restore-dom).
@MainActor
final class ClipboardGuard {
    struct Swap {
        let bundleId: String
        let original: [[String: Data]]
        let result: RedactTextResult
        let redacted: String
        /// The change count of our promise on the clipboard.
        var changeCount: Int
        /// When we last wrote it: a paste gesture must come after.
        var writtenAt: Date
        /// Silent re-arms left after reads that were not pastes (bounds a loop with an app
        /// that reads on every clipboard change).
        var silentRearms = 1
        /// The report of the last paste, for "paste the original".
        var lastPaste: Task<String?, Never>?
    }

    /// Our own writes carry this type, so the next tick recognises them (Maccy's `.fromMaccy`).
    static let marker = "com.tryriot.agent.redacted"
    static let tokenPattern = try! NSRegularExpression(pattern: #"\[[A-Z][A-Z0-9]*(?:_[A-Z][A-Z0-9]*)*_\d+\]"#)

    private let pasteboard: PasteboardAccess
    private let backend: GuardBackend
    private let gestures: GestureProbe
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
         gestures: GestureProbe = SystemGestureProbe(), now: @escaping () -> Date = Date.init,
         rearmDelay: TimeInterval = 0.5) {
        self.pasteboard = pasteboard
        self.backend = backend
        self.gestures = gestures
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
        // The user copied something else meanwhile, or left the app: that newer state wins.
        guard result.action == "redacted", let redacted = result.text,
              pasteboard.changeCount == countAtRead, frontmost == bundleId else { return }
        swap = Swap(bundleId: bundleId, original: original, result: result, redacted: redacted,
                    changeCount: 0, writtenAt: now())
        arm()
    }

    /// Puts (back) the promise of the redacted text on the clipboard.
    private func arm() {
        guard var swap else { return }
        let plainOriginal = swap.original.first?[NSPasteboard.PasteboardType.string.rawValue]
            .map { String(decoding: $0, as: UTF8.self) }
        let redacted = swap.redacted
        pasteboard.writePromisedText(marker: Self.marker) { [weak self] in
            MainActor.assumeIsolated { self?.provide(redacted: redacted, original: plainOriginal) ?? redacted }
        }
        swap.changeCount = pasteboard.changeCount
        swap.writtenAt = now()
        lastSeen = swap.changeCount
        self.swap = swap
    }

    /// An app reads our promise. Answer at once (it is waiting), decide what the read was after.
    private func provide(redacted: String, original: String?) -> String {
        let reader = frontmost
        // Safety net, should the read beat `leave`: a non-protected app gets the original.
        if let reader, !targets.contains(reader), let original { return original }
        let count = pasteboard.changeCount
        let gestureAge = gestures.secondsSincePasteGesture()
        let readAt = now()
        enqueue { [weak self] in self?.classifyRead(changeCount: count, gestureAge: gestureAge, at: readAt) }
        return redacted
    }

    private func classifyRead(changeCount: Int, gestureAge: TimeInterval?, at readAt: Date) {
        guard var swap, swap.changeCount == changeCount, frontmost == swap.bundleId,
              pasteboard.changeCount == changeCount else { return }
        // A paste gesture made after our write. Activating the app (⌘Tab, click) comes before
        // it; so do the paste that led to a read on change by the app.
        let pasted = gestureAge.map { readAt.addingTimeInterval(-$0) > swap.writtenAt } ?? false
        if pasted {
            if let eventId = swap.result.eventId {
                let backend = self.backend
                swap.lastPaste = Task { try? await backend.reportPaste(eventId: eventId) }
            }
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
        // An answer copied inside the app may carry tokens: hand out the real values. (Plain
        // text only: the rich representations of that copy still hold the tokens.)
        guard copiedInside, let text = pasteboard.plainText(),
              Self.tokenPattern.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) != nil
        else { return }
        let countAtRead = pasteboard.changeCount
        guard let result = try? await backend.detokenize(text, bundleId: bundleId), result.replaced > 0,
              pasteboard.changeCount == countAtRead else { return }
        pasteboard.writePlainText(result.text, marker: "")
        lastSeen = pasteboard.changeCount
    }

    /// "Paste without redaction", after the user confirmed: the original goes back on the
    /// clipboard for this app, and the last paste is re-reported as not redacted.
    func pasteOriginal() {
        guard let swap, swap.result.allowBypass, pasteboard.changeCount == swap.changeCount else { return }
        self.swap = nil
        pasteboard.restore(swap.original, marker: Self.marker) // marked: not re-inspected
        lastSeen = pasteboard.changeCount
        if let lastPaste = swap.lastPaste {
            let backend = self.backend
            Task {
                guard let pasteId = await lastPaste.value else { return }
                try? await backend.reportOverride(pasteId: pasteId)
            }
        }
    }
}

/// The real pasteboard.
final class SystemPasteboard: PasteboardAccess {
    private let pb = NSPasteboard.general
    /// Promises still on the clipboard (`NSPasteboardItem` does not retain its provider).
    private var providers: [ObjectIdentifier: PromiseProvider] = [:]

    var changeCount: Int { pb.changeCount }

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

    func writePlainText(_ text: String, marker: String) {
        pb.clearContents()
        let item = NSPasteboardItem()
        item.setString(text, forType: .string)
        if !marker.isEmpty { item.setData(Data(), forType: NSPasteboard.PasteboardType(marker)) }
        pb.writeObjects([item])
    }

    func writePromisedText(marker: String, provide: @escaping () -> String) {
        pb.clearContents()
        let item = NSPasteboardItem()
        item.setData(Data(), forType: NSPasteboard.PasteboardType(marker))
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

/// Last ⌘-key press (⌘ still held, as during ⌘V) or click release, from the window server's
/// event counters: no Accessibility or Input Monitoring permission involved.
final class SystemGestureProbe: GestureProbe {
    static let window: TimeInterval = 1

    func secondsSincePasteGesture() -> TimeInterval? {
        let since = { CGEventSource.secondsSinceLastEventType(.combinedSessionState, eventType: $0) }
        var ages: [TimeInterval] = [since(.leftMouseUp), since(.rightMouseUp)]
        if NSEvent.modifierFlags.contains(.command) { ages.append(since(.keyDown)) }
        return ages.filter { $0 < Self.window }.min()
    }
}
