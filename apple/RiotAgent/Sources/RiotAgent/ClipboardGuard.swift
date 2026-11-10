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
}

/// What the guard asks the daemon.
protocol GuardBackend: AnyObject {
    func redactText(_ text: String, bundleId: String) async throws -> RedactTextResult
    func detokenize(_ text: String, bundleId: String) async throws -> DetokenizeResult
    func reportOverride(eventId: String) async throws
}

/// The clipboard side of the agent, polling like a clipboard manager (Maccy, Paste):
///
/// * `changeCount` is polled every 0.5 s. Reading it triggers no privacy alert.
/// * Content is read only when a protected AI app is frontmost: when it is activated, or when
///   the clipboard changes while it is. Elsewhere the guard never looks.
/// * Sensitive text is swapped for its tokenized version before the user pastes, whatever the
///   paste gesture (⌘V, Edit menu, context menu, drag). The original is kept in memory only.
/// * Leaving the app puts the original back; text copied *out of* the app gets its tokens
///   swapped back to the real values (the native counterpart of the extension's restore-dom).
@MainActor
final class ClipboardGuard {
    struct Swap {
        let bundleId: String
        let original: [[String: Data]]
        let changeCount: Int
        let eventId: String?
        let allowBypass: Bool
    }

    /// Our own writes carry this type, so the next tick recognises them (Maccy's `.fromMaccy`).
    static let marker = "com.tryriot.agent.redacted"
    static let tokenPattern = try! NSRegularExpression(pattern: #"\[[A-Z][A-Z0-9]*(?:_[A-Z][A-Z0-9]*)*_\d+\]"#)

    private let pasteboard: PasteboardAccess
    private let backend: GuardBackend
    var targets: Set<String> = []
    var onRedacted: ((RedactTextResult, String) -> Void)?

    private(set) var frontmost: String?
    private(set) var swap: Swap?
    private var lastSeen: Int
    /// The clipboard changed while a protected app was frontmost (an answer was copied).
    private var copiedInside = false
    private var timer: Timer?
    private var inFlight: Task<Void, Never>?

    init(pasteboard: PasteboardAccess, backend: GuardBackend) {
        self.pasteboard = pasteboard
        self.backend = backend
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
        frontmost = bundleId
        enqueue { [weak self] in
            guard let self else { return }
            if let previous, self.targets.contains(previous) { await self.leave(previous) }
            if let bundleId, self.targets.contains(bundleId) { await self.inspect(for: bundleId) }
        }
    }

    func tick() {
        let count = pasteboard.changeCount
        guard count != lastSeen else { return }
        lastSeen = count
        guard isTargetFrontmost, let bundleId = frontmost else { return }
        if swap?.changeCount == count || pasteboard.hasType(Self.marker) { return }
        // New content while the AI app is frontmost: an answer copied out, or a background copy.
        copiedInside = true
        swap = nil
        enqueue { [weak self] in await self?.inspect(for: bundleId) }
    }

    /// Serialise the async steps: a leave must finish before the next app's inspection.
    private func enqueue(_ step: @escaping @MainActor () async -> Void) {
        let previous = inFlight
        inFlight = Task { @MainActor in
            await previous?.value
            await step()
        }
    }

    func waitIdle() async { await inFlight?.value }

    // MARK: steps

    private func inspect(for bundleId: String) async {
        guard !pasteboard.hasType(Self.marker), let text = pasteboard.plainText(), !text.isEmpty else { return }
        let countAtRead = pasteboard.changeCount
        let original = pasteboard.snapshot()
        guard let result = try? await backend.redactText(text, bundleId: bundleId) else { return }
        // The user copied something else meanwhile, or left the app: that newer state wins.
        guard result.action == "redacted", let redacted = result.text,
              pasteboard.changeCount == countAtRead, frontmost == bundleId else { return }
        pasteboard.writePlainText(redacted, marker: Self.marker)
        lastSeen = pasteboard.changeCount
        swap = Swap(bundleId: bundleId, original: original, changeCount: pasteboard.changeCount,
                    eventId: result.eventId, allowBypass: result.allowBypass)
        onRedacted?(result, bundleId)
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
    /// clipboard for this app, and the event is re-reported as not redacted.
    func pasteOriginal() {
        guard let swap, swap.allowBypass, pasteboard.changeCount == swap.changeCount else { return }
        self.swap = nil
        pasteboard.restore(swap.original, marker: Self.marker) // marked: not re-inspected
        lastSeen = pasteboard.changeCount
        if let eventId = swap.eventId {
            Task { try? await backend.reportOverride(eventId: eventId) }
        }
    }
}

/// The real pasteboard.
final class SystemPasteboard: PasteboardAccess {
    private let pb = NSPasteboard.general

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
