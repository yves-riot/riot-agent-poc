import AppKit
import UniformTypeIdentifiers
import os

private let log = Logger(subsystem: "com.tryriot.agent", category: "drag")

/// Where the pointer is and what the mouse does (window server state, no permission involved).
protocol PointerState: AnyObject {
    var leftButtonDown: Bool { get }
    /// The app owning the window under the pointer.
    func appUnderPointer() -> String?
    var frontmostApp: String? { get }
}

/// Answers that can't wait: a drop is being read, the reader blocks until we reply.
@MainActor
protocol BlockingBackend: AnyObject {
    func redactTextNow(_ text: String, bundleId: String) -> RedactTextResult?
    func detokenizeNow(_ text: String, bundleId: String) -> DetokenizeResult?
    func reportPaste(eventId: String) async throws -> String
}

/// Text dragged into or out of a protected app, the drag-and-drop side of `ClipboardGuard`.
///
/// A drag goes through its own pasteboard, `NSPasteboard(name: .drag)`, not the general one.
/// When a text drag starts, its text is replaced with a promise; the read decides by the app
/// under the pointer: a protected app gets the redacted text (redacted right then, for that
/// app's token scope), any other app the original (or, for a drag out of a protected app, the
/// text with its tokens' values put back). A promise is answered once and Chromium apps read
/// the drag as soon as the pointer enters them, so while the button is down, crossing between a
/// protected and another app after a read promises the text again: the drop gets what fits.
/// The HUD and the report come when the button is released over the protected app that got
/// the redacted text: entering it is not dropping.
///
/// Files and images are left alone (RiotES checks files when they are opened).
@MainActor
final class DragGuard {
    private struct Drag {
        let original: String
        /// A drag out of a protected app: its tokens' values put back, for other apps.
        var restored: String?
        /// Redactions done during this drag, per protected app.
        var redacted: [String: RedactTextResult] = [:]
        /// Who the current promise was answered for: true for a protected app, nil if unread.
        var servedTarget: Bool?
        /// The protected app that got the redacted text last.
        var redactedFor: String?
    }

    private let board: PasteboardAccess
    private let backend: BlockingBackend
    private let pointer: PointerState
    var targets: Set<String> = []
    /// Redacted text dropped into a protected app: show the HUD.
    var onDropped: ((RedactTextResult, String) -> Void)?

    private var lastSeen: Int
    private var ownWrites: Set<Int> = []
    private var drag: Drag?
    private var timer: Timer?

    init(board: PasteboardAccess, backend: BlockingBackend, pointer: PointerState = SystemPointerState()) {
        self.board = board
        self.backend = backend
        self.pointer = pointer
        self.lastSeen = board.changeCount
    }

    /// A drag lasts a few hundred ms: 50 ms polling (a change count read is cheap).
    func start() {
        let timer = Timer(timeInterval: 0.05, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.tick() }
        }
        timer.tolerance = 0.02
        RunLoop.main.add(timer, forMode: .common)
        self.timer = timer
    }

    func tick() {
        noteNewDrag()
        track()
    }

    private func noteNewDrag() {
        let count = board.changeCount
        guard count != lastSeen else { return }
        lastSeen = count
        guard !ownWrites.contains(count), !targets.isEmpty else { return }
        drag = nil
        guard Self.isPlainTextDrag(board.types), let text = board.plainText(), !text.isEmpty else { return }
        var drag = Drag(original: text)
        if let source = pointer.frontmostApp, targets.contains(source), !ClipboardGuard.tokens(in: text).isEmpty,
           let result = backend.detokenizeNow(text, bundleId: source), result.replaced > 0 {
            drag.restored = result.text
        }
        self.drag = drag
        promise()
        log.debug("drag of text started, restored=\(drag.restored != nil)")
    }

    /// While the button is down: once read, promise again when the pointer crosses between a
    /// protected app and another one. On release: a drop of redacted text, if over its app.
    private func track() {
        guard var drag else { return }
        guard pointer.leftButtonDown else {
            self.drag = nil
            if drag.servedTarget == true, let app = drag.redactedFor, pointer.appUnderPointer() == app,
               let result = drag.redacted[app] {
                log.debug("drop of redacted text into \(app, privacy: .public)")
                if let eventId = result.eventId {
                    let backend = self.backend
                    Task { _ = try? await backend.reportPaste(eventId: eventId) }
                }
                var shown = result
                shown.allowBypass = false // nothing to swap back: the text is already in the field
                onDropped?(shown, app)
            }
            return
        }
        guard let served = drag.servedTarget else { return }
        let overTarget = pointer.appUnderPointer().map(targets.contains) ?? false
        guard overTarget != served else { return }
        drag.servedTarget = nil
        self.drag = drag
        promise()
    }

    private func promise() {
        board.writePromisedText(markers: ClipboardGuard.promiseMarkers) { [weak self] in
            MainActor.assumeIsolated { self?.provide() ?? "" }
        }
        lastSeen = board.changeCount
        ownWrites.insert(lastSeen)
    }

    private func provide() -> String {
        guard var drag else { return "" }
        let under = pointer.appUnderPointer()
        defer { self.drag = drag }
        guard let app = under, targets.contains(app) else {
            drag.servedTarget = false
            return drag.restored ?? drag.original
        }
        drag.servedTarget = true
        if drag.redacted[app] == nil, let result = backend.redactTextNow(drag.original, bundleId: app) {
            drag.redacted[app] = result
        }
        guard let result = drag.redacted[app] else {
            // No answer from the daemon in time: as for a paste, the text is left as it is.
            log.debug("drag into \(app, privacy: .public): no redaction in time")
            return drag.original
        }
        guard result.action == "redacted", let text = result.text else { return drag.original }
        drag.redactedFor = app
        return text
    }

    /// Text only: replacing a drag that also carries files, images or file promises with a
    /// single string would break dropping them.
    static func isPlainTextDrag(_ types: [String]) -> Bool {
        guard !types.isEmpty else { return false }
        return !types.contains { raw in
            if raw == "NSFilenamesPboardType" || raw.contains("promise") { return true }
            guard let type = UTType(raw) else { return false }
            return type.conforms(to: .fileURL) || type.conforms(to: .image) || type.conforms(to: .audiovisualContent)
        }
    }
}

final class SystemPointerState: PointerState {
    var leftButtonDown: Bool { CGEventSource.buttonState(.hidSystemState, button: .left) }

    var frontmostApp: String? { NSWorkspace.shared.frontmostApplication?.bundleIdentifier }

    /// The topmost normal window under the pointer (window list: owner pid and bounds need no
    /// permission; Screen Recording is only for titles and contents).
    func appUnderPointer() -> String? {
        guard let point = CGEvent(source: nil)?.location,
              let windows = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID)
                as? [[String: Any]] else { return nil }
        let me = ProcessInfo.processInfo.processIdentifier
        for window in windows {
            guard (window[kCGWindowLayer as String] as? Int) == 0,
                  let pid = window[kCGWindowOwnerPID as String] as? pid_t, pid != me,
                  let boundsDict = window[kCGWindowBounds as String] as? NSDictionary,
                  let bounds = CGRect(dictionaryRepresentation: boundsDict as CFDictionary),
                  bounds.contains(point) else { continue }
            return NSRunningApplication(processIdentifier: pid)?.bundleIdentifier
        }
        return nil
    }
}
