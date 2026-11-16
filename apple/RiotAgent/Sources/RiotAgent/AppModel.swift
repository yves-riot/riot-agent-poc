import AppKit
import SwiftUI

/// App state: the daemon connection, what the popup shows, and the wiring between the clipboard
/// guard, pushed daemon events and the HUD.
@MainActor
final class AppModel: ObservableObject, GuardBackend, BlockingBackend {
    @Published private(set) var popup = PopupState.placeholder
    @Published private(set) var connected = false
    @Published private(set) var pasteboardAccess = SystemPasteboard.accessState
    @AppStorage("popupMode") var popupMode = "full" // full | lite, as the extension's pasteGuard:popupMode

    private var client: DaemonClient?
    private(set) lazy var clipboard = ClipboardGuard(pasteboard: SystemPasteboard(), backend: self)
    private(set) lazy var drags = DragGuard(board: SystemPasteboard(NSPasteboard(name: .drag)), backend: self)
    lazy var hud = HUDController(model: self)

    func start() {
        clipboard.onPasted = { [weak self] result, bundleId in
            self?.hud.showText(result: result, appName: self?.appName(bundleId) ?? bundleId)
        }
        clipboard.start()
        drags.onDropped = { [weak self] result, bundleId in
            self?.hud.showText(result: result, appName: self?.appName(bundleId) ?? bundleId)
        }
        drags.start()
        connect()
    }

    // MARK: connection

    private func connect() {
        do {
            client = try DaemonClient(
                onEvent: { [weak self] event in Task { @MainActor in self?.handle(event) } },
                onClose: { [weak self] in Task { @MainActor in self?.disconnected() } })
            connected = true
            Task {
                let _: Nothing? = try? await client?.call("subscribe")
                await refresh()
            }
        } catch {
            connected = false
            scheduleReconnect()
        }
    }

    private func disconnected() {
        connected = false
        client = nil
        clipboard.targets = [] // no daemon, no decisions: leave the clipboard alone
        drags.targets = []
        scheduleReconnect()
    }

    private func scheduleReconnect() {
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [weak self] in
            guard let self, self.client == nil else { return }
            self.connect()
        }
    }

    private func handle(_ event: DaemonEvent) {
        switch event {
        case .stateChanged:
            Task { await refresh() }
        case .fileBlocked(let blocked):
            hud.showFile(blocked)
            Task { await refresh() }
        case .textRedacted(let redacted):
            hud.showMessage(redacted)
            Task { await refresh() }
        }
    }

    func refresh() async {
        pasteboardAccess = SystemPasteboard.accessState
        guard let client else { return }
        if let state: PopupState = try? await client.call("popupState") {
            popup = state
            let active: Bool
            if case .signedIn = state.view { active = true } else if case .reconnect = state.view { active = true } else { active = false }
            clipboard.targets = active ? Set(state.protectedApps.map(\.bundleId)) : []
            drags.targets = clipboard.targets
        }
    }

    func appName(_ bundleId: String) -> String {
        popup.protectedApps.first { $0.bundleId == bundleId }?.displayName ?? bundleId
    }

    // MARK: GuardBackend

    func redactText(_ text: String, bundleId: String) async throws -> RedactTextResult {
        guard let client else { throw DaemonClient.Failure.closed }
        return try await client.call("redactText", ["text": text, "bundleId": bundleId])
    }

    func reportPaste(eventId: String) async throws -> String {
        guard let client else { throw DaemonClient.Failure.closed }
        let result: ReportPasteResult = try await client.call("reportPaste", ["eventId": eventId])
        return result.pasteId
    }

    func detokenize(_ text: String, bundleId: String) async throws -> DetokenizeResult {
        guard let client else { throw DaemonClient.Failure.closed }
        return try await client.call("detokenize", ["text": text, "bundleId": bundleId])
    }

    // MARK: BlockingBackend (a drop is being read: the main thread waits, at most 2 s)

    func redactTextNow(_ text: String, bundleId: String) -> RedactTextResult? {
        client?.callNow("redactText", ["text": text, "bundleId": bundleId], timeout: 2)
    }

    func detokenizeNow(_ text: String, bundleId: String) -> DetokenizeResult? {
        client?.callNow("detokenize", ["text": text, "bundleId": bundleId], timeout: 2)
    }

    func reportOverride(pasteId: String) async throws {
        guard let client else { throw DaemonClient.Failure.closed }
        let _: Nothing = try await client.call("reportOverride", ["pasteId": pasteId])
    }

    func grantFileBypass(eventId: String) async -> Bool {
        guard let client else { return false }
        let ok: Nothing? = try? await client.call("grantFileBypass", ["eventId": eventId])
        return ok != nil
    }

    func grantTextBypass(eventId: String) async -> Bool {
        guard let client else { return false }
        let ok: Nothing? = try? await client.call("grantTextBypass", ["eventId": eventId])
        return ok != nil
    }

    func diagnostics() async -> String {
        guard let client else { return "daemon: not connected (\(DaemonClient.socketPath))" }
        guard let data: AnyJSON = try? await client.call("status") else { return "status unavailable" }
        return data.pretty
    }
}

/// Any JSON value, for the diagnostics dump.
struct AnyJSON: Decodable {
    let value: Any
    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { value = NSNull() }
        else if let b = try? c.decode(Bool.self) { value = b }
        else if let n = try? c.decode(Double.self) { value = n }
        else if let s = try? c.decode(String.self) { value = s }
        else if let a = try? c.decode([AnyJSON].self) { value = a.map(\.value) }
        else { value = try c.decode([String: AnyJSON].self).mapValues(\.value) }
    }
    var pretty: String {
        guard let data = try? JSONSerialization.data(withJSONObject: value, options: [.prettyPrinted, .sortedKeys, .fragmentsAllowed])
        else { return "\(value)" }
        return String(decoding: data, as: UTF8.self)
    }
}
