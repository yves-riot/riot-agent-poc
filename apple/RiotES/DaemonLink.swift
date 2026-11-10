import Foundation

/// The ES extension's side of the daemon protocol (core/riot-ipc): blocking calls with a hard
/// timeout, made from the ES scan queue, plus a subscription that keeps `esConfig` current.
final class DaemonLink: @unchecked Sendable {
    enum Verdict { case allow, deny }

    var onConfig: ((ESConfigSnapshot) -> Void)?
    private var client: DaemonClient?
    private let lock = NSLock()

    func start() {
        connect()
    }

    private func connect() {
        do {
            let client = try DaemonClient(
                onEvent: { [weak self] event in
                    if case .stateChanged = event { self?.reloadConfig() }
                },
                onClose: { [weak self] in self?.disconnected() })
            lock.lock()
            self.client = client
            lock.unlock()
            Task {
                let _: Nothing? = try? await client.call("subscribe")
                self.reloadConfig()
            }
        } catch {
            retry()
        }
    }

    private func disconnected() {
        lock.lock()
        client = nil
        lock.unlock()
        // No daemon: watch nothing rather than hold up every open on a dead socket.
        onConfig?(.empty)
        retry()
    }

    private func retry() {
        DispatchQueue.global().asyncAfter(deadline: .now() + 2) { [weak self] in self?.connect() }
    }

    private var current: DaemonClient? {
        lock.lock()
        defer { lock.unlock() }
        return client
    }

    private func reloadConfig() {
        guard let client = current else { return }
        Task {
            guard let config: EsConfigWire = try? await client.call("esConfig") else { return }
            var prefixes: [String: String] = [:]
            for app in config.watched {
                for prefix in app.executablePrefixes { prefixes[prefix] = app.bundleId }
            }
            onConfig?(ESConfigSnapshot(prefixes: prefixes, extensions: Set(config.extensions)))
        }
    }

    /// Blocks the calling (scan) queue for at most `timeout` seconds.
    func scanFile(path: String, bundleId: String, timeout: TimeInterval) -> Verdict {
        guard let client = current else { return .allow }
        let semaphore = DispatchSemaphore(value: 0)
        let box = VerdictBox()
        Task {
            let params: [String: Any] = ["path": path, "bundleId": bundleId, "deadlineMs": Int(timeout * 1000)]
            if let result: ScanFileWire = try? await client.call("scanFile", params, timeout: timeout) {
                box.value = result.decision == "deny" ? .deny : .allow
            }
            semaphore.signal()
        }
        _ = semaphore.wait(timeout: .now() + timeout)
        return box.value
    }

    private final class VerdictBox: @unchecked Sendable {
        var value: Verdict = .allow
    }
}

private struct EsConfigWire: Decodable {
    struct App: Decodable {
        var bundleId: String
        var teamId: String?
        var executablePrefixes: [String]
    }
    var watched: [App]
    var extensions: [String]
}

private struct ScanFileWire: Decodable {
    var decision: String
    var reason: String
}
