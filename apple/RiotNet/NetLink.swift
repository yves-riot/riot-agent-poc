import Foundation

/// What the daemon wants relayed: the protected apps and where its proxy listens.
struct NetConfigSnapshot: Sendable {
    var proxyPort: UInt16
    var bundleIds: [String]

    /// The protected app a signing identifier belongs to: the app itself, or one of its helpers
    /// (`com.anthropic.claudefordesktop.helper`).
    func app(for signingIdentifier: String) -> String? {
        bundleIds.first { signingIdentifier == $0 || signingIdentifier.hasPrefix($0 + ".") }
    }
}

/// The network extension's side of the daemon protocol (core/riot-ipc): a subscription that
/// keeps `netConfig` current. `config` is nil whenever the daemon cannot take flows (not
/// running, monitoring off, proxy off): the extension then claims nothing and the apps connect
/// directly.
final class NetLink: @unchecked Sendable {
    private var client: DaemonClient?
    private var snapshot: NetConfigSnapshot?
    private let lock = NSLock()

    var config: NetConfigSnapshot? {
        lock.lock()
        defer { lock.unlock() }
        return snapshot
    }

    func start() {
        connect()
    }

    private func connect() {
        do {
            let client = try DaemonClient(
                onEvent: { [weak self] event in
                    if case .stateChanged = event { self?.reload() }
                },
                onClose: { [weak self] in self?.disconnected() })
            lock.lock()
            self.client = client
            lock.unlock()
            Task {
                let _: Nothing? = try? await client.call("subscribe")
                self.reload()
            }
        } catch {
            retry()
        }
    }

    private func disconnected() {
        lock.lock()
        client = nil
        snapshot = nil
        lock.unlock()
        retry()
    }

    private var current: DaemonClient? {
        lock.lock()
        defer { lock.unlock() }
        return client
    }

    private func retry() {
        DispatchQueue.global().asyncAfter(deadline: .now() + 2) { [weak self] in self?.connect() }
    }

    private func reload() {
        guard let client = current else { return }
        Task {
            guard let wire: NetConfigWire = try? await client.call("netConfig") else { return }
            var next: NetConfigSnapshot?
            if let port = wire.proxyPort, !wire.apps.isEmpty {
                next = NetConfigSnapshot(proxyPort: port, bundleIds: wire.apps.map(\.bundleId))
            }
            self.store(next)
            NSLog("riot-net: relaying %d apps", next?.bundleIds.count ?? 0)
        }
    }

    private func store(_ next: NetConfigSnapshot?) {
        lock.lock()
        snapshot = next
        lock.unlock()
    }
}

private struct NetConfigWire: Decodable {
    struct App: Decodable {
        var bundleId: String
        var teamId: String?
    }
    var proxyPort: UInt16?
    var apps: [App]
}
