import Foundation

/// The protected apps, from the daemon's `esConfig` (the list RiotES watches), kept current by a
/// subscription. Without a daemon, nothing is protected: flows are left to the system rather
/// than held on a dead socket.
final class PolicyLink: @unchecked Sendable {
    /// Next to the daemon's socket: `/var/run/com.tryriot.agent/flows.sock`.
    static var flowSocketPath: String {
        ((DaemonClient.socketPath as NSString).deletingLastPathComponent as NSString).appendingPathComponent("flows.sock")
    }

    private var client: DaemonClient?
    private var current = AppMatcher.empty
    private let lock = NSLock()

    var snapshot: AppMatcher {
        lock.lock()
        defer { lock.unlock() }
        return current
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
        current = .empty
        lock.unlock()
        retry()
    }

    private func retry() {
        DispatchQueue.global().asyncAfter(deadline: .now() + 2) { [weak self] in self?.connect() }
    }

    private func reload() {
        lock.lock()
        let client = self.client
        lock.unlock()
        guard let client else { return }
        Task {
            guard let config: ConfigWire = try? await client.call("esConfig") else { return }
            var matcher = AppMatcher.empty
            for app in config.watched {
                if let team = app.teamId, !team.isEmpty { matcher.teams[team] = app.bundleId }
                for prefix in app.executablePrefixes { matcher.prefixes[prefix] = app.bundleId }
            }
            log.notice("\(Set(matcher.teams.values).union(matcher.prefixes.values).count, privacy: .public) protected app(s)")
            self.apply(matcher)
        }
    }

    private func apply(_ matcher: AppMatcher) {
        lock.lock()
        current = matcher
        lock.unlock()
    }
}

/// Which protected app a process belongs to: by signing team id, or by its executable's folder
/// for apps without one.
struct AppMatcher {
    var teams: [String: String]
    var prefixes: [String: String]

    static let empty = AppMatcher(teams: [:], prefixes: [:])

    func app(teamId: String?, executable: String) -> String? {
        if let teamId, !teamId.isEmpty, let app = teams[teamId] { return app }
        return prefixes.first { executable.hasPrefix($0.key) }?.value
    }
}

private struct ConfigWire: Decodable {
    struct App: Decodable {
        var bundleId: String
        var teamId: String?
        var executablePrefixes: [String]
    }
    var watched: [App]
}

/// A flow's process, from its audit token: pid, executable and signing team id, cached per
/// process (pid and pid version, so a reused pid is looked up again).
final class ProcessIdentities: @unchecked Sendable {
    struct Identity {
        let pid: pid_t
        let executable: String
        let teamId: String?
    }

    private var cache: [Key: Identity] = [:]
    private let lock = NSLock()

    private struct Key: Hashable {
        let pid: pid_t
        let version: Int32
    }

    func identify(auditToken data: Data) -> Identity? {
        guard data.count == MemoryLayout<audit_token_t>.size else { return nil }
        let token = data.withUnsafeBytes { $0.loadUnaligned(as: audit_token_t.self) }
        let key = Key(pid: audit_token_to_pid(token), version: audit_token_to_pidversion(token))
        lock.lock()
        if let hit = cache[key] {
            lock.unlock()
            return hit
        }
        lock.unlock()

        var path = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
        guard proc_pidpath(key.pid, &path, UInt32(path.count)) > 0 else { return nil }
        let identity = Identity(pid: key.pid, executable: String(cString: path), teamId: Self.teamId(audit: data))
        lock.lock()
        if cache.count > 4096 { cache.removeAll() }
        cache[key] = identity
        lock.unlock()
        return identity
    }

    private static func teamId(audit: Data) -> String? {
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: audit] as CFDictionary, [], &code) == errSecSuccess,
              let code else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return nil }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let info = info as? [String: Any] else { return nil }
        return info[kSecCodeInfoTeamIdentifier as String] as? String
    }
}
