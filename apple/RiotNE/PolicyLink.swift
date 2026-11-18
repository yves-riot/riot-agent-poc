import Foundation

/// The protected apps and the AI hosts, from the daemon's `esConfig` (the list RiotES watches),
/// kept current by a subscription and saved, so that a restarted extension still knows them
/// while the daemon is down. `daemonUp` is true once the daemon has answered, false again as
/// soon as its socket closes: the proxy then refuses protected apps' flows to AI hosts.
final class PolicyLink: @unchecked Sendable {
    /// Next to the daemon's socket: `/var/run/com.tryriot.agent/flows.sock`.
    static var flowSocketPath: String {
        ((DaemonClient.socketPath as NSString).deletingLastPathComponent as NSString).appendingPathComponent("flows.sock")
    }

    /// Root-only, beside the daemon's data.
    static let savedPath = "/Library/Application Support/com.tryriot.agent/network-policy.json"

    struct State {
        let policy: Policy
        let daemonUp: Bool
    }

    private var client: DaemonClient?
    private var current = Policy.load(from: PolicyLink.savedPath) ?? .empty
    private var daemonUp = false
    private let lock = NSLock()

    var state: State {
        lock.lock()
        defer { lock.unlock() }
        return State(policy: current, daemonUp: daemonUp)
    }

    func start() {
        log.notice("\(self.current.appCount, privacy: .public) protected app(s), \(self.current.hosts.count, privacy: .public) AI host(s) from the saved policy")
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
        let wasUp = daemonUp
        client = nil
        daemonUp = false
        lock.unlock()
        if wasUp { log.error("daemon unreachable: protected apps' flows to AI hosts are refused") }
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
            var policy = Policy.empty
            for app in config.watched {
                if let team = app.teamId, !team.isEmpty { policy.teams[team] = app.bundleId }
                for prefix in app.executablePrefixes { policy.prefixes[prefix] = app.bundleId }
            }
            policy.hosts = Set(config.apiHosts ?? [])
            log.notice("\(policy.appCount, privacy: .public) protected app(s), \(policy.hosts.count, privacy: .public) AI host(s)")
            self.apply(policy)
        }
    }

    private func apply(_ policy: Policy) {
        lock.lock()
        let changed = policy != current
        current = policy
        daemonUp = true
        lock.unlock()
        if changed { policy.save(to: Self.savedPath) }
    }
}

/// Which protected app a process belongs to (by signing team id, or by its executable's folder
/// for apps without one), and the hosts the daemon decrypts.
struct Policy: Codable, Equatable {
    var teams: [String: String]
    var prefixes: [String: String]
    var hosts: Set<String>

    static let empty = Policy(teams: [:], prefixes: [:], hosts: [])

    var appCount: Int { Set(teams.values).union(prefixes.values).count }

    func app(teamId: String?, executable: String) -> String? {
        if let teamId, !teamId.isEmpty, let app = teams[teamId] { return app }
        return prefixes.first { executable.hasPrefix($0.key) }?.value
    }

    func isAIHost(_ host: String) -> Bool {
        hosts.contains(host.lowercased())
    }

    static func load(from path: String) -> Policy? {
        guard let data = FileManager.default.contents(atPath: path) else { return nil }
        return try? JSONDecoder().decode(Policy.self, from: data)
    }

    func save(to path: String) {
        do {
            let folder = (path as NSString).deletingLastPathComponent
            try FileManager.default.createDirectory(atPath: folder, withIntermediateDirectories: true)
            try JSONEncoder().encode(self).write(to: URL(fileURLWithPath: path), options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)
        } catch {
            log.error("cannot save the policy: \(String(describing: error), privacy: .public)")
        }
    }
}

private struct ConfigWire: Decodable {
    struct App: Decodable {
        var bundleId: String
        var teamId: String?
        var executablePrefixes: [String]
    }
    var watched: [App]
    var apiHosts: [String]?
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
