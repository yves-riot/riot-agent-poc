import Darwin
import EndpointSecurity
import Foundation
import Security

/// Endpoint Security client: blocks protected AI apps from opening documents that hold
/// sensitive data, whatever the path (file picker, drag and drop, pasted file).
///
/// * The protected apps are recognised by their code signature (the policy's team ids), or by
///   their executable's folder for apps without a team id (Apple's own). Their descendants are
///   theirs too: Claude Desktop runs Claude Code from `~/Library/Application Support`, and
///   Claude Code runs `cat`, `python`… on the user's files.
/// * Two ES clients. `lifecycle` sees every exec, fork and exit and keeps the set of protected
///   processes. Exec is an AUTH event: the new image is marked before it runs, so a `cat` that
///   opens a file at once is already protected (a notify arrived after that open). The answer is
///   an in-memory lookup, never cached. `opens` gets AUTH_OPEN from protected processes only:
///   process muting is inverted (`es_invert_muting`, macOS 13+), so the rest of the machine costs
///   nothing.
/// * Decisions come from the daemon (`scanFile`); this process holds no policy.
/// * Never make the AI app unusable: if the daemon is unreachable or the deadline is near, allow.
///   A scan *error* is a deny (fail closed, as the extension), decided by the daemon.
final class ESGuard {
    private var opens: OpaquePointer?
    private var lifecycle: OpaquePointer?
    private let queue = DispatchQueue(label: "com.tryriot.agent.es.scan", qos: .userInitiated, attributes: .concurrent)
    private let daemon: DaemonLink
    private var config = ESConfigSnapshot.empty
    /// Protected processes: (pid, pidversion) → their token and the app they belong to.
    private var protected: [ProcessKey: (token: audit_token_t, bundleId: String)] = [:]
    /// The same by pid alone, for parents (`ppid` carries no pidversion).
    private var protectedPids: [pid_t: String] = [:]
    private let lock = NSLock()
    /// Kept clear of the kernel's deadline: answering late gets the client killed.
    private let deadlineMargin: TimeInterval = 1.5
    /// `RIOT_DEBUG=1`: one line per judged open and per protected process.
    private let debug = ProcessInfo.processInfo.environment["RIOT_DEBUG"] != nil

    init(daemon: DaemonLink) {
        self.daemon = daemon
    }

    func start() throws {
        var opens: OpaquePointer?
        let result = es_new_client(&opens) { [weak self] client, message in self?.handleOpen(client, message) }
        guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let opens else { throw ESError.newClient(result) }
        self.opens = opens
        guard es_clear_cache(opens) == ES_CLEAR_CACHE_RESULT_SUCCESS else { throw ESError.setup("clear cache") }
        // Inverted process muting: the muted processes become the only ones delivered.
        guard es_invert_muting(opens, ES_MUTE_INVERSION_TYPE_PROCESS) == ES_RETURN_SUCCESS else {
            throw ESError.setup("invert muting")
        }
        var openEvents = [ES_EVENT_TYPE_AUTH_OPEN]
        guard es_subscribe(opens, &openEvents, UInt32(openEvents.count)) == ES_RETURN_SUCCESS else {
            throw ESError.setup("subscribe opens")
        }

        var lifecycle: OpaquePointer?
        let lifecycleResult = es_new_client(&lifecycle) { [weak self] client, message in
            guard let self else {
                if message.pointee.event_type == ES_EVENT_TYPE_AUTH_EXEC {
                    es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
                }
                return
            }
            self.handleLifecycle(client, message)
        }
        guard lifecycleResult == ES_NEW_CLIENT_RESULT_SUCCESS, let lifecycle else { throw ESError.newClient(lifecycleResult) }
        self.lifecycle = lifecycle
        var lifecycleEvents = [ES_EVENT_TYPE_AUTH_EXEC, ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXIT]
        guard es_subscribe(lifecycle, &lifecycleEvents, UInt32(lifecycleEvents.count)) == ES_RETURN_SUCCESS else {
            throw ESError.setup("subscribe lifecycle")
        }

        daemon.onConfig = { [weak self] snapshot in self?.apply(snapshot) }
        daemon.start()
    }

    // MARK: protected processes

    /// Re-targets when the policy changes (apps added/removed, monitoring toggled): the processes
    /// already running are looked at again.
    private func apply(_ snapshot: ESConfigSnapshot) {
        guard let opens else { return }
        lock.lock()
        config = snapshot
        for (_, entry) in protected {
            var token = entry.token
            es_unmute_process(opens, &token)
        }
        protected = [:]
        protectedPids = [:]
        lock.unlock()
        for process in RunningProcess.all() {
            protect(token: process.token, bundleId: snapshot.app(teamId: process.teamId, executable: process.executable))
        }
        // Descendants of protected processes started before us.
        var added = true
        while added {
            added = false
            for process in RunningProcess.all() where bundleId(of: process.token) == nil {
                if let parent = protectedApp(pid: process.ppid) {
                    protect(token: process.token, bundleId: parent)
                    added = true
                }
            }
        }
        // Earlier allow-decisions may be cached by the kernel for files that are now in scope.
        es_clear_cache(opens)
        lock.lock()
        let count = protected.count
        lock.unlock()
        NSLog("riot-es: watching %d apps (%d team ids), %d running processes", snapshot.apps, snapshot.teams.count, count)
    }

    private func handleLifecycle(_ client: OpaquePointer, _ message: UnsafePointer<es_message_t>) {
        let process = message.pointee.process.pointee
        switch message.pointee.event_type {
        case ES_EVENT_TYPE_NOTIFY_FORK:
            let child = message.pointee.event.fork.child.pointee
            protect(token: child.audit_token, bundleId: bundleId(of: process.audit_token))
        case ES_EVENT_TYPE_AUTH_EXEC:
            // The image changes, and so does the audit token (pidversion): carry the protection
            // over (from the process, or its parent for a posix_spawn whose fork we may not have
            // seen yet), or start it if the new image is a protected app's. Then let it run.
            let target = message.pointee.event.exec.target.pointee
            lock.lock()
            let snapshot = config
            let inherited = protected[ProcessKey(process.audit_token)]?.bundleId ?? protectedPids[process.ppid]
            lock.unlock()
            let app = inherited
                ?? snapshot.app(teamId: string(target.team_id), executable: string(target.executable.pointee.path))
            unprotect(token: process.audit_token)
            protect(token: target.audit_token, bundleId: app)
            es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            unprotect(token: process.audit_token)
        default:
            break
        }
    }

    private func protect(token: audit_token_t, bundleId: String?) {
        guard let bundleId, let opens else { return }
        let key = ProcessKey(token)
        lock.lock()
        let isNew = protected.updateValue((token, bundleId), forKey: key) == nil
        protectedPids[key.pid] = bundleId
        lock.unlock()
        guard isNew else { return }
        var token = token
        es_mute_process(opens, &token)
        if debug { NSLog("riot-es: protecting pid %d for %@", key.pid, bundleId) }
    }

    private func unprotect(token: audit_token_t) {
        guard let opens else { return }
        let key = ProcessKey(token)
        lock.lock()
        let removed = protected.removeValue(forKey: key)
        if removed != nil { protectedPids[key.pid] = nil }
        lock.unlock()
        guard removed != nil else { return }
        var token = token
        es_unmute_process(opens, &token)
    }

    private func bundleId(of token: audit_token_t) -> String? {
        lock.lock()
        defer { lock.unlock() }
        return protected[ProcessKey(token)]?.bundleId
    }

    private func protectedApp(pid: pid_t) -> String? {
        lock.lock()
        defer { lock.unlock() }
        return protectedPids[pid]
    }

    // MARK: opens

    private func handleOpen(_ client: OpaquePointer, _ message: UnsafePointer<es_message_t>) {
        guard message.pointee.event_type == ES_EVENT_TYPE_AUTH_OPEN else { return }
        let fflag = UInt32(bitPattern: message.pointee.event.open.fflag)
        let path = string(message.pointee.event.open.file.pointee.path)

        lock.lock()
        let snapshot = config
        let app = protected[ProcessKey(message.pointee.process.pointee.audit_token)]?.bundleId
        lock.unlock()

        // Authorize with every flag: echoing the request's `fflag` back let only an app's first
        // open of a file through (TextEdit then failed to read it).
        guard let bundleId = app, snapshot.isCandidate(path) else {
            // Not ours to judge: allow, and let the kernel cache it.
            es_respond_flags_result(client, message, UInt32.max, true)
            return
        }

        let budget = secondsUntil(message.pointee.deadline) - deadlineMargin
        guard budget > 0.2 else {
            es_respond_flags_result(client, message, UInt32.max, false)
            return
        }
        es_retain_message(message)
        let started = Date()
        let executable = (string(message.pointee.process.pointee.executable.pointee.path) as NSString).lastPathComponent
        queue.async { [daemon, debug] in
            let verdict = daemon.scanFile(path: path, bundleId: bundleId, timeout: budget)
            if debug {
                NSLog("riot-es: %@ (%@) %@ fflag=0x%x %@ in %.0f ms (budget %.1f s)", bundleId, executable,
                      (path as NSString).lastPathComponent, fflag, verdict == .deny ? "deny" : "allow",
                      Date().timeIntervalSince(started) * 1000, budget)
            }
            // Never cache a verdict: the file may change, and "send anyway" must take effect.
            es_respond_flags_result(client, message, verdict == .deny ? 0 : UInt32.max, false)
            es_release_message(message)
        }
    }

    private func string(_ token: es_string_token_t) -> String {
        guard let data = token.data, token.length > 0 else { return "" }
        return String(decoding: UnsafeRawBufferPointer(start: data, count: token.length), as: UTF8.self)
    }

    private func secondsUntil(_ deadline: UInt64) -> TimeInterval {
        var info = mach_timebase_info_data_t()
        mach_timebase_info(&info)
        let now = mach_absolute_time()
        guard deadline > now else { return 0 }
        let nanos = Double(deadline - now) * Double(info.numer) / Double(info.denom)
        return nanos / 1_000_000_000
    }

    enum ESError: Error {
        case newClient(es_new_client_result_t)
        case setup(String)
    }
}

/// A process instance: the pid and its pidversion, which changes at every exec.
struct ProcessKey: Hashable {
    let pid: pid_t
    let version: Int32

    init(_ token: audit_token_t) {
        pid = audit_token_to_pid(token)
        version = audit_token_to_pidversion(token)
    }
}

/// What the ES client watches, from the daemon's `esConfig`.
struct ESConfigSnapshot {
    /// Signing team id → the protected app's bundle id.
    var teams: [String: String]
    /// Executable path prefix → bundle id, for apps without a team id (Apple's own).
    var prefixes: [String: String]
    var extensions: Set<String>

    static let empty = ESConfigSnapshot(teams: [:], prefixes: [:], extensions: [])

    var apps: Int { Set(teams.values).union(prefixes.values).count }

    /// The protected app a process belongs to, from its signature or its executable's folder.
    func app(teamId: String?, executable: String) -> String? {
        if let teamId, !teamId.isEmpty, let app = teams[teamId] { return app }
        return prefixes.first { executable.hasPrefix($0.key) }?.value
    }

    /// A user document the engine can scan. The app's own files (caches, state, bundle) are not
    /// uploads and must not pay for a scan.
    func isCandidate(_ path: String) -> Bool {
        let ext = (path as NSString).pathExtension.lowercased()
        guard extensions.contains(ext) else { return false }
        let ignored = ["/System/", "/Library/", "/private/var/", "/Applications/", "/usr/", "/opt/"]
        if ignored.contains(where: path.hasPrefix) { return false }
        if path.contains("/Library/") { return false } // ~/Library: app support, caches, containers
        return true
    }
}

/// The processes already running, with what identifies their app (root: any task's name port).
struct RunningProcess {
    let token: audit_token_t
    let ppid: pid_t
    let executable: String
    let teamId: String?

    static func all() -> [RunningProcess] {
        let capacity = Int(proc_listallpids(nil, 0)) + 64
        var pids = [pid_t](repeating: 0, count: capacity)
        let count = Int(proc_listallpids(&pids, Int32(capacity * MemoryLayout<pid_t>.size)))
        return pids.prefix(max(count, 0)).compactMap { pid in pid > 0 ? RunningProcess(pid: pid) : nil }
    }

    init?(pid: pid_t) {
        var task: mach_port_name_t = 0
        guard task_name_for_pid(mach_task_self_, pid, &task) == KERN_SUCCESS else { return nil }
        defer { mach_port_deallocate(mach_task_self_, task) }
        var token = audit_token_t()
        var size = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<natural_t>.size)
        let kr = withUnsafeMutablePointer(to: &token) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(size)) {
                task_info(task, task_flavor_t(TASK_AUDIT_TOKEN), $0, &size)
            }
        }
        guard kr == KERN_SUCCESS else { return nil }

        var path = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
        guard proc_pidpath(pid, &path, UInt32(path.count)) > 0 else { return nil }
        var info = proc_bsdinfo()
        let infoSize = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, infoSize) == infoSize else { return nil }

        self.token = token
        self.ppid = pid_t(info.pbi_ppid)
        self.executable = String(cString: path)
        self.teamId = Self.teamId(of: token)
    }

    private static func teamId(of token: audit_token_t) -> String? {
        var token = token
        let audit = Data(bytes: &token, count: MemoryLayout<audit_token_t>.size)
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
