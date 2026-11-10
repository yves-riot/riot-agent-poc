import EndpointSecurity
import Foundation

/// Endpoint Security client: blocks protected AI apps from opening documents that hold
/// sensitive data, whatever the path (file picker, drag and drop, pasted file).
///
/// * Only AUTH_OPEN from the protected apps' executables reaches us: muting is inverted on
///   executable path prefixes (`es_invert_muting`, macOS 13+), so the rest of the machine costs
///   nothing.
/// * Decisions come from the daemon (`scanFile`); this process holds no policy.
/// * Never make the AI app unusable: if the daemon is unreachable or the deadline is near, allow.
///   A scan *error* is a deny (fail closed, as the extension), decided by the daemon.
final class ESGuard {
    private var client: OpaquePointer?
    private let queue = DispatchQueue(label: "com.tryriot.agent.es.scan", qos: .userInitiated, attributes: .concurrent)
    private let daemon: DaemonLink
    private var config = ESConfigSnapshot.empty
    private let configLock = NSLock()
    /// Kept clear of the kernel's deadline: answering late gets the client killed.
    private let deadlineMargin: TimeInterval = 1.5

    init(daemon: DaemonLink) {
        self.daemon = daemon
    }

    func start() throws {
        let result = es_new_client(&client) { [weak self] client, message in
            self?.handle(client, message)
        }
        guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let client else {
            throw ESError.newClient(result)
        }
        guard es_clear_cache(client) == ES_CLEAR_CACHE_RESULT_SUCCESS else { throw ESError.setup("clear cache") }
        // Inverted path muting: the muted prefixes become the only ones delivered.
        guard es_invert_muting(client, ES_MUTE_INVERSION_TYPE_PATH) == ES_RETURN_SUCCESS else {
            throw ESError.setup("invert muting")
        }
        var events = [ES_EVENT_TYPE_AUTH_OPEN]
        guard es_subscribe(client, &events, UInt32(events.count)) == ES_RETURN_SUCCESS else {
            throw ESError.setup("subscribe")
        }
        daemon.onConfig = { [weak self] snapshot in self?.apply(snapshot) }
        daemon.start()
    }

    /// Re-targets the client when the policy changes (apps added/removed, monitoring toggled).
    private func apply(_ snapshot: ESConfigSnapshot) {
        guard let client else { return }
        configLock.lock()
        config = snapshot
        configLock.unlock()
        es_unmute_all_paths(client)
        for prefix in snapshot.prefixes.keys {
            es_mute_path(client, prefix, ES_MUTE_PATH_TYPE_PREFIX)
        }
        // Earlier allow-decisions may be cached by the kernel for files that are now in scope.
        es_clear_cache(client)
        NSLog("riot-es: watching %d executable prefixes", snapshot.prefixes.count)
    }

    private func handle(_ client: OpaquePointer, _ message: UnsafePointer<es_message_t>) {
        guard message.pointee.event_type == ES_EVENT_TYPE_AUTH_OPEN else { return }
        let fflag = UInt32(bitPattern: message.pointee.event.open.fflag)
        let path = string(message.pointee.event.open.file.pointee.path)
        let executable = string(message.pointee.process.pointee.executable.pointee.path)

        configLock.lock()
        let snapshot = config
        configLock.unlock()

        guard let bundleId = snapshot.bundleId(forExecutable: executable), snapshot.isCandidate(path) else {
            // Not ours to judge: allow, and let the kernel cache it for this process/file.
            es_respond_flags_result(client, message, fflag, true)
            return
        }

        let budget = secondsUntil(message.pointee.deadline) - deadlineMargin
        guard budget > 0.2 else {
            es_respond_flags_result(client, message, fflag, false)
            return
        }
        es_retain_message(message)
        queue.async { [daemon] in
            let verdict = daemon.scanFile(path: path, bundleId: bundleId, timeout: budget)
            // Never cache a verdict: the file may change, and "send anyway" must take effect.
            es_respond_flags_result(client, message, verdict == .deny ? 0 : fflag, false)
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

/// What the ES client watches, from the daemon's `esConfig`.
struct ESConfigSnapshot {
    /// Executable path prefix → the protected app's bundle id.
    var prefixes: [String: String]
    var extensions: Set<String>

    static let empty = ESConfigSnapshot(prefixes: [:], extensions: [])

    func bundleId(forExecutable path: String) -> String? {
        prefixes.first { path.hasPrefix($0.key) }?.value
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
