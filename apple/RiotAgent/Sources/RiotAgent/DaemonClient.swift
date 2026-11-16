import Darwin
import Foundation

/// Line-delimited JSON over the daemon's Unix socket (protocol: core/riot-ipc). One connection
/// carries both replies and pushed events; replies are matched to callers by `id`.
final class DaemonClient: @unchecked Sendable {
    enum Failure: Error, CustomStringConvertible {
        case connect(String)
        case closed
        case timeout
        case remote(code: String, message: String)
        var description: String {
            switch self {
            case .connect(let m): return "connect: \(m)"
            case .closed: return "connection closed"
            case .timeout: return "timeout"
            case .remote(let code, let message): return "\(code): \(message)"
            }
        }
    }

    static var socketPath: String {
        ProcessInfo.processInfo.environment["RIOT_SOCKET"] ?? "/var/run/com.tryriot.agent/agent.sock"
    }

    private let fd: Int32
    private let lock = NSLock()
    private var nextId: UInt64 = 1
    private var pending: [UInt64: (Result<Data, Error>) -> Void] = [:]
    private var closed = false
    private let onEvent: (DaemonEvent) -> Void
    private let onClose: () -> Void

    init(path: String = DaemonClient.socketPath,
         onEvent: @escaping (DaemonEvent) -> Void,
         onClose: @escaping () -> Void) throws {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw Failure.connect(String(cString: strerror(errno))) }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: addr.sun_path) else {
            close(fd)
            throw Failure.connect("socket path too long")
        }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: bytes)
            raw[bytes.count] = 0
        }
        let size = socklen_t(MemoryLayout<sockaddr_un>.size)
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, size) }
        }
        guard rc == 0 else {
            let message = String(cString: strerror(errno))
            close(fd)
            throw Failure.connect(message)
        }
        var on: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
        self.fd = fd
        self.onEvent = onEvent
        self.onClose = onClose
        let reader = Thread { [weak self] in self?.readLoop() }
        reader.name = "riot-daemon-client"
        reader.start()
    }

    deinit { shutdown() }

    func shutdown() {
        lock.lock()
        let wasClosed = closed
        closed = true
        let waiting = pending
        pending.removeAll()
        lock.unlock()
        guard !wasClosed else { return }
        Darwin.shutdown(fd, SHUT_RDWR)
        close(fd)
        waiting.values.forEach { $0(.failure(Failure.closed)) }
    }

    // MARK: calls

    func call<T: Decodable>(_ method: String, _ params: [String: Any]? = nil, timeout: TimeInterval = 15) async throws -> T {
        let data = try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Data, Error>) in
            send(method, params, timeout: timeout) { cont.resume(with: $0) }
        }
        return try JSONDecoder().decode(T.self, from: data)
    }

    /// Blocks the calling thread until the reply, for an answer that can't wait (a drop being
    /// read). The reply arrives on the reader thread, so the main thread may block here.
    func callNow<T: Decodable>(_ method: String, _ params: [String: Any]? = nil, timeout: TimeInterval) -> T? {
        let done = DispatchSemaphore(value: 0)
        let reply = Locked<Result<Data, Error>>(.failure(Failure.timeout))
        send(method, params, timeout: timeout) { result in
            reply.set(result)
            done.signal()
        }
        guard done.wait(timeout: .now() + timeout) == .success, case .success(let data) = reply.get() else { return nil }
        return try? JSONDecoder().decode(T.self, from: data)
    }

    /// `completion` runs once, on the reader thread or a global queue.
    private func send(_ method: String, _ params: [String: Any]?, timeout: TimeInterval,
                      completion: @escaping (Result<Data, Error>) -> Void) {
        lock.lock()
        if closed {
            lock.unlock()
            completion(.failure(Failure.closed))
            return
        }
        let id = nextId
        nextId += 1
        // `complete` removes the handler under the lock, so it runs at most once.
        pending[id] = completion
        var envelope: [String: Any] = ["id": id, "method": method]
        if let params { envelope["params"] = params }
        lock.unlock()

        guard var line = try? JSONSerialization.data(withJSONObject: envelope) else {
            complete(id, .failure(Failure.connect("unencodable request")))
            return
        }
        line.append(0x0A)
        if !writeAll(line) {
            complete(id, .failure(Failure.closed))
            return
        }
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { [weak self] in
            self?.complete(id, .failure(Failure.timeout))
        }
    }

    private func complete(_ id: UInt64, _ result: Result<Data, Error>) {
        lock.lock()
        let handler = pending.removeValue(forKey: id)
        lock.unlock()
        handler?(result)
    }

    private func writeAll(_ data: Data) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return data.withUnsafeBytes { raw -> Bool in
            var offset = 0
            while offset < raw.count {
                let n = write(fd, raw.baseAddress! + offset, raw.count - offset)
                if n <= 0 { return false }
                offset += n
            }
            return true
        }
    }

    // MARK: reading

    private func readLoop() {
        var buffer = Data()
        var chunk = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let n = read(fd, &chunk, chunk.count)
            if n <= 0 { break }
            buffer.append(chunk, count: n)
            while let newline = buffer.firstIndex(of: 0x0A) {
                let line = buffer[buffer.startIndex..<newline]
                buffer.removeSubrange(buffer.startIndex...newline)
                handle(line: Data(line))
            }
        }
        shutdown()
        onClose()
    }

    private func handle(line: Data) {
        guard let object = try? JSONSerialization.jsonObject(with: line) as? [String: Any] else { return }
        if let event = object["event"] as? String {
            func payload<T: Decodable>(_ type: T.Type) -> T? {
                guard let data = object["data"], let json = try? JSONSerialization.data(withJSONObject: data) else { return nil }
                return try? JSONDecoder().decode(type, from: json)
            }
            switch event {
            case "fileBlocked":
                if let blocked = payload(FileBlocked.self) { onEvent(.fileBlocked(blocked)) }
            case "textRedacted":
                if let redacted = payload(TextRedacted.self) { onEvent(.textRedacted(redacted)) }
            default:
                onEvent(.stateChanged)
            }
            return
        }
        guard let id = (object["id"] as? NSNumber)?.uint64Value else { return }
        if let error = object["error"] as? [String: Any] {
            complete(id, .failure(Failure.remote(code: error["code"] as? String ?? "internal",
                                                 message: error["message"] as? String ?? "")))
            return
        }
        let ok = object["ok"] ?? NSNull()
        let data = (try? JSONSerialization.data(withJSONObject: ok, options: .fragmentsAllowed)) ?? Data("null".utf8)
        complete(id, .success(data))
    }
}

/// A value shared between threads.
final class Locked<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Value
    init(_ value: Value) { self.value = value }
    func get() -> Value { lock.withLock { value } }
    func set(_ newValue: Value) { lock.withLock { value = newValue } }
}
