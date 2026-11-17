import Foundation
import Network
import NetworkExtension

/// One claimed TCP flow, piped to the daemon: a CONNECT on `flows.sock`, then bytes both ways.
/// The flow is opened only once the daemon has accepted it, so that a refusal reaches the app
/// as a failed connection rather than a silent one.
final class FlowRelay: @unchecked Sendable {
    private let flow: NEAppProxyTCPFlow
    private let target: String
    private let app: String
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "riot-ne.flow")
    private var head = Data()
    /// Keeps the relay alive until both directions are done.
    private var selfReference: FlowRelay?
    private var openDirections = 2

    init(flow: NEAppProxyTCPFlow, target: String, app: String, socket: String) {
        self.flow = flow
        self.target = target
        self.app = app
        connection = NWConnection(to: .unix(path: socket), using: .tcp)
    }

    func start() {
        selfReference = self
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready: self.sendConnect()
            case let .failed(error), let .waiting(error): self.fail("daemon unreachable: \(error)")
            default: break
            }
        }
        connection.start(queue: queue)
    }

    private func sendConnect() {
        connection.stateUpdateHandler = nil
        let app = self.app.replacingOccurrences(of: "\r", with: "").replacingOccurrences(of: "\n", with: "")
        let request = "CONNECT \(target) HTTP/1.1\r\nHost: \(target)\r\nRiot-App: \(app)\r\n\r\n"
        connection.send(content: Data(request.utf8), completion: .contentProcessed { [weak self] error in
            if let error { self?.fail("CONNECT not sent: \(error)") } else { self?.readHead() }
        })
    }

    /// Reads the daemon's answer up to the blank line; anything after it already belongs to
    /// the tunnel.
    private func readHead() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data { self.head.append(data) }
            if let end = self.head.range(of: Data("\r\n\r\n".utf8)) {
                let status = String(decoding: self.head[..<end.lowerBound], as: UTF8.self).split(separator: "\r\n").first ?? ""
                guard status.contains(" 200 ") else { return self.fail("daemon refused: \(status)") }
                let rest = self.head[end.upperBound...]
                self.openFlow(then: rest)
            } else if isComplete || error != nil || self.head.count > 16384 {
                self.fail("no answer from the daemon")
            } else {
                self.readHead()
            }
        }
    }

    private func openFlow(then early: Data) {
        flow.open(withLocalFlowEndpoint: nil) { [weak self] error in
            guard let self else { return }
            if let error { return self.fail("flow not opened: \(error)") }
            if early.isEmpty {
                self.pumpToApp()
            } else {
                self.flow.write(Data(early)) { [weak self] _ in self?.pumpToApp() }
            }
            self.pumpToDaemon()
        }
    }

    private func pumpToDaemon() {
        flow.readData { [weak self] data, error in
            guard let self else { return }
            guard let data, !data.isEmpty, error == nil else {
                // The app closed its side (or failed): tell the daemon, keep reading its answer.
                self.connection.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .idempotent)
                return self.done()
            }
            self.connection.send(content: data, completion: .contentProcessed { [weak self] error in
                if error == nil { self?.pumpToDaemon() } else { self?.close() }
            })
        }
    }

    private func pumpToApp() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            let finish = {
                if isComplete || error != nil {
                    self.flow.closeWriteWithError(nil)
                    self.done()
                } else {
                    self.pumpToApp()
                }
            }
            guard let data, !data.isEmpty else { return finish() }
            self.flow.write(data) { [weak self] error in
                if error == nil { finish() } else { self?.close() }
            }
        }
    }

    private func done() {
        queue.async {
            self.openDirections -= 1
            if self.openDirections <= 0 { self.close() }
        }
    }

    private func fail(_ reason: String) {
        log.error("\(self.app, privacy: .public) → \(self.target, privacy: .public): \(reason, privacy: .public)")
        close()
    }

    private func close() {
        queue.async {
            guard self.selfReference != nil else { return }
            self.flow.closeReadWithError(nil)
            self.flow.closeWriteWithError(nil)
            self.connection.cancel()
            self.selfReference = nil
        }
    }
}
