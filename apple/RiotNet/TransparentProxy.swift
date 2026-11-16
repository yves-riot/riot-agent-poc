import Foundation
import Network
import NetworkExtension

/// Hands the protected AI apps' HTTPS connections to the daemon's local proxy, which decides
/// what to decrypt (core/riot-proxy). This process holds no policy and reads no content.
///
/// * Only TCP port 443 from the protected apps is claimed. Everything else on the machine is
///   refused in `handleNewFlow` and goes out directly, untouched.
/// * The apps' QUIC (UDP 443) is closed, so they fall back to HTTP/2 over TCP, which is relayed.
/// * Never make the AI app unusable: with no daemon or no proxy, nothing is claimed.
@objc(RiotTransparentProxy)
final class TransparentProxy: NETransparentProxyProvider {
    private let daemon = NetLink()

    override func startProxy(options: [String: Any]?, completionHandler: @escaping (Error?) -> Void) {
        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        // Prefix 0: any address, on port 443. (The endpoint types are the pre-macOS 15 ones: the
        // extension still runs on 14.)
        settings.includedNetworkRules = ["0.0.0.0", "::"].flatMap { address in
            let any = NWHostEndpoint(hostname: address, port: "443")
            return [
                NENetworkRule(remoteNetwork: any, remotePrefix: 0, localNetwork: nil, localPrefix: 0, protocol: .TCP, direction: .outbound),
                NENetworkRule(remoteNetwork: any, remotePrefix: 0, localNetwork: nil, localPrefix: 0, protocol: .UDP, direction: .outbound),
            ]
        }
        setTunnelNetworkSettings(settings) { [daemon] error in
            if let error {
                NSLog("riot-net: cannot apply the network rules: %@", String(describing: error))
            } else {
                daemon.start()
                NSLog("riot-net: started")
            }
            completionHandler(error)
        }
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        NSLog("riot-net: stopped (reason %ld)", reason.rawValue)
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        guard let config = daemon.config,
              let bundleId = config.app(for: flow.metaData.sourceAppSigningIdentifier) else { return false }
        if let tcp = flow as? NEAppProxyTCPFlow {
            guard let destination = tcp.remoteEndpoint as? NWHostEndpoint else { return false }
            Relay(flow: tcp, destination: destination, proxyPort: config.proxyPort,
                  source: Source(bundleId: bundleId, auditToken: flow.metaData.sourceAppAuditToken)).start()
            return true
        }
        // QUIC from a protected app: refused, so the app retries over TCP.
        let refused = NSError(domain: NEAppProxyErrorDomain, code: NEAppProxyFlowError.refused.rawValue)
        flow.closeReadWithError(refused)
        flow.closeWriteWithError(refused)
        return true
    }
}

/// Who opened a flow, for the daemon: the protected app, and the user and process behind it.
struct Source {
    var bundleId: String
    var uid: uid_t?
    var pid: pid_t?

    init(bundleId: String, auditToken: Data?) {
        self.bundleId = bundleId
        if let auditToken, auditToken.count == MemoryLayout<audit_token_t>.size {
            let token = auditToken.withUnsafeBytes { $0.loadUnaligned(as: audit_token_t.self) }
            uid = audit_token_to_euid(token)
            pid = audit_token_to_pid(token)
        }
    }
}

/// One app connection, relayed through the daemon's proxy: a `CONNECT` naming the destination
/// and the source, then bytes both ways until either side is done.
final class Relay: @unchecked Sendable {
    private let flow: NEAppProxyTCPFlow
    private let connection: NWConnection
    private let preface: Data
    private var reply = Data()
    private let queue = DispatchQueue(label: "com.tryriot.agent.net.relay")
    private var closed = false

    init(flow: NEAppProxyTCPFlow, destination: NWHostEndpoint, proxyPort: UInt16, source: Source) {
        self.flow = flow
        let host = destination.hostname.contains(":") ? "[\(destination.hostname)]" : destination.hostname
        var lines = ["CONNECT \(host):\(destination.port) HTTP/1.1", "X-Riot-Bundle-Id: \(source.bundleId)"]
        if let uid = source.uid { lines.append("X-Riot-Uid: \(uid)") }
        if let pid = source.pid { lines.append("X-Riot-Pid: \(pid)") }
        preface = Data((lines.joined(separator: "\r\n") + "\r\n\r\n").utf8)
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        connection = NWConnection(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: proxyPort) ?? 443,
                                  using: NWParameters(tls: nil, tcp: tcp))
    }

    func start() {
        connection.stateUpdateHandler = { [self] state in
            switch state {
            case .ready:
                connection.send(content: preface, completion: .contentProcessed { [self] error in
                    if let error { close(error) } else { readReply() }
                })
            case .failed(let error), .waiting(let error):
                close(error) // no proxy: the app sees a failed connection and retries
            default:
                break
            }
        }
        connection.start(queue: queue)
    }

    /// The proxy answers `HTTP/1.1 200 …` and a blank line before it relays anything.
    private func readReply() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [self] data, _, isComplete, error in
            guard let data, error == nil else { return close(error) }
            reply.append(data)
            guard let end = reply.range(of: Data("\r\n\r\n".utf8)) else {
                return isComplete || reply.count > 8192 ? close(nil) : readReply()
            }
            guard reply.starts(with: Data("HTTP/1.1 200".utf8)) else { return close(nil) }
            let rest = reply.subdata(in: end.upperBound..<reply.count)
            flow.open(withLocalEndpoint: nil) { [self] error in
                queue.async { [self] in
                    if let error { return close(error) }
                    pumpFromApp()
                    if rest.isEmpty { pumpToApp() } else { writeToApp(rest) }
                }
            }
        }
    }

    private func pumpFromApp() {
        flow.readData { [self] data, error in
            queue.async { [self] in
                guard let data, error == nil else { return close(error) }
                if data.isEmpty {
                    // The app is done sending; the answer may still be on its way.
                    connection.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .idempotent)
                    return
                }
                connection.send(content: data, completion: .contentProcessed { [self] error in
                    if let error { close(error) } else { pumpFromApp() }
                })
            }
        }
    }

    private func pumpToApp() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [self] data, _, isComplete, error in
            if let data, !data.isEmpty {
                writeToApp(data, thenClose: isComplete || error != nil)
            } else if isComplete || error != nil {
                close(error)
            } else {
                pumpToApp()
            }
        }
    }

    private func writeToApp(_ data: Data, thenClose: Bool = false) {
        flow.write(data) { [self] error in
            queue.async { [self] in
                if error != nil || thenClose { close(error) } else { pumpToApp() }
            }
        }
    }

    /// Called on `queue`.
    private func close(_ error: Error?) {
        guard !closed else { return }
        closed = true
        connection.cancel()
        flow.closeReadWithError(error)
        flow.closeWriteWithError(error)
    }
}
