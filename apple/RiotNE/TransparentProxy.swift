import Foundation
import Network
import NetworkExtension

/// Sees every outbound TCP and UDP flow to port 443, and claims those of protected apps,
/// recognised by their signing team id (or their executable's folder for apps without one):
/// the same rule as RiotES, because a protected app's traffic may come from a process outside
/// its tree (Codex's app-server daemon is started by launchd).
///
/// A claimed TCP flow is handed to the daemon as a CONNECT on `flows.sock`; the daemon reads
/// the ClientHello and either decrypts it (an AI host of the policy) or tunnels it. A claimed
/// UDP flow is closed: QUIC fails and the app falls back to TCP. Flows of other processes are
/// left to the system untouched.
///
/// Fail-closed: while the daemon is unreachable, a protected app's TCP flow to an AI host of the
/// policy, or to an address whose name the system does not know, is refused rather than let out
/// unredacted; its other flows (telemetry, updates) go out as they are. The policy is the last
/// one the daemon gave, saved across restarts.
final class TransparentProxy: NETransparentProxyProvider, NEAppProxyUDPFlowHandling {
    private let policy = PolicyLink()
    private let identities = ProcessIdentities()

    override func startProxy(options: [String: Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
        policy.start()
        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        let anyV4 = Network.NWEndpoint.hostPort(host: "0.0.0.0", port: 443)
        let anyV6 = Network.NWEndpoint.hostPort(host: "::", port: 443)
        settings.includedNetworkRules = [
            NENetworkRule(destinationNetworkEndpoint: anyV4, prefix: 0, protocol: .TCP),
            NENetworkRule(destinationNetworkEndpoint: anyV6, prefix: 0, protocol: .TCP),
            NENetworkRule(destinationNetworkEndpoint: anyV4, prefix: 0, protocol: .UDP),
            NENetworkRule(destinationNetworkEndpoint: anyV6, prefix: 0, protocol: .UDP),
        ]
        setTunnelNetworkSettings(settings) { error in
            if let error { log.error("cannot apply network settings: \(String(describing: error), privacy: .public)") }
            completionHandler(error)
        }
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        log.notice("stopping (reason \(reason.rawValue, privacy: .public))")
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        let state = policy.state
        guard let tcp = flow as? NEAppProxyTCPFlow,
              let app = protectedApp(flow, state.policy),
              let target = Self.target(of: tcp) else { return false }
        guard state.daemonUp else {
            guard Self.mayReachAI(tcp, state.policy) else { return false }
            log.error("\(app, privacy: .public) → \(target, privacy: .public): refused, the daemon is unreachable")
            Self.refuse(flow)
            return true
        }
        log.notice("\(app, privacy: .public) → \(target, privacy: .public)")
        FlowRelay(flow: tcp, target: target, app: app, socket: PolicyLink.flowSocketPath).start()
        return true
    }

    func handleNewUDPFlow(_ flow: NEAppProxyUDPFlow, initialRemoteFlowEndpoint remoteEndpoint: Network.NWEndpoint) -> Bool {
        guard let app = protectedApp(flow, policy.state.policy) else { return false }
        // QUIC to port 443: refused, so that the app retries over TCP, which the daemon sees.
        let name = flow.remoteHostname.flatMap { $0.isEmpty ? nil : $0 } ?? "\(remoteEndpoint)"
        log.notice("\(app, privacy: .public) → \(name, privacy: .public) (UDP): refused, the app falls back to TCP")
        Self.refuse(flow)
        return true
    }

    /// Claimed, then closed: the app sees a connection that ends at once.
    private static func refuse(_ flow: NEAppProxyFlow) {
        flow.open(withLocalFlowEndpoint: nil) { _ in
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
        }
    }

    /// Whether the flow may carry a prompt: to an AI host, or to an address the system has no
    /// name for (only the ClientHello would tell, and nothing reads it without the daemon).
    private static func mayReachAI(_ flow: NEAppProxyTCPFlow, _ policy: Policy) -> Bool {
        guard let hostname = flow.remoteHostname, !hostname.isEmpty else { return true }
        return policy.isAIHost(hostname)
    }

    /// `bundleId (pid N)` of the protected app the flow's process belongs to.
    private func protectedApp(_ flow: NEAppProxyFlow, _ policy: Policy) -> String? {
        guard let token = flow.metaData.sourceAppAuditToken,
              let process = identities.identify(auditToken: token),
              let app = policy.app(teamId: process.teamId, executable: process.executable) else { return nil }
        return "\(app) (\(flow.metaData.sourceAppSigningIdentifier), pid \(process.pid))"
    }

    /// `host:port` for the CONNECT: the name the app asked for when the system knows it, else
    /// the address (the daemon then routes by the ClientHello's server name).
    private static func target(of flow: NEAppProxyTCPFlow) -> String? {
        guard case let .hostPort(host, port) = flow.remoteFlowEndpoint else { return nil }
        let name: String
        if let hostname = flow.remoteHostname, !hostname.isEmpty {
            name = hostname
        } else {
            switch host {
            case let .ipv4(address): name = "\(address)"
            case let .ipv6(address): name = "[\(address)]"
            case let .name(hostname, _): name = hostname
            @unknown default: return nil
            }
        }
        return "\(name):\(port.rawValue)"
    }
}
