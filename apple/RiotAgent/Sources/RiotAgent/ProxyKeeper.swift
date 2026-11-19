import Foundation
import NetworkExtension

/// Keeps the MDM's transparent proxy running. The profile asks for it on demand
/// (`OnDemandEnabled`, one `Connect` rule), but on a Mac enrolled in Iru (macOS 27.2) the saved
/// configuration has `OnDemandEnabled` false: the session stays idle, and System Settings does
/// not let the user start a managed proxy. The app that contains the provider can start it, so
/// launchd's copy does, and again whenever it stops (replacing the extension stops it).
@MainActor
final class ProxyKeeper {
    private let providerIdentifier: String
    private var manager: NETransparentProxyManager?
    private var observer: NSObjectProtocol?
    /// Starts since the proxy last connected: each waits twice as long as the one before.
    private var attempts = 0
    private var pending = false

    init(providerIdentifier: String) {
        self.providerIdentifier = providerIdentifier
    }

    func start() {
        NETransparentProxyManager.loadAllFromPreferences { managers, error in
            DispatchQueue.main.async { self.loaded(managers ?? [], error) }
        }
    }

    private func loaded(_ managers: [NETransparentProxyManager], _ error: Error?) {
        if let error {
            NSLog("riot: cannot load the transparent proxy configuration: %@", String(describing: error))
            return
        }
        guard let manager = managers.first(where: {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == providerIdentifier
        }) else {
            NSLog("riot: no transparent proxy configuration for %@ (the profile's com.apple.vpn.managed payload)", providerIdentifier)
            return
        }
        if let observer { NotificationCenter.default.removeObserver(observer) }
        self.manager = manager
        observer = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: manager.connection, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.statusChanged() }
        }
        statusChanged()
    }

    private func statusChanged() {
        guard let manager else { return }
        switch manager.connection.status {
        case .connected:
            attempts = 0
        case .disconnected:
            scheduleStart()
        default:
            break // connecting, reasserting, disconnecting: wait for the next change; invalid: nothing to start
        }
    }

    private func scheduleStart() {
        guard !pending else { return }
        pending = true
        let delay = attempts == 0 ? 0 : min(60, pow(2, Double(attempts)))
        attempts += 1
        DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
            self.pending = false
            guard let manager = self.manager, manager.connection.status == .disconnected else { return }
            guard manager.isEnabled else {
                NSLog("riot: the transparent proxy configuration is disabled; not starting it")
                return
            }
            do {
                try manager.connection.startVPNTunnel()
                NSLog("riot: starting the transparent proxy (attempt %d)", self.attempts)
            } catch {
                NSLog("riot: cannot start the transparent proxy: %@", String(describing: error))
                self.scheduleStart()
            }
        }
    }
}
