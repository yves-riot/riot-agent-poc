import Foundation
import NetworkExtension
import ServiceManagement
import SystemExtensions

/// First-run setup when installed by the MDM package in /Applications. Every step is
/// pre-approved by the MDM profile, so the user sees no prompt:
///   * daemon + per-user agent: SMAppService, approved by `com.apple.servicemanagement`
///     (Managed Login Items, rule on the team id);
///   * system extensions: OSSystemExtensionRequest, approved by
///     `com.apple.system-extension-policy`. The ES extension gets Full Disk Access from
///     `com.apple.TCC.configuration-profile-policy`; the network extension gets its transparent
///     proxy configuration from `com.apple.vpn.managed`.
/// Development runs (outside /Applications) skip all of it.
@MainActor
final class Installer: NSObject, OSSystemExtensionRequestDelegate {
    /// Whichever of these the app bundles is activated.
    nonisolated static let esExtension = "com.tryriot.agent.es"
    nonisolated static let netExtension = "com.tryriot.agent.net"

    static var isInstalledCopy: Bool { Bundle.main.bundlePath.hasPrefix("/Applications/") }

    func run() {
        guard Self.isInstalledCopy else { return }
        register(SMAppService.daemon(plistName: "com.tryriot.agent.daemon.plist"), "daemon")
        register(SMAppService.agent(plistName: "com.tryriot.agent.plist"), "agent")
        let bundled = Bundle.main.bundleURL.appendingPathComponent("Contents/Library/SystemExtensions")
        for identifier in [Self.esExtension, Self.netExtension] {
            guard FileManager.default.fileExists(atPath: bundled.appendingPathComponent("\(identifier).systemextension").path) else { continue }
            let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: identifier, queue: .main)
            request.delegate = self
            OSSystemExtensionManager.shared.submitRequest(request)
        }
    }

    /// Turns the network extension's proxy on. The MDM profile normally provides the
    /// configuration (the user then sees no "Allow" prompt); without one, the app creates it.
    private func startProxy() {
        NETransparentProxyManager.loadAllFromPreferences { managers, error in
            if let error {
                NSLog("riot: cannot read the proxy configurations: %@", String(describing: error))
                return
            }
            let ours = managers?.first {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == Self.netExtension
            }
            let manager = ours ?? NETransparentProxyManager()
            if ours == nil {
                let configuration = NETunnelProviderProtocol()
                configuration.providerBundleIdentifier = Self.netExtension
                configuration.serverAddress = "127.0.0.1" // required; the proxy is the local daemon
                manager.protocolConfiguration = configuration
                manager.localizedDescription = "Riot"
            }
            manager.isEnabled = true
            manager.saveToPreferences { error in
                if let error {
                    NSLog("riot: cannot save the proxy configuration: %@", String(describing: error))
                    return
                }
                // A saved configuration must be loaded again before it can be started.
                manager.loadFromPreferences { _ in
                    do {
                        try manager.connection.startVPNTunnel()
                    } catch {
                        NSLog("riot: cannot start the proxy: %@", String(describing: error))
                    }
                }
            }
        }
    }

    private func register(_ service: SMAppService, _ name: String) {
        guard service.status != .enabled else { return }
        do {
            try service.register()
        } catch {
            // `.requiresApproval` means the Managed Login Items payload is missing.
            NSLog("riot: cannot register %@ (status %d): %@", name, service.status.rawValue, String(describing: error))
        }
    }

    // MARK: OSSystemExtensionRequestDelegate

    nonisolated func request(_ request: OSSystemExtensionRequest,
                             actionForReplacingExtension existing: OSSystemExtensionProperties,
                             withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        .replace // updates ship inside the app; always take the bundled version
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        NSLog("riot: %@ awaits approval: the system-extension-policy payload is missing", request.identifier)
    }

    nonisolated func request(_ request: OSSystemExtensionRequest,
                             didFinishWithResult result: OSSystemExtensionRequest.Result) {
        NSLog("riot: %@ activation result %d", request.identifier, result.rawValue)
        if request.identifier == Self.netExtension, result == .completed {
            Task { @MainActor in self.startProxy() }
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        NSLog("riot: %@ activation failed: %@", request.identifier, String(describing: error))
    }
}
