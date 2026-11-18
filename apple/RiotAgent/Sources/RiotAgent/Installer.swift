import Foundation
import ServiceManagement
import SystemExtensions

/// First-run setup when installed by the MDM package in /Applications. Every step is
/// pre-approved by the MDM profile, so the user sees no prompt:
///   * daemon + per-user agent: SMAppService, approved by `com.apple.servicemanagement`
///     (Managed Login Items, rule on the team id);
///   * system extensions: OSSystemExtensionRequest, approved by `com.apple.system-extension-policy`:
///     ES (Full Disk Access from `com.apple.TCC.configuration-profile-policy`) and the network
///     extension (its transparent proxy configuration comes from `com.apple.vpn.managed`).
/// Development runs (outside /Applications) skip all of it.
@MainActor
final class Installer: NSObject, OSSystemExtensionRequestDelegate {
    /// The bundled system extensions, named after the app's bundle id; each is activated when
    /// its bundle ships in the app.
    static var extensionIdentifiers: [String] {
        let app = Bundle.main.bundleIdentifier ?? "com.tryriot.agent"
        return ["\(app).es", "\(app).network"]
    }

    static var isInstalledCopy: Bool { Bundle.main.bundlePath.hasPrefix("/Applications/") }

    func run() {
        guard Self.isInstalledCopy else { return }
        register(SMAppService.daemon(plistName: "com.tryriot.agent.daemon.plist"), "daemon")
        register(SMAppService.agent(plistName: "com.tryriot.agent.plist"), "agent")
        // Test fleets only: parrot's agent API, stubbed (WITH_STUB=1 build-app.sh).
        let stub = "com.tryriot.agent.stub-parrot.plist"
        if FileManager.default.fileExists(atPath: Bundle.main.bundleURL.appendingPathComponent("Contents/Library/LaunchDaemons/\(stub)").path) {
            register(SMAppService.daemon(plistName: stub), "stub parrot")
        }
        let sysext = Bundle.main.bundleURL.appendingPathComponent("Contents/Library/SystemExtensions")
        for identifier in Self.extensionIdentifiers
        where FileManager.default.fileExists(atPath: sysext.appendingPathComponent("\(identifier).systemextension").path) {
            let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: identifier, queue: .main)
            request.delegate = self
            OSSystemExtensionManager.shared.submitRequest(request)
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
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        NSLog("riot: %@ activation failed: %@", request.identifier, String(describing: error))
    }
}
