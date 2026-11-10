import Foundation
import ServiceManagement
import SystemExtensions

/// First-run setup when installed by the MDM package in /Applications. Every step is
/// pre-approved by the MDM profile, so the user sees no prompt:
///   * daemon + per-user agent: SMAppService, approved by `com.apple.servicemanagement`
///     (Managed Login Items, rule on the team id);
///   * ES extension: OSSystemExtensionRequest, approved by `com.apple.system-extension-policy`,
///     with Full Disk Access from `com.apple.TCC.configuration-profile-policy`.
/// Development runs (outside /Applications) skip all of it.
@MainActor
final class Installer: NSObject, OSSystemExtensionRequestDelegate {
    static let extensionIdentifier = "com.tryriot.agent.es"

    static var isInstalledCopy: Bool { Bundle.main.bundlePath.hasPrefix("/Applications/") }

    func run() {
        guard Self.isInstalledCopy else { return }
        register(SMAppService.daemon(plistName: "com.tryriot.agent.daemon.plist"), "daemon")
        register(SMAppService.agent(plistName: "com.tryriot.agent.plist"), "agent")
        let sysext = Bundle.main.bundleURL.appendingPathComponent("Contents/Library/SystemExtensions")
        if FileManager.default.fileExists(atPath: sysext.path) {
            let request = OSSystemExtensionRequest.activationRequest(
                forExtensionWithIdentifier: Self.extensionIdentifier, queue: .main)
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
        NSLog("riot: ES extension awaits approval: the system-extension-policy payload is missing")
    }

    nonisolated func request(_ request: OSSystemExtensionRequest,
                             didFinishWithResult result: OSSystemExtensionRequest.Result) {
        NSLog("riot: ES extension activation result %d", result.rawValue)
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        NSLog("riot: ES extension activation failed: %@", String(describing: error))
    }
}
