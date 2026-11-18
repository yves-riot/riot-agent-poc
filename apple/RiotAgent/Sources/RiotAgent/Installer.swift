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

    /// Whether this copy was started by launchd as the per-user agent, rather than opened (by
    /// the package's postinstall, or by the user).
    static var isLaunchAgent: Bool { ProcessInfo.processInfo.environment["XPC_SERVICE_NAME"] == "com.tryriot.agent" }

    /// Registers and activates everything. Returns whether this copy should quit: an opened copy
    /// (the package's postinstall, the user) leaves the menu bar to launchd's once the agent is
    /// registered, and starts it if it is not running (a copy that quit is not restarted), so
    /// that one icon shows. launchd's copy activates the system extensions.
    func run() -> Bool {
        guard Self.isInstalledCopy else { return false }
        register(SMAppService.daemon(plistName: "com.tryriot.agent.daemon.plist"), "daemon")
        let agent = SMAppService.agent(plistName: "com.tryriot.agent.plist")
        register(agent, "agent")
        // Test fleets only: parrot's agent API, stubbed (WITH_STUB=1 build-app.sh).
        let stub = "com.tryriot.agent.stub-parrot.plist"
        if FileManager.default.fileExists(atPath: Bundle.main.bundleURL.appendingPathComponent("Contents/Library/LaunchDaemons/\(stub)").path) {
            register(SMAppService.daemon(plistName: stub), "stub parrot")
        }
        if agent.status == .enabled && !Self.isLaunchAgent {
            Self.startLaunchAgent()
            return true
        }
        let sysext = Bundle.main.bundleURL.appendingPathComponent("Contents/Library/SystemExtensions")
        for identifier in Self.extensionIdentifiers
        where FileManager.default.fileExists(atPath: sysext.appendingPathComponent("\(identifier).systemextension").path) {
            let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: identifier, queue: .main)
            request.delegate = self
            OSSystemExtensionManager.shared.submitRequest(request)
        }
        return false
    }

    /// Starts launchd's copy, unless it runs already.
    private static func startLaunchAgent() {
        let launchctl = Process()
        launchctl.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        launchctl.arguments = ["kickstart", "gui/\(getuid())/com.tryriot.agent"]
        do {
            try launchctl.run()
            launchctl.waitUntilExit()
        } catch {
            NSLog("riot: cannot start the menu bar agent: %@", String(describing: error))
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
