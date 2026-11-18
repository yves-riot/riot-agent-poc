import AppKit
import SwiftUI

@main
struct RiotAgentApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate

    var body: some Scene {
        MenuBarExtra {
            MenuPopup().environmentObject(delegate.model)
        } label: {
            MenuBarIcon(model: delegate.model)
        }
        .menuBarExtraStyle(.window)
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let model = AppModel()
    private let installer = Installer()

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory) // menu bar only, no Dock icon
        if installer.run() {
            // launchd runs the menu bar app from now on (Installer.run).
            NSApp.terminate(nil)
            return
        }
        model.start()
    }
}

/// Observes the model so the icon follows the daemon connection.
private struct MenuBarIcon: View {
    @ObservedObject var model: AppModel
    var body: some View {
        Image(systemName: model.connected ? "shield.lefthalf.filled" : "shield.slash")
    }
}
