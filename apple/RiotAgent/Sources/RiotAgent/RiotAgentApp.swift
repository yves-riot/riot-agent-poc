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

/// Observes the model so the icon follows the daemon connection. A development copy (run from
/// outside /Applications) says so, to tell it from an installed agent's icon next to it.
private struct MenuBarIcon: View {
    @ObservedObject var model: AppModel
    var body: some View {
        let icon = Image(systemName: model.connected ? "shield.lefthalf.filled" : "shield.slash")
        if Installer.isInstalledCopy {
            icon
        } else {
            HStack(spacing: 2) {
                icon
                Text("DEV").font(.system(size: 9, weight: .bold))
            }
        }
    }
}
