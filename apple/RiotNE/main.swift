import Foundation
import NetworkExtension

// RiotNE.systemextension: a transparent proxy (NETransparentProxyProvider). Activated by
// Riot.app (OSSystemExtensionRequest); its configuration comes from the MDM profile
// (`com.apple.vpn.managed`, VPNType TransparentProxy). Runs as root.

autoreleasepool {
    NEProvider.startSystemExtensionMode()
}
dispatchMain()
