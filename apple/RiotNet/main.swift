import Foundation
import NetworkExtension

// RiotNet.systemextension: activated by Riot.app (OSSystemExtensionRequest), approved and
// configured by the MDM profile (mdm/riot-agent.mobileconfig). Runs as root. The system
// instantiates `TransparentProxy` (Info.plist, NEProviderClasses) when the proxy starts.

autoreleasepool {
    NEProvider.startSystemExtensionMode()
}
dispatchMain()
