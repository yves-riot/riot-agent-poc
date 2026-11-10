import Foundation

// RiotES.systemextension: activated by Riot.app (OSSystemExtensionRequest), approved and
// granted Full Disk Access by the MDM profile (mdm/riot-agent.mobileconfig). Runs as root.

let guardian = ESGuard(daemon: DaemonLink())
do {
    try guardian.start()
    NSLog("riot-es: started")
} catch {
    // Missing entitlement, no Full Disk Access, or not approved: the system logs the reason.
    NSLog("riot-es: cannot start: %@", String(describing: error))
    exit(EXIT_FAILURE)
}
dispatchMain()
