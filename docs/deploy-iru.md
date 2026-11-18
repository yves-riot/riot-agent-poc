# Deploying to a test fleet with Iru

Riot.app on Macs managed by Iru, signed with a Developer ID team of our own, without parrot's
agent API: each Mac runs a stub of it next to the daemon. What it brings: the network
extension, which redacts Claude Desktop, the ChatGPT app, Claude Code and Codex; the clipboard
guard. Not the file blocking: the ES extension needs Apple's entitlement.

## What gets deployed

- **A configuration profile** (`mdm/riot-agent.mobileconfig`, rendered): pre-approves the
  network extension, the daemons (Managed Login Items), Full Disk Access for the daemon,
  sending keys for the menu bar app; sets the transparent proxy; trusts the fleet CA; gives the
  daemon its settings (the stub's URL, workspace and secret).
- **A package** (`Riot-<version>.pkg`): Riot.app in `/Applications` (the menu bar app, the daemon,
  the stub, the network extension) and the fleet CA's key in
  `/Library/Application Support/com.tryriot.agent` (root, `0600`). Its postinstall starts the app
  in the user's session; the app registers the daemon, the stub and itself as a login item, and
  activates the network extension.

### The fleet CA

The daemon terminates the AI hosts' TLS with a CA. On a developer's Mac each daemon creates its
own, trusted by hand; a profile cannot trust a CA it does not know in advance. A test fleet
shares one: its certificate in the profile, its key in the package. Whoever gets the key, or
the package, can read the AI traffic of every Mac of the fleet: keep both out of the repository
and out of shared drives. The CA can only issue for the AI domains (name constraints), and
lasts a year. Production: see "To decide: the CA in production" in
[network-interception.md](network-interception.md).

### The stub

`riot-stub-parrot` (`core/riot-daemon/src/bin/stub_parrot.rs`), on `127.0.0.1:7592`, as
`nobody`: enrolls the daemon, gives it the policy of `dev/stub-policy.json` (the same as
`dev/stub-parrot.mjs`), takes its heartbeats and reports and keeps nothing. Reports stay on the
Mac. The popup greets the user by the local part of the email Iru substitutes for `$EMAIL`.

## Build

Once, the CA, in a folder outside the repository:

```sh
mdm/fleet-ca.sh ~/riot/fleet-ca
```

Then the package, with the team's identity and provisioning profiles (an app id whose profiles
carry the System Extension and Network Extensions capabilities; a bundle id other than
`com.tryriot.agent` takes `APP_ID`). Build it in a shell that does not mark the files it writes
(`com.apple.provenance` turns into `._*` entries in the package; they do no harm, the installer
folds them back into attributes). Raise `BUILD_NUMBER` with every release: macOS keeps an
installed network extension whose version did not change.

```sh
SIGN_IDENTITY="Developer ID Application: … (TEAMID)" TEAM_ID=TEAMID APP_ID=… \
WITH_NE=1 NE_PROVISIONING_PROFILE=… APP_PROVISIONING_PROFILE=… BUILD_NUMBER=… \
WITH_STUB=1 FLEET_CA_DIR=~/riot/fleet-ca NOTARY_PROFILE=riot apple/build-pkg.sh
```

`NOTARY_PROFILE` notarizes Riot.app, then staples it, before packaging it: on a Mac with SIP on,
sysextd checks the network extension with the notary service and uninstalls it when it is not
notarized (`extension failed to validate! uninstalling...`). The credentials are stored once:
`xcrun notarytool store-credentials riot --apple-id … --team-id TEAMID`, with an app-specific
password of the team's Apple Account.

And the profile:

```sh
TEAM_ID=TEAMID APP_ID=… API_URL=http://127.0.0.1:7592/portal WORKSPACE_ID=ws-dev \
ENROLLMENT_SECRET=rbx_dev CA_CERT=~/riot/fleet-ca/gateway-ca.pem \
mdm/render-profile.sh > riot-agent-fleet.mobileconfig
```

The package itself is signed only if `INSTALLER_IDENTITY` names a Developer ID Installer
identity: Iru installs it with its agent, as root, without asking Gatekeeper.

## In Iru

1. **The profile** as a custom profile in the Library, assigned to the test Macs' blueprint.
   Iru signs it. `$EMAIL` is Iru's variable for the user's email.
2. **Check it on a Mac** before the package: System Settings › Privacy & Security › Profiles,
   "Riot Agent". Installed after the profile, the package finds every step pre-approved;
   installed before, the user sees prompts for the background items and the extension.
3. **The package** as a custom app, assigned to the same blueprint.

Updates: a new package (higher `BUILD_NUMBER`) in the same custom app. The postinstall restarts
the app, the daemon and the stub on the new binaries; the app replaces the network extension.

## Checking a Mac

```sh
/Applications/Riot.app/Contents/MacOS/riotctl status   # "monitoring": true, "lastError": null
systemextensionsctl list                               # the network extension, [activated enabled]
sudo tail /Library/Logs/Riot/daemon.log                # "device enrolled", "gateway redaction"
log stream --predicate 'subsystem == "<APP_ID>.network"'   # flows claimed by the extension
```

In Claude Desktop, a new conversation: "My email is jean.dupont@acme.fr. Spell my email letter by
letter, separated by dashes." Claude only saw a token, and spells `[-E-M-A-I-L-_-1-]`; the user
sees the email everywhere else.

## Measured (macOS 26 VM, not enrolled in an MDM)

With the payloads that need an MDM replaced by hand (background items approved in System
Settings, the managed settings written to `/Library/Managed Preferences`, which macOS empties at every
startup when no profile holds them, the CA trusted with
`security add-trusted-cert`): `installer -pkg` installed Riot.app with a valid signature and the
CA's key; the app registered the daemon and the stub and replaced the network extension (not notarized: the VM runs with SIP off); the
daemon enrolled with the stub and got the policy. Claude Desktop's message was redacted with the
fleet CA (the spelling test above). Installed again over itself, the package restarted all three
on the new binaries; the daemon enrolled again with the restarted stub.

## Measured (MacBook, macOS 27.2, enrolled in Iru)

The profile, scoped by a tag, installed every payload (`Source: MDM`, `Removal Disallowed`); Iru
substituted `$EMAIL`. The package, not notarized: Iru installed it, the daemon and the stub ran
without a prompt and the daemon got the policy, but sysextd uninstalled the network extension,
not notarized. The postinstall's copy of the app and launchd's both stayed, two icons in the
menu bar. Notarized, the extension was activated without a prompt.

An opened copy of the app now starts launchd's (`launchctl kickstart`) and quits: launchd does
not restart a copy that exited with status 0, which a stopped app does. In the VM, after an
update, one copy ran, launchd's, and the new extension replaced the old one.

## Limits

- **Nobody logged in** when Iru installs the package (a Mac being set up): the postinstall does
  not start the app, and nothing does until the user opens it once.
- **An update restarts the daemon**, which loses its tokens: conversations from before show
  tokens where they showed values (see the Connect RPC limits in network-interception.md).
- **Developing on a Mac of the fleet**: `dev/run-dev.sh` pauses the installed agent for its run
  (`sudo riotctl pause <its pid>`: the agent resumes once the script is gone, however it ends), its gateway on 7601 (the agent's daemon
  holds 7591). Paused, the agent applies no policy: no clipboard guard, the network extension
  takes no flow. A pause lasts until `resume` or the daemon's next start (a restart, an update),
  and the heartbeat reports it. Stopping the agent's daemon instead would leave the protected
  apps without their API hosts: the network extension refuses their flows while the daemon is
  down.
- **Removing** the agent: unassign the custom app and the profile, then delete `/Applications/Riot.app`
  and `/Library/Application Support/com.tryriot.agent`. The profile keeps the extension from being
  removed by the user, not by the MDM.
