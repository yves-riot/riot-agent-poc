# Testing file blocking in a VM

Endpoint Security needs Apple's `com.apple.developer.endpoint-security.client` entitlement. Until
it is granted, RiotES runs in a macOS VM with SIP off, as a plain root binary (not a system
extension): with SIP off, the entitlement is not enforced for it.

## The VM

[Tart](https://tart.run) (Fair Source license) runs macOS VMs on Apple silicon:

```sh
brew install cirruslabs/cli/tart
tart clone ghcr.io/cirruslabs/macos-tahoe-base:latest riot-es   # macOS 26, user admin / admin
tart set riot-es --memory 6144                                   # 8 GB swaps on a 24 GB Mac
tart run --recovery riot-es        # Utilities > Terminal: csrutil disable, then restart
tart run riot-es
tart exec riot-es csrutil status   # disabled
```

`tart exec` runs commands in the VM through its guest agent, and `tart exec -i` pipes stdin, which
is enough to copy files in with `tar`. Plain text is shared between the host and VM clipboards.

If the VM has no network, look for a host route over `192.168.64.0/24` that does not go through
the VM's bridge: Tailscale installed one here (`netstat -rn -f inet | grep 192.168.64`). Turn the
VPN off, then restart the VM so its bridge gets its route back.

## Riot in the VM

```sh
apple/build-app.sh                       # Riot.app
cd apple && xcode=/Applications/Xcode.app/Contents/Developer
sdk=$(DEVELOPER_DIR=$xcode xcrun --sdk macosx --show-sdk-path)
DEVELOPER_DIR=$xcode swiftc -O -sdk "$sdk" -target arm64-apple-macos14.0 -swift-version 5 \
  -lEndpointSecurity -lbsm RiotES/*.swift \
  RiotAgent/Sources/RiotAgent/DaemonClient.swift RiotAgent/Sources/RiotAgent/Models.swift \
  -o build/es/riot-es
codesign --force --sign - --entitlements RiotES/RiotES.entitlements build/es/riot-es
cd ..
tar -czf - -C core/target/release riot-daemon riotctl riot-stub-parrot -C ../../../apple/build/es riot-es \
  -C ../../../dev settings.json -C ../apple/build Riot.app \
  | tart exec -i riot-es sh -c 'mkdir -p ~/riot && tar -C ~/riot -xzf -'
```

In the VM, the stub, the daemon and RiotES as root on the
default socket, then the app:

```sh
cd ~/riot
nohup ./riot-stub-parrot 8787 --dev > stub.log 2>&1 &
sudo env RIOT_SETTINGS=$HOME/riot/settings.json RIOT_DATA_DIR=/var/tmp/riot-data \
  nohup ./riot-daemon > daemon.log 2>&1 &
sudo env RIOT_DEBUG=1 nohup ./riot-es > es.log 2>&1 &
open Riot.app
```

`RIOT_DEBUG=1` logs each protected process and each judged open (app, executable, file name,
flags, verdict, time). `sudo eslogger open` shows every open on the machine, with the process
that made it: the way to find which process of an app actually reads a file.

## Checks

- A protected app (or a copy of `/bin/sh` under its `executable_prefixes`, for an app that is
  not installed) opens a document with detections: `Operation not permitted`, a `fileBlocked`
  event (`riotctl popup`), the card in Riot.app. A clean document opens.
- A child and a grandchild of that app (`sh -c 'cat …'`) are denied the same way; the same `cat`
  outside the app is not.
- `riotctl bypass <eventId>`: the file opens for 60 s, until it is modified.
- Claude Desktop: Chat mode reads attachments itself; Code mode hands the path to Claude Code
  (`~/Library/Application Support/Claude/claude-code/…/claude`), which reads it when asked.
- Fixtures from the conformance corpus (`sonar-detection/conformance/fixtures`) cover pdf, docx,
  xlsx and an unreadable docx (denied: an error is not known to be clean).
