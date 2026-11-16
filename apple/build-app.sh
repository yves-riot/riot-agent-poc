#!/bin/sh
# Assembles apple/build/Riot.app: the SwiftUI menu bar app, the Rust daemon, the extension's
# locale files and the launchd plists SMAppService registers.
#   SIGN_IDENTITY="Developer ID Application: …" apple/build-app.sh   (default: ad-hoc, local runs only)
# The system extensions are bundled on request, each needing a real identity and a provisioning
# profile with its entitlement:
#   WITH_ES=1  ES_PROVISIONING_PROFILE=…                                    (Endpoint Security)
#   WITH_NET=1 TEAM_ID=… NET_PROVISIONING_PROFILE=… APP_PROVISIONING_PROFILE=…   (network extension)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
packages=${SONAR_PACKAGES_DIR:-$HOME/dev/riot/riot-browser-extension-pkgs/packages}
# Xcode (SwiftUI macros) for the Swift steps only. Cargo must see the same environment as
# `dev/run-dev.sh` and `cargo test`: the C crates (aws-lc-sys, rquickjs-sys) rebuild, with
# everything above them, whenever DEVELOPER_DIR changes (about 5 min).
xcode=${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}
app="$here/build/Riot.app"

(cd "$root/js" && node build.mjs >/dev/null)
(cd "$root/core" && cargo build --release -q -p riot-daemon)
(cd "$here/RiotAgent" && DEVELOPER_DIR="$xcode" swift build -c release -q)

rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources/locales" \
         "$app/Contents/Library/LaunchDaemons" "$app/Contents/Library/LaunchAgents"
cp "$here/Packaging/Info.plist" "$app/Contents/Info.plist"
cp "$here/RiotAgent/.build/release/RiotAgent" "$app/Contents/MacOS/RiotAgent"
cp "$root/core/target/release/riot-daemon" "$app/Contents/MacOS/riot-daemon"
cp "$root/core/target/release/riotctl" "$app/Contents/MacOS/riotctl"
cp "$packages/sonar-ui/src/locales/en.json" "$packages/sonar-ui/src/locales/fr.json" "$app/Contents/Resources/locales/"
cp "$here/Packaging/com.tryriot.agent.daemon.plist" "$app/Contents/Library/LaunchDaemons/"
cp "$here/Packaging/com.tryriot.agent.plist" "$app/Contents/Library/LaunchAgents/"

identity=${SIGN_IDENTITY:--}

# The ES system extension needs Apple's endpoint-security entitlement and a provisioning
# profile: only bundled when asked (WITH_ES=1), i.e. with a real Developer ID identity.
if [ "${WITH_ES:-0}" = 1 ]; then
  sysext="$app/Contents/Library/SystemExtensions/com.tryriot.agent.es.systemextension"
  mkdir -p "$sysext/Contents/MacOS"
  cp "$here/RiotES/Info.plist" "$sysext/Contents/Info.plist"
  sdk=$(DEVELOPER_DIR="$xcode" xcrun --sdk macosx --show-sdk-path)
  DEVELOPER_DIR="$xcode" swiftc -O -sdk "$sdk" -target arm64-apple-macos14.0 -swift-version 5 -lEndpointSecurity -lbsm \
    "$here/RiotES/main.swift" "$here/RiotES/ESGuard.swift" "$here/RiotES/DaemonLink.swift" \
    "$here/RiotAgent/Sources/RiotAgent/DaemonClient.swift" "$here/RiotAgent/Sources/RiotAgent/Models.swift" \
    -o "$sysext/Contents/MacOS/com.tryriot.agent.es"
  [ -n "${ES_PROVISIONING_PROFILE:-}" ] && cp "$ES_PROVISIONING_PROFILE" "$sysext/Contents/embedded.provisionprofile"
  codesign --force --options runtime --sign "$identity" --entitlements "$here/RiotES/RiotES.entitlements" "$sysext"
fi

# The network extension relays the protected apps' HTTPS to the daemon's proxy. Its entitlement
# comes with the Network Extensions capability of a provisioning profile (no request to Apple);
# the app that activates it needs one too.
app_entitlements=
if [ "${WITH_NET:-0}" = 1 ]; then
  : "${TEAM_ID:?WITH_NET=1 needs TEAM_ID (the app group and the Mach service name carry it)}"
  sysext="$app/Contents/Library/SystemExtensions/com.tryriot.agent.net.systemextension"
  mkdir -p "$sysext/Contents/MacOS"
  sed "s/__TEAM_ID__/$TEAM_ID/g" "$here/RiotNet/Info.plist" > "$sysext/Contents/Info.plist"
  sed "s/__TEAM_ID__/$TEAM_ID/g" "$here/RiotNet/RiotNet.entitlements" > "$here/build/RiotNet.entitlements"
  sed "s/__TEAM_ID__/$TEAM_ID/g" "$here/Packaging/Riot.entitlements" > "$here/build/Riot.entitlements"
  sdk=$(DEVELOPER_DIR="$xcode" xcrun --sdk macosx --show-sdk-path)
  DEVELOPER_DIR="$xcode" swiftc -O -sdk "$sdk" -target arm64-apple-macos14.0 -swift-version 5 -lbsm \
    "$here/RiotNet/main.swift" "$here/RiotNet/TransparentProxy.swift" "$here/RiotNet/NetLink.swift" \
    "$here/RiotAgent/Sources/RiotAgent/DaemonClient.swift" "$here/RiotAgent/Sources/RiotAgent/Models.swift" \
    -o "$sysext/Contents/MacOS/com.tryriot.agent.net"
  [ -n "${NET_PROVISIONING_PROFILE:-}" ] && cp "$NET_PROVISIONING_PROFILE" "$sysext/Contents/embedded.provisionprofile"
  [ -n "${APP_PROVISIONING_PROFILE:-}" ] && cp "$APP_PROVISIONING_PROFILE" "$app/Contents/embedded.provisionprofile"
  codesign --force --options runtime --sign "$identity" --entitlements "$here/build/RiotNet.entitlements" "$sysext"
  app_entitlements="$here/build/Riot.entitlements"
fi
for bin in riot-daemon riotctl; do
  codesign --force --options runtime --sign "$identity" --identifier "com.tryriot.agent.$bin" "$app/Contents/MacOS/$bin"
done
if [ -n "$app_entitlements" ]; then
  codesign --force --options runtime --sign "$identity" --entitlements "$app_entitlements" "$app"
else
  codesign --force --options runtime --sign "$identity" "$app"
fi
du -sh "$app" | awk '{print "built " $2 " (" $1 ")"}'
