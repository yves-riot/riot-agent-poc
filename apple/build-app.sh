#!/bin/sh
# Assembles apple/build/Riot.app: the SwiftUI menu bar app, the Rust daemon, the extension's
# locale files and the launchd plists SMAppService registers.
#   SIGN_IDENTITY="Developer ID Application: …" apple/build-app.sh   (default: ad-hoc, local runs only)
# APP_ID (default com.tryriot.agent) changes the app's bundle id and the network extension's
# (APP_ID.network), for builds signed with another team's provisioning profiles.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
packages=${SONAR_PACKAGES_DIR:-$HOME/dev/riot/riot-browser-extension/packages}
# Xcode (SwiftUI macros) for the Swift steps only. Cargo must see the same environment as
# `dev/run-dev.sh` and `cargo test`: the C crates (aws-lc-sys, rquickjs-sys) rebuild, with
# everything above them, whenever DEVELOPER_DIR changes (about 5 min).
xcode=${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}
app="$here/build/Riot.app"
app_id=${APP_ID:-com.tryriot.agent}

(cd "$root/js" && node build.mjs >/dev/null)
(cd "$root/core" && cargo build --release -q -p riot-daemon)
(cd "$here/RiotAgent" && DEVELOPER_DIR="$xcode" swift build -c release -q)

rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources/locales" \
         "$app/Contents/Library/LaunchDaemons" "$app/Contents/Library/LaunchAgents"
cp "$here/Packaging/Info.plist" "$app/Contents/Info.plist"
plutil -replace CFBundleIdentifier -string "$app_id" "$app/Contents/Info.plist"
# The build an MDM compares with the one it deploys (mdm/iru-audit.sh).
plutil -replace CFBundleVersion -string "${BUILD_NUMBER:-1}" "$app/Contents/Info.plist"
cp "$here/RiotAgent/.build/release/RiotAgent" "$app/Contents/MacOS/RiotAgent"
cp "$root/core/target/release/riot-daemon" "$app/Contents/MacOS/riot-daemon"
cp "$root/core/target/release/riotctl" "$app/Contents/MacOS/riotctl"
cp "$packages/sonar-ui/src/locales/en.json" "$packages/sonar-ui/src/locales/fr.json" "$app/Contents/Resources/locales/"
cp "$here/Packaging/com.tryriot.agent.daemon.plist" "$app/Contents/Library/LaunchDaemons/"
cp "$here/Packaging/com.tryriot.agent.plist" "$app/Contents/Library/LaunchAgents/"
bins="riot-daemon riotctl"
# A test fleet without parrot's agent API (WITH_STUB=1): its stub runs next to the daemon.
if [ "${WITH_STUB:-0}" = 1 ]; then
  cp "$root/core/target/release/riot-stub-parrot" "$app/Contents/MacOS/riot-stub-parrot"
  cp "$here/Packaging/com.tryriot.agent.stub-parrot.plist" "$app/Contents/Library/LaunchDaemons/"
  bins="$bins riot-stub-parrot"
fi
for plist in "$app"/Contents/Library/LaunchDaemons/*.plist "$app"/Contents/Library/LaunchAgents/*.plist; do
  plutil -replace AssociatedBundleIdentifiers -json "[\"$app_id\"]" "$plist"
done

identity=${SIGN_IDENTITY:--}

# The ES system extension needs Apple's endpoint-security entitlement and a provisioning
# profile: only bundled when asked (WITH_ES=1), i.e. with a real Developer ID identity.
if [ "${WITH_ES:-0}" = 1 ]; then
  sysext="$app/Contents/Library/SystemExtensions/com.tryriot.agent.es.systemextension"
  mkdir -p "$sysext/Contents/MacOS"
  cp "$here/RiotES/Info.plist" "$sysext/Contents/Info.plist"
  plutil -replace CFBundleVersion -string "${BUILD_NUMBER:-1}" "$sysext/Contents/Info.plist"
  sdk=$(DEVELOPER_DIR="$xcode" xcrun --sdk macosx --show-sdk-path)
  DEVELOPER_DIR="$xcode" swiftc -O -sdk "$sdk" -target arm64-apple-macos14.0 -swift-version 5 -lEndpointSecurity -lbsm \
    "$here/RiotES/main.swift" "$here/RiotES/ESGuard.swift" "$here/RiotES/DaemonLink.swift" \
    "$here/RiotAgent/Sources/RiotAgent/DaemonClient.swift" "$here/RiotAgent/Sources/RiotAgent/Models.swift" \
    -o "$sysext/Contents/MacOS/com.tryriot.agent.es"
  [ -n "${ES_PROVISIONING_PROFILE:-}" ] && cp "$ES_PROVISIONING_PROFILE" "$sysext/Contents/embedded.provisionprofile"
  codesign --force --options runtime --sign "$identity" --entitlements "$here/RiotES/RiotES.entitlements" "$sysext"
fi
# The network extension (transparent proxy) needs the Network Extensions capability in a
# Developer ID provisioning profile (NE_PROVISIONING_PROFILE) and Riot's team id (TEAM_ID):
# only bundled when asked (WITH_NE=1).
if [ "${WITH_NE:-0}" = 1 ]; then
  : "${TEAM_ID:?WITH_NE=1 needs TEAM_ID}"
  sysext="$app/Contents/Library/SystemExtensions/$app_id.network.systemextension"
  mkdir -p "$sysext/Contents/MacOS"
  sed -e "s/__TEAM_ID__/$TEAM_ID/g" -e "s/__APP_ID__/$app_id/g" "$here/RiotNE/Info.plist" > "$sysext/Contents/Info.plist"
  # macOS keeps an installed extension whose version did not change: bump BUILD_NUMBER to replace it.
  plutil -replace CFBundleVersion -string "${BUILD_NUMBER:-1}" "$sysext/Contents/Info.plist"
  sed -e "s/__TEAM_ID__/$TEAM_ID/g" -e "s/__APP_ID__/$app_id/g" "$here/RiotNE/RiotNE.entitlements" > "$here/build/RiotNE.entitlements"
  sdk=$(DEVELOPER_DIR="$xcode" xcrun --sdk macosx --show-sdk-path)
  DEVELOPER_DIR="$xcode" swiftc -O -sdk "$sdk" -target arm64-apple-macos15.0 -swift-version 5 -module-name RiotNE -lbsm \
    "$here"/RiotNE/*.swift \
    "$here/RiotAgent/Sources/RiotAgent/DaemonClient.swift" "$here/RiotAgent/Sources/RiotAgent/Models.swift" \
    -o "$sysext/Contents/MacOS/$app_id.network"
  [ -n "${NE_PROVISIONING_PROFILE:-}" ] && cp "$NE_PROVISIONING_PROFILE" "$sysext/Contents/embedded.provisionprofile"
  codesign --force --options runtime --sign "$identity" --entitlements "$here/build/RiotNE.entitlements" "$sysext"
fi
for bin in $bins; do
  codesign --force --options runtime --sign "$identity" --identifier "com.tryriot.agent.$bin" "$app/Contents/MacOS/$bin"
done
# Activating a system extension takes an entitlement that comes with the app's provisioning
# profile (APP_PROVISIONING_PROFILE, with the System Extension capability).
if [ -d "$app/Contents/Library/SystemExtensions" ]; then
  [ -n "${APP_PROVISIONING_PROFILE:-}" ] && cp "$APP_PROVISIONING_PROFILE" "$app/Contents/embedded.provisionprofile"
  : "${TEAM_ID:?bundling a system extension needs TEAM_ID}"
  sed -e "s/__TEAM_ID__/$TEAM_ID/g" -e "s/__APP_ID__/$app_id/g" "$here/Packaging/Riot.entitlements" > "$here/build/Riot.entitlements"
  codesign --force --options runtime --sign "$identity" --entitlements "$here/build/Riot.entitlements" "$app"
else
  codesign --force --options runtime --sign "$identity" "$app"
fi
du -sh "$app" | awk '{print "built " $2 " (" $1 ")"}'
