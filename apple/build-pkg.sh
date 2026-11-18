#!/bin/sh
# Builds apple/build/Riot-<version>.pkg, the package an MDM deploys (after the profile).
#   SIGN_IDENTITY="Developer ID Application: …" INSTALLER_IDENTITY="Developer ID Installer: …" \
#   WITH_ES=1 ES_PROVISIONING_PROFILE=… apple/build-pkg.sh
# (the variables of build-app.sh). FLEET_CA_DIR (mdm/fleet-ca.sh) installs a CA every Mac shares,
# which the profile trusts; without it, each daemon creates its own, which nothing trusts.
# Then notarize: xcrun notarytool submit build/Riot-*.pkg --keychain-profile riot --wait
#                xcrun stapler staple build/Riot-*.pkg
set -eu
here=$(cd "$(dirname "$0")" && pwd)
"$here/build-app.sh"
version=$(defaults read "$here/build/Riot.app/Contents/Info" CFBundleShortVersionString)
root="$here/build/pkgroot"
rm -rf "$root" && mkdir -p "$root/Applications"
ditto --noextattr --noqtn "$here/build/Riot.app" "$root/Applications/Riot.app"
if [ -n "${FLEET_CA_DIR:-}" ]; then
  data="$root/Library/Application Support/com.tryriot.agent"
  mkdir -p "$data"
  install -m 0644 "$FLEET_CA_DIR/gateway-ca.pem" "$data/gateway-ca.pem"
  install -m 0600 "$FLEET_CA_DIR/gateway-ca-key.pem" "$data/gateway-ca-key.pem"
fi
export COPYFILE_DISABLE=1
# Installed where the package says, never "relocated" onto another copy of the app the
# installer finds elsewhere on the Mac (a build folder, a download).
components="$here/build/components.plist"
pkgbuild --analyze --root "$root" "$components"
i=0
while /usr/libexec/PlistBuddy -c "Print :$i" "$components" >/dev/null 2>&1; do
  /usr/libexec/PlistBuddy -c "Delete :$i:BundleIsRelocatable" "$components" >/dev/null 2>&1 || true
  /usr/libexec/PlistBuddy -c "Add :$i:BundleIsRelocatable bool false" "$components"
  i=$((i + 1))
done
pkgbuild --root "$root" --component-plist "$components" --identifier com.tryriot.agent.pkg --version "$version" \
  --scripts "$here/Packaging/scripts" --install-location / "$here/build/Riot-component.pkg"
if [ -n "${INSTALLER_IDENTITY:-}" ]; then
  productbuild --package "$here/build/Riot-component.pkg" --sign "$INSTALLER_IDENTITY" "$here/build/Riot-$version.pkg"
else
  productbuild --package "$here/build/Riot-component.pkg" "$here/build/Riot-$version.pkg"
fi
rm -f "$here/build/Riot-component.pkg" "$components"
echo "built $here/build/Riot-$version.pkg"
