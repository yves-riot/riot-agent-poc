#!/bin/sh
# Builds apple/build/Riot-<version>-<build>.pkg, the package an MDM deploys (after the profile),
# and apple/build/iru-audit.sh, the audit script that has Iru install it where an older build runs.
#   SIGN_IDENTITY="Developer ID Application: …" INSTALLER_IDENTITY="Developer ID Installer: …" \
#   WITH_ES=1 ES_PROVISIONING_PROFILE=… apple/build-pkg.sh
# (the variables of build-app.sh). The package holds no key: each daemon generates its own, and
# parrot signs its intermediate CA (docs/network-interception.md).
# NOTARY_PROFILE notarizes Riot.app before packaging it: a Mac with SIP on refuses a system
# extension that is not notarized. The profile holds the team's credentials, stored once with
#   xcrun notarytool store-credentials <profile> --apple-id … --team-id …
set -eu
here=$(cd "$(dirname "$0")" && pwd)
"$here/build-app.sh"
if [ -n "${NOTARY_PROFILE:-}" ]; then
  zip="$here/build/Riot-notarize.zip"
  rm -f "$zip"
  ditto -c -k --keepParent "$here/build/Riot.app" "$zip"
  out=$(xcrun notarytool submit "$zip" --keychain-profile "$NOTARY_PROFILE" --wait 2>&1) || true
  rm -f "$zip"
  echo "$out"
  echo "$out" | grep -q "status: Accepted" || {
    echo "notarization failed: xcrun notarytool log <id> --keychain-profile $NOTARY_PROFILE" >&2
    exit 1
  }
  xcrun stapler staple "$here/build/Riot.app"
fi
version=$(defaults read "$here/build/Riot.app/Contents/Info" CFBundleShortVersionString)
build=$(defaults read "$here/build/Riot.app/Contents/Info" CFBundleVersion)
pkg="$here/build/Riot-$version-$build.pkg"
root="$here/build/pkgroot"
rm -rf "$root" && mkdir -p "$root/Applications"
ditto --noextattr --noqtn "$here/build/Riot.app" "$root/Applications/Riot.app"
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
pkgbuild --root "$root" --component-plist "$components" --identifier com.tryriot.agent.pkg --version "$version.$build" \
  --scripts "$here/Packaging/scripts" --install-location / "$here/build/Riot-component.pkg"
if [ -n "${INSTALLER_IDENTITY:-}" ]; then
  productbuild --package "$here/build/Riot-component.pkg" --sign "$INSTALLER_IDENTITY" "$pkg"
else
  productbuild --package "$here/build/Riot-component.pkg" "$pkg"
fi
rm -f "$here/build/Riot-component.pkg" "$components"
sed "s/__BUILD_NUMBER__/$build/" "$here/../mdm/iru-audit.sh" > "$here/build/iru-audit.sh"
echo "built $pkg and $here/build/iru-audit.sh"
