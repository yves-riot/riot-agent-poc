#!/bin/sh
# Builds apple/build/Riot-<version>.pkg, the package an MDM deploys (after the profile).
#   SIGN_IDENTITY="Developer ID Application: …" INSTALLER_IDENTITY="Developer ID Installer: …" \
#   WITH_ES=1 ES_PROVISIONING_PROFILE=… apple/build-pkg.sh
# Then notarize: xcrun notarytool submit build/Riot-*.pkg --keychain-profile riot --wait
#                xcrun stapler staple build/Riot-*.pkg
set -eu
here=$(cd "$(dirname "$0")" && pwd)
"$here/build-app.sh"
version=$(defaults read "$here/build/Riot.app/Contents/Info" CFBundleShortVersionString)
root="$here/build/pkgroot"
rm -rf "$root" && mkdir -p "$root/Applications"
ditto --noextattr --noqtn "$here/build/Riot.app" "$root/Applications/Riot.app"
export COPYFILE_DISABLE=1
pkgbuild --root "$root" --identifier com.tryriot.agent.pkg --version "$version" \
  --scripts "$here/Packaging/scripts" --install-location / "$here/build/Riot-component.pkg"
if [ -n "${INSTALLER_IDENTITY:-}" ]; then
  productbuild --package "$here/build/Riot-component.pkg" --sign "$INSTALLER_IDENTITY" "$here/build/Riot-$version.pkg"
else
  productbuild --package "$here/build/Riot-component.pkg" "$here/build/Riot-$version.pkg"
fi
rm -f "$here/build/Riot-component.pkg"
echo "built $here/build/Riot-$version.pkg"
