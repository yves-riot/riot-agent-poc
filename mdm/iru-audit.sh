#!/bin/sh
# Audit script of the Riot custom app in Iru ("Audit and Enforce"), rendered by
# apple/build-pkg.sh into apple/build/iru-audit.sh with the package's build number. Iru runs it
# as root at every check-in: 0 leaves the Mac as it is, anything else has Iru install the package.
want=__BUILD_NUMBER__
have=$(defaults read /Applications/Riot.app/Contents/Info CFBundleVersion 2>/dev/null || echo 0)
if [ "$have" -ge "$want" ] 2>/dev/null; then
  echo "Riot build $have installed"
  exit 0
fi
echo "Riot build $have installed, $want deployed: installing"
exit 1
