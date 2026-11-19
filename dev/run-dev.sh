#!/bin/sh
# Builds Riot.app (apple/build-app.sh, ad-hoc signed) and runs it for development: the stub
# parrot, the daemon (unprivileged, its state under $RIOT_DEV_DIR) and the menu bar app (its icon
# says "DEV"), until interrupted.
#   dev/run-dev.sh            then, in another shell:  RIOT_SOCKET=$TMPDIR/riot-dev.sock riotctl status
# RIOT_DEV_APP=0 runs without the menu bar app; RIOT_DEV_BUILD=0 runs the last build as it is.
# The gateway (127.0.0.1:7591) is also an HTTPS_PROXY here (RIOT_DEV_PROXY=0 turns it off); its
# CA is $RIOT_DEV_DIR/gateway-ca.pem. See docs/network-interception.md.
# On a Mac where the agent is installed (a test fleet's), the installed agent is paused for the
# run (sudo) and resumed when it ends, so that only the dev one guards the clipboard and the AI
# apps; its daemon still holds 7591, and the dev gateway listens on 7601.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
app="$root/apple/build/Riot.app/Contents/MacOS"
export RIOT_DEV_DIR=${RIOT_DEV_DIR:-${TMPDIR:-/tmp}/riot-dev}
mkdir -p "$RIOT_DEV_DIR"
# Unix socket paths are limited to 104 bytes; keep it short.
export RIOT_SOCKET=${RIOT_SOCKET:-${TMPDIR:-/tmp}/riot-dev.sock}

if [ "${RIOT_DEV_BUILD:-1}" = 1 ]; then
  echo "building Riot.app…" >&2
  # A development build: none of a release's signing or bundled extensions.
  env -u SIGN_IDENTITY -u APP_ID -u WITH_ES -u WITH_NE -u WITH_STUB "$root/apple/build-app.sh" >/dev/null
elif [ ! -x "$app/riot-daemon" ] || [ ! -x "$root/core/target/release/riot-stub-parrot" ]; then
  echo "no build in apple/build/Riot.app: run without RIOT_DEV_BUILD=0 once" >&2
  exit 1
fi

if [ -z "${RIOT_GATEWAY_ADDR:-}" ] && nc -z 127.0.0.1 7591 2>/dev/null; then
  export RIOT_GATEWAY_ADDR=127.0.0.1:7601
  echo "127.0.0.1:7591 is taken (the installed agent?): the dev gateway listens on $RIOT_GATEWAY_ADDR" >&2
fi
installed=/Applications/Riot.app/Contents/MacOS/riotctl
paused=0
if [ -x "$installed" ] && [ -S /var/run/com.tryriot.agent/agent.sock ]; then
  echo "pausing the installed agent for this run (sudo)" >&2
  # For as long as this script runs: the installed daemon resumes once it is gone, however it
  # ends (Ctrl-C, its terminal closed, killed).
  if sudo env -u RIOT_SOCKET "$installed" pause $$ >/dev/null; then
    paused=1
  else
    echo "could not pause the installed agent: it keeps guarding the clipboard and the AI apps" >&2
  fi
fi

stub= daemon= menubar=
stop() {
  for pid in $menubar $daemon $stub; do kill "$pid" 2>/dev/null || true; done
  [ $paused = 0 ] || echo "the installed agent resumes" >&2
}
trap stop EXIT
trap 'exit 130' INT TERM HUP

"$root/core/target/release/riot-stub-parrot" 8787 --dev &
stub=$!
rm -f "$RIOT_SOCKET"
RIOT_SETTINGS="$root/dev/settings.json" RIOT_DATA_DIR="$RIOT_DEV_DIR" \
  RIOT_DEV_ALLOW_SCAN=1 RIOT_DEV_PROXY=${RIOT_DEV_PROXY:-1} "$app/riot-daemon" &
daemon=$!
if [ "${RIOT_DEV_APP:-1}" = 1 ]; then
  while [ ! -S "$RIOT_SOCKET" ]; do
    kill -0 $daemon 2>/dev/null || exit 1
    sleep 0.2
  done
  "$app/RiotAgent" &
  menubar=$!
fi
wait $daemon
