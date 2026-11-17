#!/bin/sh
# Starts the stub parrot and the daemon, unprivileged, with their state under $RIOT_DEV_DIR.
#   dev/run-dev.sh            then, in another shell:  RIOT_SOCKET=$TMPDIR/riot-dev.sock riotctl status
# The gateway (127.0.0.1:7591) is also an HTTPS_PROXY here (RIOT_DEV_PROXY=0 turns it off); its
# CA is $RIOT_DEV_DIR/gateway-ca.pem. See docs/network-interception.md.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
export RIOT_DEV_DIR=${RIOT_DEV_DIR:-${TMPDIR:-/tmp}/riot-dev}
mkdir -p "$RIOT_DEV_DIR"
# Unix socket paths are limited to 104 bytes; keep it short.
export RIOT_SOCKET=${RIOT_SOCKET:-${TMPDIR:-/tmp}/riot-dev.sock}
node "$root/dev/stub-parrot.mjs" 8787 &
stub=$!
trap 'kill $stub 2>/dev/null' EXIT INT TERM
(cd "$root/js" && node build.mjs >/dev/null)
cd "$root/core"
RIOT_SETTINGS="$root/dev/settings.json" RIOT_DATA_DIR="$RIOT_DEV_DIR" RIOT_SOCKET="$RIOT_SOCKET" \
  RIOT_DEV_ALLOW_SCAN=1 RIOT_DEV_PROXY=${RIOT_DEV_PROXY:-1} cargo run --release -q -p riot-daemon --bin riot-daemon
