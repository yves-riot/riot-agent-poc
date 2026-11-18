#!/bin/sh
# Creates the CA a test fleet shares, in a folder outside the repository:
#   mdm/fleet-ca.sh ~/riot/fleet-ca
# writes gateway-ca.pem (the profile trusts it: CA_CERT=… render-profile.sh) and gateway-ca-key.pem
# (the package installs it: FLEET_CA_DIR=… build-pkg.sh). Every Mac of the fleet then terminates
# TLS with the same key: whoever has it, or the package, can read the AI traffic of those Macs.
# Like the CA each daemon creates for itself (core/riot-daemon/src/gateway/ca.rs), it may only
# issue for the AI domains; keep the two lists the same.
set -eu
dir=${1:?usage: fleet-ca.sh <folder>}
[ -e "$dir/gateway-ca-key.pem" ] && { echo "$dir already holds a CA" >&2; exit 1; }
mkdir -p "$dir"
umask 077
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$dir/gateway-ca-key.pem"
umask 022
config=$(mktemp)
trap 'rm -f "$config"' EXIT
cat > "$config" <<'EOF'
[req]
distinguished_name = dn
prompt = no
x509_extensions = ca
[dn]
O = Riot
CN = Riot AI gateway (test fleet)
[ca]
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
nameConstraints = critical, permitted;DNS:anthropic.com, permitted;DNS:claude.ai, permitted;DNS:openai.com, permitted;DNS:chatgpt.com
EOF
openssl req -new -x509 -key "$dir/gateway-ca-key.pem" -days 365 -sha256 -config "$config" -out "$dir/gateway-ca.pem"
openssl x509 -in "$dir/gateway-ca.pem" -noout -subject -enddate -fingerprint -sha256
