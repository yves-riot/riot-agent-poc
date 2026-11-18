#!/bin/sh
# Fills the profile's placeholders:
#   TEAM_ID=ABCDE12345 API_URL=https://… WORKSPACE_ID=… ENROLLMENT_SECRET=rbx_… \
#   EMPLOYEE_EMAIL='$EMAIL' mdm/render-profile.sh > riot-agent-acme.mobileconfig
# CA_CERT=…/gateway-ca.pem (mdm/fleet-ca.sh) adds the payload that trusts a test fleet's CA.
# Sign it with your MDM, or: security cms -S -N "Developer ID Application: …" -i in -o out
set -eu
: "${TEAM_ID:?}" "${API_URL:?}" "${WORKSPACE_ID:?}" "${ENROLLMENT_SECRET:?}"
EMPLOYEE_EMAIL=${EMPLOYEE_EMAIL:-\$EMAIL}
APP_ID=${APP_ID:-com.tryriot.agent}
esc() { printf '%s' "$1" | sed -e 's/[&|\\]/\\&/g'; }
if [ -n "${CA_CERT:-}" ]; then
  ca=$(openssl x509 -in "$CA_CERT" -outform der | base64 | tr -d '\n')
  ca_block='s|__CA_CERT__|'"$ca"'|g'
else
  ca_block='/<!-- ca:begin -->/,/<!-- ca:end -->/d'
fi
sed -e "s|__TEAM_ID__|$(esc "$TEAM_ID")|g" \
    -e "s|__APP_ID__|$(esc "$APP_ID")|g" \
    -e "s|__API_URL__|$(esc "$API_URL")|g" \
    -e "s|__WORKSPACE_ID__|$(esc "$WORKSPACE_ID")|g" \
    -e "s|__ENROLLMENT_SECRET__|$(esc "$ENROLLMENT_SECRET")|g" \
    -e "s|__EMPLOYEE_EMAIL__|$(esc "$EMPLOYEE_EMAIL")|g" \
    -e "$ca_block" \
    "$(dirname "$0")/riot-agent.mobileconfig"
