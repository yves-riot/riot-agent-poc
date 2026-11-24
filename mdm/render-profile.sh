#!/bin/sh
# Fills the profile's placeholders, for a test fleet or a development server; customers get
# theirs, filled, from the Hub (parrot's generate_agent_mdm_profile, docs/parrot-agent-api.md):
#   TEAM_ID=ABCDE12345 API_URL=https://… ENROLLMENT_KEY=rae_… CA_CERT=riot-root.pem \
#   EMPLOYEE_EMAIL='$EMAIL' mdm/render-profile.sh > riot-agent-acme.mobileconfig
# Without API_URL the agent uses production parrot. ENROLLMENT_KEY and CA_CERT (the
# organization's root, a certificate: no key) both come from parrot's admin API.
# Sign it with your MDM, or: security cms -S -N "Developer ID Application: …" -i in -o out
set -eu
: "${TEAM_ID:?}" "${ENROLLMENT_KEY:?}" "${CA_CERT:?}"
case $ENROLLMENT_KEY in rae_*) ;; *) echo "ENROLLMENT_KEY is the agent's rae_ key, not the extension's rbx_ secret" >&2; exit 1 ;; esac
EMPLOYEE_EMAIL=${EMPLOYEE_EMAIL:-\$EMAIL}
APP_ID=${APP_ID:-com.tryriot.agent}
esc() { printf '%s' "$1" | sed -e 's/[&|\\]/\\&/g'; }
ca=$(openssl x509 -in "$CA_CERT" -outform der | base64 | tr -d '\n')
# No API_URL: the ApiUrl line goes, and the agent uses its default.
api_url_line="/<key>ApiUrl<\/key>/d"
[ -z "${API_URL:-}" ] || api_url_line="s|__API_URL__|$(esc "$API_URL")|g"
sed -e "s|__TEAM_ID__|$(esc "$TEAM_ID")|g" \
    -e "s|__APP_ID__|$(esc "$APP_ID")|g" \
    -e "$api_url_line" \
    -e "s|__ENROLLMENT_KEY__|$(esc "$ENROLLMENT_KEY")|g" \
    -e "s|__EMPLOYEE_EMAIL__|$(esc "$EMPLOYEE_EMAIL")|g" \
    -e "s|__CA_CERT__|$ca|g" \
    "$(dirname "$0")/riot-agent.mobileconfig"
