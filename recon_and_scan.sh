#!/bin/bash
# recon_and_scan.sh
#
# Discovers DVWA's actual vulnerable endpoints with dirb, then runs the
# Command Injection / File Inclusion scanner against each one automatically
# - so you only ever type the BASE url, not every full endpoint path.
#
# Usage:
#   ./recon_and_scan.sh <base_url> [dvwa_user] [dvwa_pass]
#
# Example:
#   ./recon_and_scan.sh http://172.17.0.1:8080 admin password
#
# Requires: dirb (pre-installed on Kali), python3, and the scanner files
# (simple_main.py, auto_scanner.py, pdf_report_generator.py) in the same
# directory as this script.

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <base_url> [dvwa_user] [dvwa_pass]"
    echo "Example: $0 http://172.17.0.1:8080 admin password"
    exit 1
fi

BASE_URL="${1%/}"          # strip a trailing slash if present, we add it back consistently below

# Split into "scheme://host[:port]" and "path" so the filename-stripping
# logic below only ever looks at the PATH, never the host. Matching against
# the whole URL was the original bug: "http://google.com" has a dot in the
# host too, so the old regex treated "google.com" itself as if it were a
# filename like "index.php" and stripped it off, leaving a broken "http:/".
SCHEME_HOST=$(printf '%s' "$BASE_URL" | grep -oP '^[a-zA-Z][a-zA-Z0-9+.-]*://[^/]+' || true)
PATH_PART="${BASE_URL#"$SCHEME_HOST"}"

# If the person pasted a link to a specific page (e.g. .../index.php or
# .../login.php - the URL you'd actually browse to, which is a very natural
# thing to paste here) strip it back to the site root. dirb needs the root
# to correctly combine with the wordlist's relative paths like
# "vulnerabilities/exec/" - with a filename left in the base, every
# combined path becomes invalid (e.g. ".../index.php/vulnerabilities/exec/",
# which doesn't exist) and dirb finds nothing.
if [[ -n "$PATH_PART" && "$PATH_PART" =~ /[^/]+\.[a-zA-Z0-9]+$ ]]; then
    STRIPPED_PATH="${PATH_PART%/*}"
    echo "[i] Detected a specific page in the URL (${PATH_PART##*/}) - using the site root instead: ${SCHEME_HOST}${STRIPPED_PATH}"
    BASE_URL="${SCHEME_HOST}${STRIPPED_PATH}"
fi

DVWA_USER="${2:-admin}"
DVWA_PASS="${3:-password}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORDLIST="$SCRIPT_DIR/dvwa_wordlist.txt"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DIRB_OUTPUT="reports/dirb_scan_${TIMESTAMP}.txt"
COOKIE_JAR=$(mktemp)

mkdir -p reports

if [ ! -f "$WORDLIST" ]; then
    echo "[!] Wordlist not found at $WORDLIST - make sure dvwa_wordlist.txt is next to this script."
    exit 1
fi

# --- Scope allowlist + authorization gate -----------------------------
# This runs BEFORE any network traffic (login attempt, dirb). Previously
# authorization was only confirmed in Step 3, after Steps 1-2 had already
# hit the target - meaning a typo'd or wrong target (like the google.com
# mishap) got live requests before anyone was ever asked "should this be
# scanned at all?". Both checks now happen up front instead.
HOST_PART=$(printf '%s' "$SCHEME_HOST" | sed -E 's#^[a-zA-Z][a-zA-Z0-9+.-]*://##')
ALLOWLIST_FILE="$SCRIPT_DIR/authorized_targets.txt"

if [ ! -f "$ALLOWLIST_FILE" ]; then
    cat > "$ALLOWLIST_FILE" <<'EOF'
# authorized_targets.txt
# One authorized host per line, exactly as it appears in the URL you pass
# to recon_and_scan.sh - hostname or hostname:port, e.g.:
#   172.17.0.1:8080
#   dvwa-staging.internal.example.com
# Only add a host here if you have written authorization to test it.
# Lines starting with # are ignored.
EOF
    echo "[!] No authorized_targets.txt found - created an empty template at $ALLOWLIST_FILE"
    echo "    Add the host(s) you're authorized to test, one per line, then re-run."
    rm -f "$COOKIE_JAR"
    exit 1
fi

if ! grep -vE '^\s*#|^\s*$' "$ALLOWLIST_FILE" | grep -qxF "$HOST_PART"; then
    echo "[!] '$HOST_PART' is not listed in $ALLOWLIST_FILE."
    echo "    Refusing to scan a host that isn't explicitly allowlisted."
    echo "    Add it to $ALLOWLIST_FILE first - but only if you have written"
    echo "    authorization to test it."
    rm -f "$COOKIE_JAR"
    exit 1
fi

echo "======================================================================"
echo "AUTHORIZATION CHECK"
echo "======================================================================"
echo "Target: $BASE_URL"
echo "This will send a login attempt, a dirb directory brute-force, and then"
echo "(after a second confirmation) live command-injection/LFI payloads."
read -p "Confirm you have explicit written authorization to test this target right now [y/N]: " PRE_AUTH
if [[ ! "$PRE_AUTH" =~ ^[Yy] ]]; then
    echo "[!] Authorization not confirmed. Exiting before any scanning began."
    rm -f "$COOKIE_JAR"
    exit 1
fi

echo "======================================================================"
echo "STEP 1: Authenticating to $BASE_URL (needed so dirb sees real pages,"
echo "         not login-redirects, while discovering endpoints)"
echo "======================================================================"
curl -s -c "$COOKIE_JAR" "$BASE_URL/login.php" -o /tmp/dvwa_login_page_$$.html || true

USER_TOKEN=$(python3 -c "
from bs4 import BeautifulSoup
try:
    with open('/tmp/dvwa_login_page_$$.html') as f:
        soup = BeautifulSoup(f.read(), 'html.parser')
    tok = soup.find('input', {'name': 'user_token'})
    print(tok.get('value', '') if tok else '')
except Exception:
    print('')
")
rm -f /tmp/dvwa_login_page_$$.html

curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" -X POST "$BASE_URL/login.php" \
    -d "username=$DVWA_USER&password=$DVWA_PASS&Login=Login&user_token=$USER_TOKEN" -o /dev/null || true

COOKIE_HEADER=$(python3 -c "
import http.cookiejar, sys
cj = http.cookiejar.MozillaCookieJar('$COOKIE_JAR')
try:
    cj.load(ignore_discard=True, ignore_expires=True)
except Exception:
    pass
print('; '.join(f'{c.name}={c.value}' for c in cj))
")

if [ -z "$COOKIE_HEADER" ]; then
    echo "[!] Could not obtain a session cookie - login may have failed."
    echo "    Continuing anyway, but dirb may just find the login page repeatedly."
    DIRB_COOKIE_ARGS=()
else
    echo "[+] Authenticated, got cookie(s): $COOKIE_HEADER"
    DIRB_COOKIE_ARGS=(-c "$COOKIE_HEADER")
fi

echo ""
echo "======================================================================"
echo "STEP 2: Discovering live endpoints with dirb"
echo "======================================================================"
dirb "$BASE_URL/" "$WORDLIST" "${DIRB_COOKIE_ARGS[@]}" -o "$DIRB_OUTPUT" < /dev/null

ENDPOINTS=$(grep -oP '(?<=^\+ )\S+(?= \(CODE:200)' "$DIRB_OUTPUT" || true)
COUNT=$(printf '%s\n' "$ENDPOINTS" | grep -c . || true)

if [ "$COUNT" -eq 0 ]; then
    echo ""
    echo "[!] No live (CODE:200) endpoints found."
    echo "    - Check dvwa_wordlist.txt actually covers your target's page names"
    echo "    - Verify login succeeded above (a failed login means every path"
    echo "      redirects to login.php instead of returning 200)"
    echo "    - Full dirb output saved at: $DIRB_OUTPUT"
    rm -f "$COOKIE_JAR"
    exit 1
fi

echo "[+] Found $COUNT live endpoint(s):"
printf '%s\n' "$ENDPOINTS" | sed 's/^/    - /'

echo ""
echo "======================================================================"
echo "STEP 3: Vulnerability scanning each discovered endpoint"
echo "======================================================================"
echo "Authorization for $BASE_URL was already confirmed above."
echo ""

while IFS= read -r endpoint; do
    [ -z "$endpoint" ] && continue
    echo ""
    echo "----------------------------------------------------------------------"
    echo "Scanning: $endpoint"
    echo "----------------------------------------------------------------------"
    python3 "$SCRIPT_DIR/simple_main.py" "$endpoint" --pdf \
        --user "$DVWA_USER" --pass "$DVWA_PASS" --i-have-authorization
done <<< "$ENDPOINTS"

rm -f "$COOKIE_JAR"

echo ""
echo "======================================================================"
echo "ALL SCANS COMPLETE"
echo "======================================================================"
echo "Individual PDF/JSON reports for each endpoint are in reports/"
echo "Full dirb discovery log: $DIRB_OUTPUT"
