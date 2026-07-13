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

echo "======================================================================"
echo "STEP 1: Authenticating to $BASE_URL (needed so dirb sees real pages,"
echo "         not login-redirects, while discovering endpoints)"
echo "======================================================================"
curl -s -c "$COOKIE_JAR" -X POST "$BASE_URL/login.php" \
    -d "username=$DVWA_USER&password=$DVWA_PASS" -o /dev/null || true

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
echo "You'll confirm authorization ONCE for this entire batch of scans."
echo ""
read -p "Do you have explicit authorization to test $BASE_URL? [y/N]: " AUTH
if [[ ! "$AUTH" =~ ^[Yy] ]]; then
    echo "[!] Authorization not confirmed. Exiting without scanning."
    rm -f "$COOKIE_JAR"
    exit 1
fi

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
