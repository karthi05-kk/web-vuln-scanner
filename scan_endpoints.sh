#!/bin/bash
# scan_endpoints.sh
#
# Takes the endpoints YOU already found with dirb (or any plain list of
# URLs) and automatically runs the Command Injection / File Inclusion
# scanner against every single one - no manual typing of each URL.
#
# Works with two kinds of input file:
#   1. Raw dirb output (the -o file dirb writes, with "+ URL (CODE:200...)" lines)
#   2. A plain text file with one URL per line
# The script auto-detects which one you gave it.
#
# Usage:
#   ./scan_endpoints.sh <dirb_output_or_url_list> [dvwa_user] [dvwa_pass]
#
# Examples:
#   ./scan_endpoints.sh reports/dirb_scan_20260714.txt admin password
#   ./scan_endpoints.sh my_endpoints.txt admin password

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <dirb_output_file_or_url_list> [dvwa_user] [dvwa_pass]"
    echo ""
    echo "Examples:"
    echo "  $0 reports/dirb_scan_20260714.txt admin password"
    echo "  $0 my_endpoints.txt admin password"
    exit 1
fi

INPUT_FILE="$1"
DVWA_USER="${2:-admin}"
DVWA_PASS="${3:-password}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -f "$INPUT_FILE" ]; then
    echo "[!] File not found: $INPUT_FILE"
    exit 1
fi

echo "======================================================================"
echo "STEP 1: Reading endpoints from $INPUT_FILE"
echo "======================================================================"

if grep -q "^+ http" "$INPUT_FILE"; then
    echo "[i] Detected dirb output format - extracting live (CODE:200) endpoints"
    ENDPOINTS=$(grep -oP '(?<=^\+ )\S+(?= \(CODE:200)' "$INPUT_FILE" | sort -u)
else
    echo "[i] Treating this as a plain list of URLs (one per line)"
    ENDPOINTS=$(grep -E '^https?://' "$INPUT_FILE" | sort -u)
fi

COUNT=$(printf '%s\n' "$ENDPOINTS" | grep -c . || true)

if [ "$COUNT" -eq 0 ]; then
    echo "[!] No URLs found in $INPUT_FILE"
    echo "    - If this is dirb output, make sure it has lines like:"
    echo "      + http://target/vulnerabilities/exec/ (CODE:200|SIZE:163)"
    echo "    - If it's a plain list, make sure each line starts with http:// or https://"
    exit 1
fi

echo "[+] Found $COUNT endpoint(s) to scan:"
printf '%s\n' "$ENDPOINTS" | sed 's/^/    - /'

echo ""
echo "======================================================================"
echo "STEP 2: Vulnerability scanning each endpoint automatically"
echo "======================================================================"
echo "You'll confirm authorization ONCE for this entire batch."
echo ""
read -p "Do you have explicit authorization to test these targets? [y/N]: " AUTH
if [[ ! "$AUTH" =~ ^[Yy] ]]; then
    echo "[!] Authorization not confirmed. Exiting without scanning."
    exit 1
fi

SCANNED=0
while IFS= read -r endpoint; do
    [ -z "$endpoint" ] && continue
    SCANNED=$((SCANNED + 1))
    echo ""
    echo "----------------------------------------------------------------------"
    echo "[$SCANNED/$COUNT] Scanning: $endpoint"
    echo "----------------------------------------------------------------------"
    python3 "$SCRIPT_DIR/simple_main.py" "$endpoint" --pdf \
        --user "$DVWA_USER" --pass "$DVWA_PASS" --i-have-authorization
done <<< "$ENDPOINTS"

echo ""
echo "======================================================================"
echo "ALL SCANS COMPLETE - $SCANNED endpoint(s) scanned"
echo "======================================================================"
echo "Individual PDF/JSON reports for each endpoint are in reports/"
