#!/usr/bin/env python3
import argparse
import json
import os
import sys
from datetime import datetime
from auto_scanner import AutoVulnerabilityScanner
from pdf_report_generator import PDFReportGenerator


AUTH_WARNING = """
======================================================================
⚠️  AUTHORIZATION REQUIRED
======================================================================
This tool actively sends command injection and file inclusion payloads
to the target. That is intrusion, not passive scanning, and running it
against a system you don't own or don't have explicit written
permission to test is illegal (e.g. under the CFAA in the US, the
Computer Misuse Act in the UK, and equivalent laws elsewhere) -
regardless of intent or whether anything is found.

Only proceed if ALL of the following are true:
  - You own this target, OR
  - You have explicit written permission to test it (e.g. a signed
    pentest engagement or scope document), OR
  - It is an in-scope asset in a bug bounty program you're enrolled in
======================================================================
"""


def confirm_authorization(skip_prompt: bool) -> bool:
    """Refuses to proceed unless the operator explicitly confirms
    authorization. --i-have-authorization skips the interactive prompt
    for legitimate repeated/scripted use (e.g. re-running against your
    own lab, or CI against a test environment you control)."""
    if skip_prompt:
        return True
    print(AUTH_WARNING)
    answer = input("Do you have explicit authorization to test this target? [y/N]: ").strip().lower()
    return answer in ("y", "yes")


def main():
    parser = argparse.ArgumentParser(
        description='🔐 AUTOMATIC WEB VULNERABILITY SCANNER',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  python3 simple_main.py "http://example.com/page?param=value"
  python3 simple_main.py "http://example.com/page?param=value" --json
  python3 simple_main.py "http://example.com/page?param=value" --pdf

  # DVWA-style target behind a login (auto-login is on by default):
  python3 simple_main.py "http://10.0.0.5/dvwa/vulnerabilities/exec/" --pdf
  python3 simple_main.py "http://10.0.0.5/dvwa/vulnerabilities/exec/" --pdf --user admin --pass password

  # Target that doesn't need login at all - skip the login attempt:
  python3 simple_main.py "http://example.com/page?id=1" --no-login --pdf
"""
    )
    parser.add_argument('url', help='Target URL with parameters')
    parser.add_argument('--json', action='store_true', help='Export to JSON')
    parser.add_argument('--pdf', action='store_true', help='Export to PDF')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout in seconds')
    parser.add_argument('--user', default='admin', help='Username for auto-login if a login form is detected (default: admin)')
    parser.add_argument('--pass', dest='password', default='password',
                         help='Password for auto-login if a login form is detected (default: password)')
    parser.add_argument('--no-login', action='store_true', help='Skip auto-login detection entirely')
    parser.add_argument('--i-have-authorization', action='store_true',
                         help='Skip the interactive authorization prompt (for repeated/scripted use '
                              'against a target you are already authorized to test)')
    args = parser.parse_args()

    if not confirm_authorization(args.i_have_authorization):
        print("\n[!] Authorization not confirmed. Exiting without scanning.")
        sys.exit(1)

    scanner = AutoVulnerabilityScanner(
        args.url, timeout=args.timeout,
        username=args.user, password=args.password, auto_login=not args.no_login,
    )
    results = scanner.run_automatic_scan()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    os.makedirs("reports", exist_ok=True)

    if args.json or not args.pdf:
        filename = f"reports/scan_{timestamp}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"\n[+] JSON saved: {filename}\n")

    if args.pdf:
        report_gen = PDFReportGenerator()
        pdf_file = report_gen.generate_report(results)
        print(f"\n[+] PDF saved: {pdf_file}\n")


if __name__ == '__main__':
    main()
