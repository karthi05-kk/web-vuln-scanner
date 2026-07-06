#!/usr/bin/env python3
import argparse
import json
import os
from datetime import datetime
from urllib.parse import parse_qsl

from auto_scanner_fixed import AutoVulnerabilityScanner
from pdf_report_generator import PDFReportGenerator


def parse_post_data(raw: str) -> dict:
    """Turns 'ip=127.0.0.1&Submit=Submit' into {'ip': '127.0.0.1', 'Submit': 'Submit'}."""
    if not raw:
        return {}
    return dict(parse_qsl(raw, keep_blank_values=True))


def main():
    parser = argparse.ArgumentParser(
        description='🔐 AUTOMATIC WEB VULNERABILITY SCANNER (fixed)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  python3 simple_main_fixed.py "http://example.com/page?param=value"
  python3 simple_main_fixed.py "http://example.com/page?param=value" --pdf

  # For POST-driven forms (e.g. DVWA command injection page):
  python3 simple_main_fixed.py "http://localhost/DVWA/vulnerabilities/exec/" \\
      --post-data "ip=127.0.0.1&Submit=Submit"
"""
    )
    parser.add_argument('url', help='Target URL (with or without query parameters)')
    parser.add_argument('--json', action='store_true', help='Export to JSON')
    parser.add_argument('--pdf', action='store_true', help='Export to PDF')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout in seconds')
    parser.add_argument('--post-data', type=str, default='',
                         help='POST body params to fuzz, e.g. "ip=127.0.0.1&Submit=Submit"')
    args = parser.parse_args()

    scanner = AutoVulnerabilityScanner(
        args.url,
        timeout=args.timeout,
        post_data=parse_post_data(args.post_data),
    )
    results = scanner.run_automatic_scan()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
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
