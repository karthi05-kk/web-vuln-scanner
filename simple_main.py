#!/usr/bin/env python3
import argparse
import json
import os
from datetime import datetime
from auto_scanner import AutoVulnerabilityScanner
from pdf_report_generator import PDFReportGenerator

def main():
    parser = argparse.ArgumentParser(
        description='🔐 AUTOMATIC WEB VULNERABILITY SCANNER',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  python3 simple_main.py "http://example.com/page?param=value"
  python3 simple_main.py "http://example.com/page?param=value" --json
  python3 simple_main.py "http://example.com/page?param=value" --pdf
        """
    )
    
    parser.add_argument('url', help='Target URL with parameters')
    parser.add_argument('--json', action='store_true', help='Export to JSON')
    parser.add_argument('--pdf', action='store_true', help='Export to PDF')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout in seconds')
    
    args = parser.parse_args()
    
    scanner = AutoVulnerabilityScanner(args.url, timeout=args.timeout)
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
