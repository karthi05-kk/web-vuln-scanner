# Automatic Web Vulnerability Scanner

Just enter a URL. Everything else is automatic.

Automatically detects Command Injection & File Inclusion vulnerabilities in web applications.

## Quick Start (2 minutes)

Step 1: Install dependencies
pip3 install -r requirements.txt

Step 2: Run scanner
python3 simple_main.py "http://example.com/page?param=value"

Step 3: Check results
cat reports/scan_*.json

## Key Features

- FULLY AUTOMATIC - No configuration needed
- 16 Command Injection Payloads - Auto-tested
- 11 File Inclusion Payloads - Auto-tested
- Parameter Detection - Auto-detects URL parameters
- Vulnerability Detection - Auto-analyzes responses
- Report Generation - JSON & PDF reports
- Simple CLI - One command to scan

## How to Use

Basic Scan
python3 simple_main.py "http://target.com/page?param=value"

Export to PDF
python3 simple_main.py "http://target.com/page?param=value" --pdf

Custom Timeout
python3 simple_main.py "http://target.com/page?param=value" --timeout 20

## Examples

Test File Inclusion
python3 simple_main.py "http://localhost/DVWA/vulnerabilities/fi/?page=include.php"

Test Command Injection
python3 simple_main.py "http://target.com/cmd.php?command=test"

## What Gets Tested?

Command Injection (16 payloads)
- Separators: ;, |, ||, &&
- Execution: ` and $()
- Detects: root:x:, uid=, bin/bash

File Inclusion (11 payloads)
- Path traversal: ../../../etc/passwd
- Null bytes: %00
- PHP wrappers: php://, file://
- Detects: file content, environment variables

## Output

JSON Report
cat reports/scan_*.json

PDF Report
ls -la reports/vulnerability_report_*.pdf

## Installation

Requirements
- Python 3.8+
- pip

Setup
git clone https://github.com/karthi05-kk/web-vuln-scanner.git
cd web-vuln-scanner
pip3 install -r requirements.txt

Verify
python3 simple_main.py -h

## Legal Disclaimer

AUTHORIZED TESTING ONLY!

- Test systems you own
- Test with written permission
- Unauthorized access is ILLEGAL

## License

MIT License - See LICENSE for details

## Contributing

Found a bug? Have ideas? Contribute!

Ideas:
- Add XSS detection
- Add SQL Injection detection
- Improve payloads
- Better documentation

## Show Your Support

Give this repository a star if it helped you!

Happy Penetration Testing!
