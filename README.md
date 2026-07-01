cat > README.md << 'ENDOFFILE'
# 🔐 Automatic Web Vulnerability Scanner

[![GitHub stars](https://img.shields.io/github/stars/karthi05-kk/web-vuln-scanner)](https://github.com/karthi05-kk/web-vuln-scanner/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

**Just enter a URL. Everything else is automatic.**

🚀 Automatically detects **Command Injection** & **File Inclusion** vulnerabilities in web applications.

---

## ⚡ Quick Start (2 minutes)

```bash
# Step 1: Install dependencies
pip3 install -r requirements.txt

# Step 2: Run scanner
python3 simple_main.py "http://example.com/page?param=value"

# Step 3: Check results
cat reports/scan_*.json



✨ Key Features
✅ FULLY AUTOMATIC - No configuration needed
✅ 16 Command Injection Payloads - Auto-tested
✅ 11 File Inclusion Payloads - Auto-tested
✅ Parameter Detection - Auto-detects URL parameters
✅ Vulnerability Detection - Auto-analyzes responses
✅ Report Generation - JSON & PDF reports auto-generated
✅ Simple CLI - One command to scan everything


📖 How to Use
Basic Scan (Generates JSON Report)
bash
python3 simple_main.py "http://target.com/page?param=value"
Export to PDF Report
bash
python3 simple_main.py "http://target.com/page?param=value" --pdf
Custom Timeout (Slow Servers)
bash
python3 simple_main.py "http://target.com/page?param=value" --timeout 20
Get Help
bash
python3 simple_main.py -h

🎯 Real Examples
Example 1: Test Local Vulnerable App
bash
python3 simple_main.py "http://localhost/DVWA/vulnerabilities/fi/?page=include.php"
Example 2: Test File Inclusion
bash
python3 simple_main.py "http://target.com/download.php?file=test"
Example 3: Test Command Injection
bash
python3 simple_main.py "http://target.com/cmd.php?command=test"
📊 What Gets Tested?
Command Injection Detection
Tests 16 different payload techniques
Checks for: ;, |, ||, &&, backticks, $()
Looks for command output in response
Indicators: root:x:, uid=, bin/bash, total, etc.
File Inclusion Detection
Tests 11 different payload techniques
Path traversal: ../../../etc/passwd
Null bytes: %00
PHP wrappers: php://, file://
Looks for file content in response
Indicators: /etc/passwd, <?php, USER=, PATH=, etc.


📂 Output & Reports
JSON Report
Generated automatically as: reports/scan_YYYYMMDD_HHMMSS.json

Example:

JSON
{
  "target": "http://example.com/page",
  "scan_status": "Completed",
  "summary": {
    "total_vulnerabilities": 1,
    "critical_count": 0,
    "high_count": 1
  },
  "vulnerabilities": [
    {
      "type": "File Inclusion (LFI)",
      "severity": "HIGH",
      "parameter": "page",
      "payload": "../../../etc/passwd",
      "vulnerable": true
    }
  ]
}
PDF Report
Generated as: reports/vulnerability_report_YYYYMMDD_HHMMSS.pdf

Includes:

Title page with target info
Executive summary
Vulnerability details table
Professional formatting

🛠️ Installation
Requirements
Python 3.8 or higher
pip (Python package manager)
Linux/macOS
bash
git clone https://github.com/karthi05-kk/web-vuln-scanner.git
cd web-vuln-scanner
pip3 install -r requirements.txt
Windows
bash
git clone https://github.com/karthi05-kk/web-vuln-scanner.git
cd web-vuln-scanner
pip install -r requirements.txt
python simple_main.py -h
Verify Installation
bash
python3 simple_main.py -h
If you see help text, you're ready!

⚙️ How It Works Automatically
URL Input - You provide a URL with parameters
Parameter Detection - Tool extracts parameters automatically
Payload Selection - 27 payloads auto-selected
Vulnerability Testing - Each payload auto-tested
Response Analysis - Responses auto-analyzed for indicators
Report Generation - Reports auto-generated
File Saving - Results auto-saved to reports/ folder
All done in 1-2 minutes with ONE command!

🔍 Understanding Results
Severity Levels
CRITICAL - Immediate action required (Command Injection)
HIGH - Should be fixed soon (File Inclusion)
What Vulnerabilities Mean
Command Injection Found

The target can execute arbitrary commands
Attacker can run system commands
Very dangerous - fix immediately
File Inclusion Found

The target can read files from the system
Attacker can access sensitive files
Dangerous - fix immediately

🛡️ Remediation Guide
Fix Command Injection
Validate all user input
Use whitelists for allowed commands
Avoid system(), exec(), shell_exec()
Use language APIs instead
Escape special characters properly
Fix File Inclusion
Validate file paths
Use whitelist of allowed files
Store files outside web root
Disable PHP wrappers
Set proper file permissions

⚠️ Legal Disclaimer
IMPORTANT - READ THIS!

This tool is for AUTHORIZED SECURITY TESTING ONLY:

✅ DO:

Test systems you own
Test with written permission
Use in authorized penetration tests
Use in security research

❌ DO NOT:

Test without permission
Unauthorized access is ILLEGAL
Use for malicious purposes
Violate any laws
By using this tool, you agree to use it legally and ethically.

📚 Documentation
Installation Guide
Contributing Guidelines
Security Policy
Changelog

🤝 Contributing
Found a bug? Have a feature request? Want to contribute?

See CONTRIBUTING.md for guidelines.

Ideas:

Add XSS detection
Add SQL Injection detection
Add CSRF detection
Improve payloads
Fix bugs
Improve documentation

📄 License
MIT License - See LICENSE file for details

🔗 Links
GitHub Repository: https://github.com/karthi05-kk/web-vuln-scanner
Report Issues: https://github.com/karthi05-kk/web-vuln-scanner/issues
Discussions: https://github.com/karthi05-kk/web-vuln-scanner/discussions
⭐ Show Your Support
If this tool helped you, please give it a star on GitHub! ⭐

🙏 Thank You
Thank you for using this tool!

Remember: With great power comes great responsibility. 🔐

Last Updated: 2026-07-01 Version: 1.0.0
