# 🔐 Automatic Web Vulnerability Scanner

[![GitHub stars](https://img.shields.io/github/stars/karthi05-kk/web-vuln-scanner)](https://github.com/karthi05-kk/web-vuln-scanner/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

**Just enter a URL. Everything else is automatic.**

🚀 Automatically detects **Command Injection** & **File Inclusion** vulnerabilities in web applications with zero configuration.

---

## ⚡ Quick Start (2 minutes)

```bash
# Step 1: Install dependencies
pip3 install -r requirements.txt

# Step 2: Run scanner
python3 simple_main.py "http://example.com/page?param=value"

# Step 3: Check results
cat reports/scan_*.json
```

---

## ✨ Key Features

- ✅ **FULLY AUTOMATIC** - No configuration needed
- ✅ **16 Command Injection Payloads** - Auto-tested
- ✅ **11 File Inclusion Payloads** - Auto-tested
- ✅ **Parameter Detection** - Auto-detects URL parameters
- ✅ **Vulnerability Detection** - Auto-analyzes responses
- ✅ **Report Generation** - JSON & PDF reports auto-generated
- ✅ **Simple CLI** - One command to scan everything

---

## 📋 Prerequisites

- **Python 3.8** or higher
- **pip** (Python package manager)
- **Linux, macOS, or Windows**
- Internet connection for web requests

---

## 🛠️ Installation

### Linux/macOS
```bash
git clone https://github.com/karthi05-kk/web-vuln-scanner.git
cd web-vuln-scanner
pip3 install -r requirements.txt
```

### Windows
```bash
git clone https://github.com/karthi05-kk/web-vuln-scanner.git
cd web-vuln-scanner
pip install -r requirements.txt
```

### Verify Installation
```bash
python3 simple_main.py -h
```
If you see help text, you're ready to scan!

---

## 📖 Usage

### Basic Commands

**Run a basic scan (generates JSON report)**
```bash
python3 simple_main.py "http://target.com/page?param=value"
```

**Export to PDF report**
```bash
python3 simple_main.py "http://target.com/page?param=value" --pdf
```

**Set custom timeout (for slow servers)**
```bash
python3 simple_main.py "http://target.com/page?param=value" --timeout 20
```

**Get help**
```bash
python3 simple_main.py -h
```

### 🎯 Real-World Examples

**Test Local Vulnerable Application**
```bash
python3 simple_main.py "http://localhost/DVWA/vulnerabilities/fi/?page=include.php"
```

**Test File Inclusion Vulnerability**
```bash
python3 simple_main.py "http://target.com/download.php?file=test"
```

**Test Command Injection Vulnerability**
```bash
python3 simple_main.py "http://target.com/cmd.php?command=test"
```

---

## 📊 What Gets Tested?

### Command Injection Detection (16 Payloads)
- **Separators**: `;` `|` `||` `&&`
- **Execution Methods**: Backticks `` ` `` and `$()`
- **Indicators Detected**: `root:x:`, `uid=`, `/bin/bash`, file listings
- **Severity**: CRITICAL

### File Inclusion Detection (11 Payloads)
- **Path Traversal**: `../../../etc/passwd`
- **Null Bytes**: `%00`
- **PHP Wrappers**: `php://`, `file://`
- **Indicators Detected**: `/etc/passwd`, `<?php`, `USER=`, `PATH=`
- **Severity**: HIGH

---

## 📂 Output & Reports

### JSON Report
Automatically generated as: `reports/scan_YYYYMMDD_HHMMSS.json`

**Example output:**
```json
{
  "target": "http://example.com/page",
  "scan_status": "Completed",
  "scan_time": "2026-07-01 10:30:00",
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
      "vulnerable": true,
      "response_snippet": "root:x:0:0..."
    }
  ]
}
```

### PDF Report
Generated as: `reports/vulnerability_report_YYYYMMDD_HHMMSS.pdf`

Includes:
- Title page with target information
- Executive summary
- Vulnerability details table
- Recommendations and remediation steps
- Professional formatting

---

## ⚙️ How It Works

The scanner automates the entire vulnerability detection workflow:

1. **URL Input** - You provide a URL with parameters
2. **Parameter Detection** - Tool extracts parameters automatically
3. **Payload Selection** - 27 payloads are auto-selected
4. **Vulnerability Testing** - Each payload is auto-tested
5. **Response Analysis** - Responses are auto-analyzed for indicators
6. **Report Generation** - Reports are auto-generated
7. **File Saving** - Results are auto-saved to `reports/` folder

**Total Time**: 1-2 minutes with ONE command!

---

## 🔍 Understanding Results

### Severity Levels

| Severity | Description | Action |
|----------|-------------|--------|
| **CRITICAL** | Command Injection detected | Fix immediately |
| **HIGH** | File Inclusion detected | Fix soon |

### What Vulnerabilities Mean

**Command Injection Found**
- The target can execute arbitrary system commands
- Attacker can run any OS command
- ⚠️ **Very dangerous** - fix immediately

**File Inclusion Found**
- The target can read files from the system
- Attacker can access sensitive files (e.g., `/etc/passwd`)
- ⚠️ **Dangerous** - fix immediately

---

## 🛡️ Remediation Guide

### Fix Command Injection
- ✅ Validate all user input strictly
- ✅ Use whitelists for allowed commands
- ✅ Avoid dangerous functions: `system()`, `exec()`, `shell_exec()`
- ✅ Use language APIs instead of shell commands
- ✅ Escape special characters properly

### Fix File Inclusion
- ✅ Validate file paths
- ✅ Use whitelist of allowed files
- ✅ Store files outside web root
- ✅ Disable PHP wrappers in configuration
- ✅ Set proper file permissions (chmod 600)

---

## ❓ Troubleshooting

### Connection Timeout
**Problem**: Scan times out on slow servers
**Solution**: Increase timeout with `--timeout` parameter
```bash
python3 simple_main.py "http://target.com" --timeout 30
```

### Reports Not Generated
**Problem**: No files in `reports/` directory
**Solution**: Check that directory exists and has write permissions
```bash
mkdir -p reports
chmod 755 reports
```

### ModuleNotFoundError
**Problem**: `ModuleNotFoundError: No module named 'requests'`
**Solution**: Reinstall dependencies
```bash
pip3 install --upgrade -r requirements.txt
```

### Permission Denied
**Problem**: Script won't run
**Solution**: Make script executable
```bash
chmod +x simple_main.py
```

---

## ℹ️ Limitations & Scope

- **Passive Testing Only** - Does not modify target files or databases
- **URL Parameters Only** - Scans URL parameters (not headers, cookies, or POST body)
- **Response Analysis** - Relies on response indicators (may have false positives/negatives)
- **Rate Limiting** - Does not handle aggressive rate limiting
- **Authentication** - No built-in authentication support
- **HTTPS Only** - Works with both HTTP and HTTPS

**Not Tested:**
- SQL Injection, XSS, CSRF (separate tools recommended)
- Blind vulnerabilities (no out-of-band detection)
- Advanced bypass techniques

---

## 📚 Recommended Testing Environments

### Vulnerable Applications for Practice
- [DVWA](http://www.dvwa.co.uk/) - Damn Vulnerable Web App
- [WebGoat](https://github.com/WebGoat/WebGoat) - OWASP WebGoat
- [bWAPP](http://www.itsecgames.com/) - buggy web application
- [Juice Shop](https://github.com/juice-shop/juice-shop) - OWASP Juice Shop

---

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details

---

## 🤝 Contributing

Found a bug? Have a feature request? Want to contribute?

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Ideas for Contributions
- Add XSS detection
- Add SQL Injection detection
- Add CSRF detection
- Improve payload accuracy
- Better false positive filtering
- Support for authenticated scanning
- Add more output formats

---

## ⚠️ Legal Disclaimer

**IMPORTANT - READ THIS!**

This tool is for **AUTHORIZED SECURITY TESTING ONLY**:

### ✅ DO:
- Test systems you own
- Test with written permission
- Use in authorized penetration tests
- Use in legitimate security research
- Report findings responsibly

### ❌ DO NOT:
- Test without permission
- Perform unauthorized access (it's ILLEGAL)
- Use for malicious purposes
- Violate any laws or regulations
- Access systems you don't have permission to test

**By using this tool, you agree to use it legally and ethically.**

Unauthorized access to computer systems is illegal under the Computer Fraud and Abuse Act (CFAA) and similar laws worldwide.

---

## 🔗 Links

- 📖 [GitHub Repository](https://github.com/karthi05-kk/web-vuln-scanner)
- 🐛 [Report Issues](https://github.com/karthi05-kk/web-vuln-scanner/issues)
- 💬 [Discussions](https://github.com/karthi05-kk/web-vuln-scanner/discussions)
- 📋 [Contributing Guide](CONTRIBUTING.md)

---

## ⭐ Show Your Support

If this tool helped you, please give it a **star** ⭐ on GitHub!

---

## 🙏 Thank You

Thank you for using this tool! 

**Remember**: With great power comes great responsibility. 🔐

**Last Updated**: 2026-07-01  
**Version**: 1.0.0
