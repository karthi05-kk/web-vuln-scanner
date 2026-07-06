# 🔐 Automatic Web Vulnerability Scanner

[![GitHub stars](https://img.shields.io/github/stars/karthi05-kk/web-vuln-scanner)](https://github.com/karthi05-kk/web-vuln-scanner/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

**Just enter a URL. Everything else is automatic.**

🚀 Automatically detects **Command Injection** & **File Inclusion** vulnerabilities in web applications with zero configuration.

---

## 🆕 What's New in v1.1.0

- **Time-based blind Command Injection detection** — payloads like `; sleep 6` are now measured against response latency, catching injection that doesn't echo output back
- **POST body fuzzing** via `--post-data` — for apps like DVWA whose vulnerable fields are submitted as a form, not a URL query string
- **Authenticated scanning** via `--cookie` — pass a session cookie so gated pages (login-walled apps) actually get tested instead of silently scanning the login page
- **Login-redirect warning** — the scanner now tells you explicitly when a request landed on what looks like a login page, instead of just reporting 0 vulnerabilities
- Removed 8 dead Command Injection payloads (`whoami`-only) that could never match any detection indicator regardless of whether the target was vulnerable

---

## 📚 Documentation

| Guide | Purpose |
|---|---|
| **[🚀 QUICK_START.md](QUICK_START.md)** | Get running in 2 minutes (3 setup methods) |
| **[🛠️ INSTALLATION_GUIDE.md](INSTALLATION_GUIDE.md)** | Complete setup with virtual env, Docker, troubleshooting |
| **[📖 README.md](README.md)** | Full documentation (you are here) |

---

## ⚡ Quick Start (2 minutes)

### Choose Your Setup Method:

**Option 1: Automated Setup (Recommended)**
```bash
git clone https://github.com/karthi05-kk/web-vuln-scanner.git
cd web-vuln-scanner
bash SETUP.sh          # Linux/macOS
# OR
SETUP.bat             # Windows
source venv/bin/activate
python3 simple_main.py "http://example.com/page?param=value" --pdf
```

**Option 2: Docker (No Installation Required)**
```bash
git clone https://github.com/karthi05-kk/web-vuln-scanner.git
cd web-vuln-scanner
docker build -t vuln-scanner .
docker run vuln-scanner "http://example.com/page?param=value" --pdf
```

**Option 3: Manual Setup**
```bash
git clone https://github.com/karthi05-kk/web-vuln-scanner.git
cd web-vuln-scanner
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 simple_main.py "http://example.com/page?param=value"
```

👉 **For complete setup instructions, see [QUICK_START.md](QUICK_START.md) or [INSTALLATION_GUIDE.md](INSTALLATION_GUIDE.md)**

---

## ✨ Key Features

- ✅ **FULLY AUTOMATIC** - No configuration needed
- ✅ **17 Command Injection Payloads** - 12 indicator-based + 5 time-based (blind) detection
- ✅ **11 File Inclusion Payloads** - Auto-tested
- ✅ **GET and POST Support** - Auto-detects URL parameters; fuzz POST forms with `--post-data`
- ✅ **Authenticated Scanning** - Pass session cookies with `--cookie` for login-gated targets
- ✅ **Login-Wall Detection** - Warns you when requests are landing on a login page instead of the real target
- ✅ **Vulnerability Detection** - Auto-analyzes responses and response timing
- ✅ **Report Generation** - JSON & PDF reports auto-generated
- ✅ **Simple CLI** - One command to scan everything
- ✅ **Multiple Setup Options** - Virtual Env, Docker, Manual
- ✅ **Cross-Platform** - Works on Linux, macOS, Windows

---

## 📋 Prerequisites

- **Python 3.8** or higher
- **pip** (Python package manager)
- **Linux, macOS, or Windows**
- Internet connection for web requests

Optional:
- **Docker** (if using Docker setup method)
- **Virtual Environment** (recommended for isolation)

---

## 🛠️ Installation

### Recommended: Use Setup Scripts

**Linux/macOS:**
```bash
git clone https://github.com/karthi05-kk/web-vuln-scanner.git
cd web-vuln-scanner
bash SETUP.sh
```

**Windows:**
```bash
git clone https://github.com/karthi05-kk/web-vuln-scanner.git
cd web-vuln-scanner
SETUP.bat
```

### Alternative: Manual Setup

**Linux/macOS:**
```bash
git clone https://github.com/karthi05-kk/web-vuln-scanner.git
cd web-vuln-scanner
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

**Windows:**
```bash
git clone https://github.com/karthi05-kk/web-vuln-scanner.git
cd web-vuln-scanner
python -m venv venv
venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Docker Setup

```bash
git clone https://github.com/karthi05-kk/web-vuln-scanner.git
cd web-vuln-scanner
docker build -t vuln-scanner .
docker run vuln-scanner "http://target.com/page?param=value" --pdf
```

### Verify Installation

```bash
python3 simple_main.py -h
```

If you see help text, you're ready to scan!

👉 **For troubleshooting installation errors, see [INSTALLATION_GUIDE.md](INSTALLATION_GUIDE.md#-troubleshooting-installation-issues)**

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
python3 simple_main.py "http://target.com/page?param=value" --timeout 30
```

**Fuzz a POST form instead of URL parameters**
```bash
python3 simple_main.py "http://target.com/vulnerabilities/exec/" \
    --post-data "ip=127.0.0.1&Submit=Submit"
```

**Scan an authenticated (login-gated) target**
```bash
python3 simple_main.py "http://target.com/vulnerabilities/exec/" \
    --post-data "ip=127.0.0.1&Submit=Submit" \
    --cookie "PHPSESSID=your_session_id; security=low"
```
Get `PHPSESSID` (and any other required cookie, e.g. DVWA's `security` level cookie) by logging into the target in your browser, then copying the values from DevTools → Application → Cookies. Without a valid session, gated pages redirect to their login form and the scanner tests that instead of the real page — it will now warn you explicitly when this happens.

**Get help**
```bash
python3 simple_main.py -h
```

### 🎯 Real-World Examples

**Test Local Vulnerable Application (DVWA — File Inclusion, GET-based)**
```bash
python3 simple_main.py "http://localhost/DVWA/vulnerabilities/fi/?page=include.php" \
    --cookie "PHPSESSID=your_session_id; security=low"
```

**Test Local Vulnerable Application (DVWA — Command Injection, POST-based)**
```bash
python3 simple_main.py "http://localhost/DVWA/vulnerabilities/exec/" \
    --post-data "ip=127.0.0.1&Submit=Submit" \
    --cookie "PHPSESSID=your_session_id; security=low"
```

**Test File Inclusion Vulnerability**
```bash
python3 simple_main.py "http://target.com/download.php?file=test"
```

**Test Command Injection Vulnerability**
```bash
python3 simple_main.py "http://target.com/cmd.php?command=test"
```

**Test Multiple Parameters**
```bash
python3 simple_main.py "http://target.com/page?id=1&file=index.php&cmd=ls"
```

---

## 📊 What Gets Tested?

### Command Injection Detection (17 Payloads: 12 indicator-based + 5 time-based)

**Indicator-based** (needs the target to echo command output back in the response):
- **Separators**: `;` `|` `||` `&&`
- **Execution Methods**: Backticks `` ` `` and `$()`
- **Commands used**: `id`, `ls -la`, `cat /etc/passwd`
- **Indicators Detected**: `root:x:`, `uid=`, `gid=`, `groups=`, `/bin/bash`, `/bin/sh`, `total`, `drwx`

**Time-based / blind** (works even when the target never shows command output):
- Payloads run `sleep 6` via each separator (`;`, `|`, backticks, `$()`, `&&`)
- The scanner records a baseline response time first, then flags the target as vulnerable if the response is delayed by roughly the sleep duration, or if the request itself times out in a way consistent with the sleep executing

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
  "timestamp": "2026-07-06T01:15:20",
  "summary": {
    "total_vulnerabilities": 2,
    "critical_count": 1,
    "high_count": 1,
    "command_injection_found": 1,
    "file_inclusion_found": 1
  },
  "vulnerabilities": [
    {
      "type": "Command Injection",
      "detection": "time-based-blind",
      "severity": "CRITICAL",
      "parameter": "ip",
      "method": "POST",
      "payload": "; sleep 6",
      "vulnerable": true,
      "baseline_response_time": 0.31,
      "observed_response_time": 6.42
    },
    {
      "type": "File Inclusion (LFI)",
      "severity": "HIGH",
      "parameter": "page",
      "payload": "../../../etc/passwd",
      "vulnerable": true,
      "evidence": "root:x:0:0..."
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

### Check Results

```bash
# View JSON report
cat reports/scan_*.json

# View PDF report (macOS)
open reports/vulnerability_report_*.pdf

# View PDF report (Linux)
xdg-open reports/vulnerability_report_*.pdf

# View PDF report (Windows)
start reports/vulnerability_report_*.pdf
```

---

## ⚙️ How It Works

The scanner automates the entire vulnerability detection workflow:

1. **URL Input** - You provide a URL, optionally with `--post-data` and/or `--cookie`
2. **Preflight Check** - Tool checks whether the target redirects to a login page and warns if so
3. **Parameter Detection** - Tool extracts GET query parameters, and/or uses your supplied POST fields
4. **Payload Selection** - 28 payloads are auto-selected (17 Command Injection + 11 File Inclusion)
5. **Vulnerability Testing** - Each payload is auto-tested, with response content and timing both recorded
6. **Response Analysis** - Responses are analyzed for indicator strings and for timing anomalies vs. baseline
7. **Report Generation** - Reports are auto-generated
8. **File Saving** - Results are auto-saved to `reports/` folder

**Total Time**: 1-3 minutes with ONE command (time-based payloads add a few seconds each)

---

## 🔍 Understanding Results

### Severity Levels

| Severity | Description | Action |
|---|---|---|
| **CRITICAL** | Command Injection detected | Fix immediately |
| **HIGH** | File Inclusion detected | Fix soon |

### What Vulnerabilities Mean

**Command Injection Found**
- The target can execute arbitrary system commands
- Attacker can run any OS command
- A `detection: "time-based-blind"` finding means the app doesn't echo output but still executes injected commands — just as serious as an indicator-based match
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

### Getting 0 vulnerabilities on a target I know is vulnerable

Check the console output for these two signals before assuming the tool is wrong:

1. **`[!] No parameters found`** — the URL you scanned has no `?param=value` in it. If the real vulnerable field is a POST form (this is how DVWA's Command Injection page works), use `--post-data` instead.
2. **`[WARNING] This request appears to have landed on a LOGIN page`** — the target requires authentication and your request is hitting the login form, not the real page. Log in via your browser, grab the session cookie, and pass it with `--cookie`.

If neither warning fires and you still get 0, it's worth manually confirming the injection point with `curl` before assuming the app is safe — heavy input filtering (e.g. DVWA's Medium/High security levels) can legitimately block the default payload set.

### Connection Timeout

**Problem**: Scan times out on slow servers
**Solution**: Increase timeout with `--timeout` parameter
```bash
python3 simple_main.py "http://target.com" --timeout 30
```
Note: time-based Command Injection payloads add their own dynamic timeout on top of `--timeout`, so a single scan legitimately takes longer than earlier versions.

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

👉 **For comprehensive troubleshooting, see [INSTALLATION_GUIDE.md](INSTALLATION_GUIDE.md#-troubleshooting-installation-issues)**

### Permission Denied

**Problem**: Script won't run
**Solution**: Make script executable
```bash
chmod +x simple_main.py
```

---

## ℹ️ Limitations & Scope

- **Passive Testing Only** - Does not modify target files or databases
- **GET and POST** - Scans URL query parameters automatically, and POST body fields when supplied via `--post-data` (headers are still not tested)
- **Response Analysis** - Relies on response indicators and response timing (may have false positives/negatives)
- **Rate Limiting** - Does not handle aggressive rate limiting
- **Authentication** - Supported via `--cookie` for session-gated targets. No login-flow automation — you must log in manually and pass the session cookie
- **HTTPS Only** - Works with both HTTP and HTTPS

**Not Tested:**
- SQL Injection, XSS, CSRF (separate tools recommended)
- Out-of-band (DNS/HTTP callback) blind detection — time-based blind Command Injection is covered, but OOB channels are not implemented
- Advanced WAF/filter bypass techniques

---

## 📚 Recommended Testing Environments

### Vulnerable Applications for Practice

- [DVWA](http://www.dvwa.co.uk/) - Damn Vulnerable Web App
- [WebGoat](https://github.com/WebGoat/WebGoat) - OWASP WebGoat
- [bWAPP](http://www.itsecgames.com/) - buggy web application
- [Juice Shop](https://github.com/juice-shop/juice-shop) - OWASP Juice Shop

**Note on DVWA specifically**: its Command Injection page (`vulnerabilities/exec/`) is a POST form and requires a logged-in session with the security level cookie set — see the `--post-data` and `--cookie` examples above.

---

## 📁 Project Structure

```
web-vuln-scanner/
├── simple_main.py              Entry point (RUN THIS!)
├── auto_scanner.py             Core scanning logic
├── pdf_report_generator.py      PDF report generation
├── requirements.txt            Python dependencies
├── Dockerfile                  Container setup
├── docker-compose.yml          Docker Compose config
├── SETUP.sh                    Linux/macOS auto-setup
├── SETUP.bat                   Windows auto-setup
├── README.md                   Full documentation
├── QUICK_START.md              2-minute quick guide
├── INSTALLATION_GUIDE.md       Complete setup guide
├── .gitignore                  Git ignore rules
└── reports/                    Output folder (auto-created)
    ├── scan_20260701_103000.json
    └── vulnerability_report_20260701_103000.pdf
```

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
- Out-of-band (DNS/HTTP callback) blind detection
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

## 🔗 Quick Links

- 📖 [Quick Start Guide](QUICK_START.md) - Get running in 2 minutes
- 🛠️ [Installation Guide](INSTALLATION_GUIDE.md) - Complete setup with troubleshooting
- 🐛 [Report Issues](https://github.com/karthi05-kk/web-vuln-scanner/issues)
- 💬 [Discussions](https://github.com/karthi05-kk/web-vuln-scanner/discussions)
- 📋 [Contributing Guide](CONTRIBUTING.md)
- ⭐ [GitHub Repository](https://github.com/karthi05-kk/web-vuln-scanner)

---

## ⭐ Show Your Support

If this tool helped you, please give it a **star** ⭐ on GitHub!

---

## 🙏 Thank You

Thank you for using this tool!

**Remember**: With great power comes great responsibility. 🔐

---

**Last Updated**: 2026-07-06
**Version**: 1.1.0
**Status**: Active Development
