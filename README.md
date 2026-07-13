# 🔐 Automatic Web Vulnerability Scanner

[![GitHub stars](https://img.shields.io/github/stars/karthi05-kk/web-vuln-scanner)](https://github.com/karthi05-kk/web-vuln-scanner/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

**Just enter a URL. Everything else is automatic — including login.**

🚀 Automatically detects **Command Injection** & **File Inclusion** vulnerabilities in web applications, including login-gated targets like DVWA, with zero manual session setup.

---

## 🆕 What's New in v1.3.0

- **`recon_and_scan.sh`** — a new wrapper that discovers a target's live endpoints with `dirb` and then scans each one automatically, so you only need to type the *base* URL instead of every full vulnerable path. See [Recon Mode](#-recon-mode-discover--scan-automatically) below.
- **Fixed a report filename collision** — when two scans finished within the same second (common when batch-scanning multiple endpoints back to back), the timestamp-based report filename collided and one report silently overwrote another. Report filenames now include microsecond precision to guarantee uniqueness.

## What's New in v1.2.0

- **Auto-login** — the scanner detects a login form on the target (or a redirect to one), scrapes any CSRF token automatically, and logs in with `--user`/`--pass` (defaults to `admin`/`password`) before scanning. No more manually copying session cookies out of DevTools.
- **HTML form auto-discovery** — parameters are now found by parsing the page's actual `<form>` fields (GET or POST), not just the URL's query string. This is what lets the scanner find DVWA's Command Injection field (`ip`), which is submitted via POST and never appears in the URL at all.
- **Baseline diffing** — each parameter is tested once with a harmless value first. A payload is only flagged as vulnerable if its indicator is *new* compared to that baseline, cutting down false positives from generic words (like "total") that already appear on the normal page.
- **Authorization gate** — the scanner now prints a legal warning and requires an explicit `y` confirmation (or `--i-have-authorization` to skip the prompt for your own repeated/scripted use) before sending a single payload.
- Fixed a bug where `extract_parameters()` only ever checked the URL's query string, so scanning a URL with no `?param=value` in it (e.g. DVWA's exec page) always reported `[!] No parameters found`, even when a real vulnerability was one page-load away.

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

The first time you run a scan, you'll be asked to confirm you're authorized to test the target — see [Authorization Gate](#-authorization-gate) below.

---

## ✨ Key Features

- ✅ **FULLY AUTOMATIC** - Enter a URL; login, parameter discovery, and payload testing all happen without manual setup
- ✅ **Auto-Login** - Detects login forms, scrapes CSRF tokens, and authenticates automatically
- ✅ **GET + POST Parameter Discovery** - Parses page HTML for `<form>` fields, not just the URL query string
- ✅ **16 Command Injection Payloads** - Indicator-based detection
- ✅ **11 File Inclusion Payloads** - Auto-tested
- ✅ **Baseline Diffing** - Each finding is checked against a clean baseline response to reduce false positives
- ✅ **Authorization Gate** - Requires explicit confirmation before any payload is sent
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
- **`dirb`** (only needed for [Recon Mode](#-recon-mode-discover--scan-automatically) — ships by default on Kali; `sudo apt install dirb` otherwise)

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

## 🔓 Authorization Gate

Before any payload is sent, the scanner prints a legal warning and asks:

```
Do you have explicit authorization to test this target? [y/N]:
```

Anything other than `y`/`yes` exits immediately without sending a single request. This exists because the scanner performs active intrusion (command injection and path traversal attempts), not passive scanning, and running it against a target you're not authorized to test is illegal regardless of intent.

For your own repeated or scripted use (e.g. re-running against your own lab), skip the prompt with:
```bash
python3 simple_main.py "http://your-target" --pdf --i-have-authorization
```

This is a deliberate speed bump, not a technical enforcement mechanism — see the [Legal Disclaimer](#️-legal-disclaimer) below for what you're actually agreeing to by using this tool.

---

## 🔎 Recon Mode: Discover & Scan Automatically

Typing out every full vulnerable URL by hand (`.../vulnerabilities/exec/`, `.../vulnerabilities/fi/`, etc.) gets old fast. `recon_and_scan.sh` automates the discovery step too, using `dirb` (pre-installed on Kali) to find a target's live pages, then scanning each one automatically:

```bash
chmod +x recon_and_scan.sh
./recon_and_scan.sh http://target.com/dvwa admin password
```

What it does, in order:
1. Logs in once via `curl` so `dirb` sees real pages instead of login-redirects
2. Runs `dirb` against the target using `dvwa_wordlist.txt` — a wordlist of DVWA's actual page names (`exec`, `fi`, `sqli`, etc.), since generic `dirb` wordlists like `common.txt` don't reliably contain these specific names
3. Lists every live (`CODE:200`) endpoint it found
4. Asks you to confirm authorization **once** for the whole batch
5. Runs the full scanner against each discovered endpoint, saving a separate PDF/JSON report per endpoint into `reports/`

**Requires**: `dirb` (`sudo apt install dirb` if it's not already on your system — it ships by default on Kali).

**Limitation**: `dvwa_wordlist.txt` only covers DVWA's known `/vulnerabilities/*` page names. For broader discovery beyond DVWA specifically, you can point `dirb` at a more general wordlist (e.g. `/usr/share/dirb/wordlists/common.txt` on Kali) — expect more noise and false "found" pages, since that wordlist wasn't built for this app's structure.

If you'd rather scan one specific URL directly without discovery, `simple_main.py` still works exactly as described below.

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

**Scan a login-gated target (e.g. DVWA)**
```bash
python3 simple_main.py "http://target.com/vulnerabilities/exec/" --pdf
```
No manual cookie required — the scanner detects the login form and authenticates with the default credentials (`admin`/`password`). If your target uses different credentials:
```bash
python3 simple_main.py "http://target.com/vulnerabilities/exec/" --pdf --user myuser --pass mypass
```

**Skip auto-login entirely** (for targets that don't require it)
```bash
python3 simple_main.py "http://target.com/page?id=1" --pdf --no-login
```

**Skip the authorization prompt for repeated/scripted runs against a target you're already authorized to test**
```bash
python3 simple_main.py "http://target.com/page?id=1" --pdf --i-have-authorization
```

**Get help**
```bash
python3 simple_main.py -h
```

### 🎯 Real-World Examples

**Test Local Vulnerable Application (DVWA — File Inclusion, GET-based)**
```bash
python3 simple_main.py "http://localhost/DVWA/vulnerabilities/fi/?page=include.php" --pdf
```

**Test Local Vulnerable Application (DVWA — Command Injection, POST-based)**
```bash
python3 simple_main.py "http://localhost/DVWA/vulnerabilities/exec/" --pdf
```
The `ip` field here is a POST form field with no query string in the URL at all — the scanner finds it by parsing the page HTML, then logs in automatically before testing it.

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

### Command Injection Detection (16 Payloads)

- **Separators**: `;` `|` `||` `&&`
- **Execution Methods**: Backticks `` ` `` and `$()`
- **Commands used**: `whoami`, `id`, `ls -la`, `cat /etc/passwd`
- **Indicators Detected**: `root:x:`, `uid=`, `gid=`, `groups=`, `/bin/bash`, `/bin/sh`, `total`, `drwx`
- **False-positive guard**: each indicator is only counted if it's absent from a baseline (non-payload) request to the same parameter
- **Severity**: CRITICAL

### File Inclusion Detection (11 Payloads)

- **Path Traversal**: `../../../etc/passwd`
- **Null Bytes**: `%00`
- **PHP Wrappers**: `php://`, `file://`
- **Indicators Detected**: `root:x:`, `/bin/bash`, `/bin/sh`, `nologin`, `<?php`, `<?=`, `USER=`, `PATH=`, `HOME=`
- **False-positive guard**: same baseline-diffing as above
- **Severity**: HIGH

Total: **27 payloads** tested per discovered parameter.

---

## 📂 Output & Reports

### JSON Report

Automatically generated as: `reports/scan_YYYYMMDD_HHMMSS_ffffff.json`

**Example output:**
```json
{
  "target": "http://target.com/vulnerabilities/exec/",
  "scan_status": "Completed",
  "timestamp": "2026-07-12T13:37:11.123456",
  "scan_type": "AUTOMATIC",
  "payloads_tested": {
    "command_injection": 16,
    "file_inclusion": 11,
    "total_payloads": 27
  },
  "summary": {
    "total_vulnerabilities": 1,
    "critical_count": 1,
    "high_count": 0,
    "command_injection_found": 1,
    "file_inclusion_found": 0
  },
  "vulnerabilities": [
    {
      "type": "Command Injection",
      "severity": "CRITICAL",
      "url": "http://target.com/vulnerabilities/exec/",
      "parameter": "ip",
      "method": "POST",
      "payload": "; id",
      "vulnerable": true,
      "status_code": 200
    }
  ]
}
```

### PDF Report

Generated as: `reports/vulnerability_report_YYYYMMDD_HHMMSS_ffffff.pdf`

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

1. **Authorization Check** - You confirm you're authorized to test the target (or pass `--i-have-authorization`)
2. **URL Input** - You provide a target URL
3. **Auto-Login** - The scanner checks whether the target redirects to a login form or shows a password field; if so, it logs in automatically (scraping any CSRF token) using `--user`/`--pass`
4. **Parameter Discovery** - The scanner extracts GET query parameters from the URL *and* parses the page's actual `<form>` elements for POST/GET fields
5. **Baseline Request** - Each parameter gets one harmless "control" request first, to know what a normal response looks like
6. **Payload Testing** - All 27 payloads are tested against each discovered parameter
7. **Response Analysis** - Responses are checked for indicator strings that are new relative to the baseline
8. **Report Generation** - Results are compiled into the scan summary
9. **File Saving** - Results are auto-saved to `reports/` as JSON and/or PDF

**Total Time**: 1-2 minutes with ONE command

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

Check the console output for these signals before assuming the tool is wrong:

1. **`[!] No parameters found`** — the scanner couldn't find any GET query parameters or `<form>` fields on the page. Confirm the URL is actually the vulnerable page, not a landing/redirect page.
2. **`[AUTH] Target appears to require login... attempting auto-login`** followed by **`[!] Auto-login did not appear to succeed`** — your credentials are wrong for this target. Pass the correct ones with `--user`/`--pass`.
3. If neither warning fires and you still get 0, it's worth manually confirming the injection point with `curl` before assuming the app is safe — heavy input filtering (e.g. DVWA's Medium/High security levels) can legitimately block the default payload set.

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

**Problem**: `ModuleNotFoundError: No module named 'bs4'` (or `requests`)
**Solution**: Reinstall dependencies
```bash
pip3 install --upgrade -r requirements.txt
```
Note: this version added `beautifulsoup4` as a dependency for HTML form parsing — make sure you've re-run `pip install -r requirements.txt` after updating.

👉 **For comprehensive troubleshooting, see [INSTALLATION_GUIDE.md](INSTALLATION_GUIDE.md#-troubleshooting-installation-issues)**

### Permission Denied

**Problem**: Script won't run
**Solution**: Make script executable
```bash
chmod +x simple_main.py
```

---

## ℹ️ Limitations & Scope

- **Active Testing** - Sends real payloads to the target; this is intrusive, not passive, testing
- **GET and POST** - Discovers both automatically via URL parsing and HTML form parsing (headers and cookies themselves are not fuzzed)
- **Response Analysis** - Relies on response indicator strings, diffed against a baseline (may still have false positives/negatives)
- **Rate Limiting** - Does not handle aggressive rate limiting
- **Authentication** - Auto-login works for standard HTML login forms (like DVWA's); it does not handle multi-factor auth, OAuth flows, or JavaScript-rendered login forms
- **HTTPS Only** - Works with both HTTP and HTTPS

**Not Tested:**
- SQL Injection, XSS, CSRF (separate tools recommended)
- Out-of-band (DNS/HTTP callback) or time-based blind detection
- Advanced WAF/filter bypass techniques (e.g. DVWA Medium/High security levels)

---

## 📚 Recommended Testing Environments

### Vulnerable Applications for Practice

- [DVWA](http://www.dvwa.co.uk/) - Damn Vulnerable Web App
- [WebGoat](https://github.com/WebGoat/WebGoat) - OWASP WebGoat
- [bWAPP](http://www.itsecgames.com/) - buggy web application
- [Juice Shop](https://github.com/juice-shop/juice-shop) - OWASP Juice Shop

**Note on DVWA specifically**: its Command Injection page (`vulnerabilities/exec/`) is a POST form gated behind login — this is exactly the case the auto-login and form-discovery features were built to handle. Run it with default DVWA credentials (`admin`/`password`) and no extra flags needed.

---

## 📁 Project Structure

```
web-vuln-scanner/
├── simple_main.py              Entry point (RUN THIS!)
├── auto_scanner.py             Core scanning logic (auto-login, discovery, testing)
├── pdf_report_generator.py      PDF report generation
├── recon_and_scan.sh            Optional: dirb-based endpoint discovery + batch scan
├── dvwa_wordlist.txt            DVWA-specific page names used by recon_and_scan.sh
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
    ├── scan_20260701_103000_482913.json
    ├── vulnerability_report_20260701_103000_482913.pdf
    └── dirb_scan_20260701_103000.txt          (only when using recon_and_scan.sh)
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
- Time-based / blind Command Injection detection
- Out-of-band (DNS/HTTP callback) detection
- Improve payload accuracy for filtered environments (DVWA Medium/High)
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

Unauthorized access to computer systems is illegal under the Computer Fraud and Abuse Act (CFAA) and similar laws worldwide. The in-tool authorization prompt (see [Authorization Gate](#-authorization-gate)) is a reminder, not a substitute for actually having permission.

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

**Last Updated**: 2026-07-13
**Version**: 1.3.0
**Status**: Active Development
