# 🚀 Quick Start Guide

Get the scanner running in **2 minutes** with one of these methods.

---

## ⚡ Method 1: Automated Setup (Recommended)

### Linux/macOS

```bash
git clone https://github.com/karthi05-kk/web-vuln-scanner.git
cd web-vuln-scanner
bash SETUP.sh
source venv/bin/activate
python3 simple_main.py "http://target.com/page?param=value" --pdf
```

### Windows

```bash
git clone https://github.com/karthi05-kk/web-vuln-scanner.git
cd web-vuln-scanner
SETUP.bat
python simple_main.py "http://target.com/page?param=value" --pdf
```

---

## 🐳 Method 2: Docker (No Installation Required)

```bash
git clone https://github.com/karthi05-kk/web-vuln-scanner.git
cd web-vuln-scanner
docker build -t vuln-scanner .
docker run vuln-scanner "http://target.com/page?param=value" --pdf
```

---

## 📝 Method 3: Manual Setup

### Linux/macOS

```bash
# Clone and navigate
git clone https://github.com/karthi05-kk/web-vuln-scanner.git
cd web-vuln-scanner

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Run scanner
python3 simple_main.py "http://target.com/page?param=value" --pdf
```

### Windows

```bash
# Clone and navigate
git clone https://github.com/karthi05-kk/web-vuln-scanner.git
cd web-vuln-scanner

# Create virtual environment
python -m venv venv
venv\Scripts\activate

# Install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt

# Run scanner
python simple_main.py "http://target.com/page?param=value" --pdf
```

---

## ✅ Verify Installation

```bash
# Check Python version
python3 --version    # Should be 3.8+

# Verify dependencies
python3 -c "import requests, reportlab, urllib3; print('✓ All OK')"

# Get help
python3 simple_main.py -h
```

---

## 🎯 First Scan Example

```bash
# Scan a vulnerable app
python3 simple_main.py "http://localhost/dvwa/vulnerabilities/fi/?page=include.php" --pdf

# Check results
ls -la reports/
cat reports/scan_*.json
```

---

## 📊 Command Options

```bash
# Basic scan (JSON only)
python3 simple_main.py "http://target.com/page?param=value"

# Generate PDF report
python3 simple_main.py "http://target.com/page?param=value" --pdf

# Increase timeout for slow servers
python3 simple_main.py "http://target.com/page?param=value" --timeout 30

# Get help
python3 simple_main.py -h
```

---

## 🚨 Troubleshooting

| Issue | Solution |
|-------|----------|
| `ModuleNotFoundError` | Run: `pip install -r requirements.txt` |
| `Permission denied` | Run: `chmod +x simple_main.py` |
| Scan timeout | Add: `--timeout 30` |
| Reports not found | Run: `mkdir -p reports` |

---

## 📚 Next Steps

1. **Read the full documentation:** See [README.md](README.md)
2. **Setup advanced options:** See [INSTALLATION_GUIDE.md](INSTALLATION_GUIDE.md)
3. **Understand the results:** See [README.md#understanding-results](README.md#-understanding-results)
4. **Fix vulnerabilities:** See [README.md#remediation-guide](README.md#-remediation-guide)

---

**Last Updated:** 2026-07-01
