# 📦 Complete Installation Guide

This guide helps you avoid common setup errors and get the scanner running correctly.

---

## ⚠️ Common Installation Errors & Solutions

### **Error 1: ModuleNotFoundError: No module named 'reportlab'**

**What It Means:**
Python cannot find the required packages. This happens when dependencies aren't installed correctly.

**Quick Fix:**
```bash
pip3 install --upgrade -r requirements.txt
```

**Permanent Fix (Recommended):**
Use a virtual environment to isolate dependencies.

---

## 🛡️ Method 1: Virtual Environment (RECOMMENDED)

Virtual environments prevent conflicts and make setup reproducible.

### Linux/macOS

```bash
# Step 1: Navigate to your project
cd web-vuln-scanner

# Step 2: Create virtual environment
python3 -m venv venv

# Step 3: Activate it
source venv/bin/activate

# Step 4: Upgrade pip
pip install --upgrade pip

# Step 5: Install dependencies
pip install -r requirements.txt

# Step 6: Verify installation
python3 -c "from reportlab.lib.pagesizes import A4; import requests; print('✓ All dependencies installed!')"

# Step 7: Run scanner
python3 simple_main.py "http://target.com/page?param=value" --pdf
```

### Windows

```bash
# Step 1: Navigate to your project
cd web-vuln-scanner

# Step 2: Create virtual environment
python -m venv venv

# Step 3: Activate it
venv\Scripts\activate

# Step 4: Upgrade pip
python -m pip install --upgrade pip

# Step 5: Install dependencies
pip install -r requirements.txt

# Step 6: Verify installation
python -c "from reportlab.lib.pagesizes import A4; import requests; print('✓ All dependencies installed!')"

# Step 7: Run scanner
python simple_main.py "http://target.com/page?param=value" --pdf
```

### Next Time You Use It

Just activate the virtual environment:

```bash
# Linux/macOS
source venv/bin/activate

# Windows
venv\Scripts\activate

# Then run your scanner
python3 simple_main.py "http://target.com/page?param=value" --pdf
```

---

## 🐳 Method 2: Docker (No Dependencies Needed)

Docker is best if you want zero configuration.

### Prerequisites
- [Install Docker](https://docs.docker.com/get-docker/)

### Steps

```bash
# Step 1: Navigate to project
cd web-vuln-scanner

# Step 2: Build Docker image
docker build -t vuln-scanner .

# Step 3: Run scanner
docker run vuln-scanner "http://target.com/page?param=value" --pdf

# Step 4: Extract reports (optional)
docker run -v $(pwd)/reports:/app/reports vuln-scanner "http://target.com/page?param=value" --pdf
```

### Create Dockerfile

If Dockerfile doesn't exist, create one:

```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT ["python3", "simple_main.py"]
```

---

## 📋 Method 3: Direct Installation (Simple)

If you only need basic setup without virtual environment:

```bash
# Step 1: Clone repository
git clone https://github.com/karthi05-kk/web-vuln-scanner.git
cd web-vuln-scanner

# Step 2: Install dependencies globally
pip3 install -r requirements.txt

# Step 3: Run scanner
python3 simple_main.py "http://target.com/page?param=value" --pdf
```

**⚠️ Note:** This installs packages globally. Not recommended for multiple Python projects.

---

## ✅ Dependency Verification Checklist

Before running the scanner, verify everything is installed:

```bash
# Check Python version (must be 3.8+)
python3 --version

# Check if virtual environment is activated (if using one)
which python3

# Verify all required packages
pip3 list | grep -E "requests|reportlab|urllib3"

# Test imports
python3 -c "import requests; import reportlab; import urllib3; print('✓ All packages OK')"

# Verify directory structure
ls -la reports/
```

---

## 🔍 Troubleshooting Installation Issues

### Issue: `pip: command not found`

**Solution:**
```bash
# Use python3 -m pip instead
python3 -m pip install -r requirements.txt
```

### Issue: `ModuleNotFoundError` persists

**Solution:**
```bash
# Clear pip cache and reinstall
pip3 cache purge
pip3 install --force-reinstall --no-cache-dir -r requirements.txt
```

### Issue: Multiple Python versions installed

**Solution:**
```bash
# Check which Python version you're using
python3 --version

# Explicitly use Python 3.9+
python3.9 -m venv venv
python3.9 -m pip install -r requirements.txt
```

### Issue: Permission denied error

**Solution:**
```bash
# Make script executable
chmod +x simple_main.py

# Run with python explicitly
python3 simple_main.py "http://target.com/page?param=value"
```

### Issue: Reports folder missing

**Solution:**
```bash
# Create reports directory
mkdir -p reports
chmod 755 reports
```

---

## 📊 Quick Reference Table

| Method | Setup Time | Best For | Isolation |
|--------|-----------|----------|-----------|
| **Virtual Env** | 2-3 min | Production, Multiple Projects | ✅ Excellent |
| **Docker** | 3-5 min | Clean Environment, CI/CD | ✅ Perfect |
| **Direct Install** | 1 min | Quick Testing | ❌ None |

---

## 🚀 Quick Start (Copy-Paste)

### Linux/macOS with Virtual Environment

```bash
git clone https://github.com/karthi05-kk/web-vuln-scanner.git
cd web-vuln-scanner
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python3 simple_main.py "http://10.37.53.50/dvwa/vulnerabilities/fi/?page=include.php" --pdf
```

### Windows with Virtual Environment

```bash
git clone https://github.com/karthi05-kk/web-vuln-scanner.git
cd web-vuln-scanner
python -m venv venv
venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python simple_main.py "http://10.37.53.50/dvwa/vulnerabilities/fi/?page=include.php" --pdf
```

---

## 📚 Next Steps

After successful installation:

1. **Run a test scan:**
   ```bash
   python3 simple_main.py "http://localhost/dvwa/vulnerabilities/fi/?page=include.php"
   ```

2. **Check results:**
   ```bash
   cat reports/scan_*.json
   ```

3. **Generate PDF report:**
   ```bash
   python3 simple_main.py "http://localhost/dvwa/vulnerabilities/fi/?page=include.php" --pdf
   ```

4. **View help:**
   ```bash
   python3 simple_main.py -h
   ```

---

## 💡 Pro Tips

- **For slow servers:** Add `--timeout 30` to the command
- **For multiple scans:** Save URLs in a file and loop through them
- **For automation:** Use cron jobs or scheduled tasks
- **For security:** Always test on authorized systems only

---

## ❓ Still Having Issues?

1. **Check Python version:** Must be 3.8+
2. **Verify internet connection:** Required for HTTP requests
3. **Check file permissions:** May need `chmod 755 reports`
4. **Review error message:** Read the full traceback carefully
5. **Create a fresh virtual environment:** Sometimes helps reset issues

---

**Last Updated:** 2026-07-01  
**Version:** 1.0.0
