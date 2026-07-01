# 🔐 Automatic Web Vulnerability Scanner

**Just enter a URL. Everything else is automatic.**

## Quick Start

```bash
pip3 install -r requirements.txt
python3 simple_main.py "http://172.17.0.1:8080/vulnerabilities/fi/?page=include.php"
cat > README.md << 'ENDOFFILE'
# 🔐 Automatic Web Vulnerability Scanner

**Just enter a URL. Everything else is automatic.**

## Quick Start

```bash
pip3 install -r requirements.txt
python3 simple_main.py "http://172.17.0.1:8080/vulnerabilities/fi/?page=include.php"
cat > requirements.txt << 'ENDOFFILE'
requests==2.31.0
reportlab==4.0.4
urllib3==2.0.4
# web-vuln-scanner
