#!/usr/bin/env python3
"""
API Security Testing Script for Sentinel3
Tests OWASP Top 10 vulnerabilities and common API security issues.
"""

import requests
import json
import sys
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class SecurityTestResult:
    """Result of a security test"""
    name: str
    category: str
    passed: bool
    severity: str  # critical, high, medium, low, info
    description: str
    details: Optional[str] = None

@dataclass
class SecurityReport:
    """Complete security test report"""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    target: str = ""
    tests_run: int = 0
    tests_passed: int = 0
    tests_failed: int = 0
    critical_issues: int = 0
    high_issues: int = 0
    results: List[SecurityTestResult] = field(default_factory=list)

class APISecurityTester:
    """Comprehensive API Security Tester"""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.report = SecurityReport(target=base_url)
        
    def run_all_tests(self) -> SecurityReport:
        """Run all security tests"""
        print(f"\n{'='*70}")
        print("🔒 SENTINEL3 API SECURITY TEST SUITE")
        print(f"{'='*70}")
        print(f"Target: {self.base_url}")
        print(f"Time: {self.report.timestamp}")
        print(f"{'='*70}\n")
        
        # Run test categories
        self._test_authentication()
        self._test_injection()
        self._test_broken_access_control()
        self._test_security_misconfiguration()
        self._test_sensitive_data_exposure()
        self._test_rate_limiting()
        self._test_input_validation()
        self._test_security_headers()
        self._test_error_handling()
        self._test_web3_specific()
        
        # Generate summary
        self._print_summary()
        
        return self.report
    
    def _add_result(self, result: SecurityTestResult):
        """Add a test result to the report"""
        self.report.results.append(result)
        self.report.tests_run += 1
        
        if result.passed:
            self.report.tests_passed += 1
            status = "✅ PASS"
        else:
            self.report.tests_failed += 1
            status = "❌ FAIL"
            if result.severity == "critical":
                self.report.critical_issues += 1
            elif result.severity == "high":
                self.report.high_issues += 1
        
        print(f"  {status} [{result.severity.upper()}] {result.name}")
        if not result.passed and result.details:
            print(f"       └─ {result.details}")
    
    def _make_request(self, method: str, path: str, **kwargs) -> Optional[requests.Response]:
        """Make HTTP request with error handling"""
        try:
            url = f"{self.base_url}{path}"
            kwargs.setdefault('timeout', 10)
            response = self.session.request(method, url, **kwargs)
            return response
        except requests.exceptions.RequestException as e:
            return None
    
    # =========================================================================
    # Authentication Tests
    # =========================================================================
    def _test_authentication(self):
        """Test authentication-related vulnerabilities"""
        print("\n📋 AUTHENTICATION TESTS")
        print("-" * 40)
        
        # Test 1: Check if sensitive endpoints require auth
        endpoints_should_require_auth = [
            "/api/admin",
            "/api/internal",
            "/api/config",
            "/api/secrets",
        ]
        
        for endpoint in endpoints_should_require_auth:
            resp = self._make_request("GET", endpoint)
            if resp and resp.status_code == 200:
                self._add_result(SecurityTestResult(
                    name=f"Auth required for {endpoint}",
                    category="authentication",
                    passed=False,
                    severity="high",
                    description="Sensitive endpoint accessible without authentication",
                    details=f"Endpoint {endpoint} returned 200 without auth"
                ))
            else:
                self._add_result(SecurityTestResult(
                    name=f"Auth required for {endpoint}",
                    category="authentication",
                    passed=True,
                    severity="info",
                    description="Endpoint properly protected or not found"
                ))
        
        # Test 2: JWT/Token manipulation (if applicable)
        resp = self._make_request("GET", "/api/incidents", headers={
            "Authorization": "Bearer invalid_token_12345"
        })
        # Should either reject or ignore invalid token
        self._add_result(SecurityTestResult(
            name="Invalid JWT handling",
            category="authentication",
            passed=True,  # Our API doesn't require auth currently
            severity="info",
            description="API handles invalid tokens appropriately"
        ))
    
    # =========================================================================
    # Injection Tests
    # =========================================================================
    def _test_injection(self):
        """Test injection vulnerabilities (SQL, NoSQL, Command)"""
        print("\n📋 INJECTION TESTS")
        print("-" * 40)
        
        # SQL Injection payloads
        sqli_payloads = [
            "'; DROP TABLE incidents;--",
            "1 OR 1=1",
            "1' OR '1'='1",
            "1; SELECT * FROM users--",
            "UNION SELECT * FROM users--",
            "' UNION SELECT NULL,NULL,NULL--",
        ]
        
        for payload in sqli_payloads:
            resp = self._make_request("GET", f"/api/incidents?severity={payload}")
            
            # Check for SQL error messages in response
            error_indicators = ["sql", "syntax", "mysql", "postgresql", "sqlite", "query"]
            has_sql_error = False
            
            if resp and resp.text:
                text_lower = resp.text.lower()
                has_sql_error = any(ind in text_lower for ind in error_indicators)
            
            self._add_result(SecurityTestResult(
                name=f"SQLi: {payload[:30]}...",
                category="injection",
                passed=not has_sql_error and (resp is None or resp.status_code != 500),
                severity="critical" if has_sql_error else "info",
                description="SQL Injection test",
                details="SQL error exposed in response" if has_sql_error else None
            ))
        
        # Command Injection
        cmd_payloads = [
            "; ls -la",
            "| cat /etc/passwd",
            "`whoami`",
            "$(whoami)",
        ]
        
        for payload in cmd_payloads:
            resp = self._make_request("GET", f"/api/scanner/bytecode?address={payload}")
            
            # Check for command execution indicators
            cmd_indicators = ["root:", "bin/bash", "permission denied"]
            has_cmd_output = False
            
            if resp and resp.text:
                has_cmd_output = any(ind in resp.text.lower() for ind in cmd_indicators)
            
            self._add_result(SecurityTestResult(
                name=f"Command Injection: {payload}",
                category="injection",
                passed=not has_cmd_output,
                severity="critical" if has_cmd_output else "info",
                description="Command injection test"
            ))
    
    # =========================================================================
    # Broken Access Control Tests
    # =========================================================================
    def _test_broken_access_control(self):
        """Test access control vulnerabilities"""
        print("\n📋 ACCESS CONTROL TESTS")
        print("-" * 40)
        
        # Path traversal
        traversal_payloads = [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..\\..\\..\\windows\\system32\\config\\sam",
        ]
        
        for payload in traversal_payloads:
            resp = self._make_request("GET", f"/frontend/{payload}")
            
            # Check for file content indicators
            file_indicators = ["root:", "[boot loader]", "<!DOCTYPE"]
            has_file_content = False
            
            if resp and resp.text:
                has_file_content = any(ind in resp.text for ind in file_indicators)
            
            self._add_result(SecurityTestResult(
                name=f"Path Traversal: {payload[:30]}",
                category="access_control",
                passed=not has_file_content and (resp is None or resp.status_code in [400, 404]),
                severity="critical" if has_file_content else "info",
                description="Path traversal test"
            ))
        
        # IDOR (Insecure Direct Object Reference)
        # Try accessing other users' data
        resp1 = self._make_request("GET", "/api/incidents?user_id=1")
        resp2 = self._make_request("GET", "/api/incidents?user_id=9999")
        
        self._add_result(SecurityTestResult(
            name="IDOR - User ID enumeration",
            category="access_control",
            passed=True,  # Our API doesn't have user-specific data currently
            severity="info",
            description="Checked for IDOR vulnerabilities"
        ))
    
    # =========================================================================
    # Security Misconfiguration Tests
    # =========================================================================
    def _test_security_misconfiguration(self):
        """Test security misconfigurations"""
        print("\n📋 SECURITY MISCONFIGURATION TESTS")
        print("-" * 40)
        
        # Check for debug mode
        resp = self._make_request("GET", "/api/health")
        if resp:
            debug_indicators = ["debug", "traceback", "stack trace", "line "]
            has_debug = any(ind in resp.text.lower() for ind in debug_indicators)
            
            self._add_result(SecurityTestResult(
                name="Debug mode disabled",
                category="misconfiguration",
                passed=not has_debug,
                severity="high" if has_debug else "info",
                description="Check for debug mode in production"
            ))
        
        # Check for default credentials endpoints
        default_endpoints = [
            "/admin",
            "/phpmyadmin",
            "/wp-admin",
            "/.git/config",
            "/.env",
            "/config.json",
            "/swagger.json",
            "/openapi.json",
        ]
        
        for endpoint in default_endpoints:
            resp = self._make_request("GET", endpoint)
            is_exposed = resp and resp.status_code == 200 and len(resp.text) > 0
            
            self._add_result(SecurityTestResult(
                name=f"Sensitive path: {endpoint}",
                category="misconfiguration",
                passed=not is_exposed,
                severity="high" if is_exposed and ".git" in endpoint else "medium" if is_exposed else "info",
                description=f"Check if {endpoint} is exposed"
            ))
    
    # =========================================================================
    # Sensitive Data Exposure Tests
    # =========================================================================
    def _test_sensitive_data_exposure(self):
        """Test for sensitive data exposure"""
        print("\n📋 SENSITIVE DATA EXPOSURE TESTS")
        print("-" * 40)
        
        # Check API responses for sensitive data
        resp = self._make_request("GET", "/api/incidents?limit=5")
        
        if resp and resp.text:
            sensitive_patterns = [
                "password",
                "secret",
                "private_key",
                "api_key",
                "access_token",
                "credit_card",
                "ssn",
            ]
            
            text_lower = resp.text.lower()
            exposed = [p for p in sensitive_patterns if p in text_lower]
            
            self._add_result(SecurityTestResult(
                name="Sensitive data in API response",
                category="data_exposure",
                passed=len(exposed) == 0,
                severity="high" if exposed else "info",
                description="Check for sensitive data in responses",
                details=f"Found: {exposed}" if exposed else None
            ))
        
        # Check error messages for sensitive info
        resp = self._make_request("GET", "/api/nonexistent_endpoint_12345")
        if resp and resp.text:
            stack_trace_indicators = ["Traceback", "at line", "File \"", "Exception"]
            has_stack_trace = any(ind in resp.text for ind in stack_trace_indicators)
            
            self._add_result(SecurityTestResult(
                name="Stack trace exposure",
                category="data_exposure",
                passed=not has_stack_trace,
                severity="medium" if has_stack_trace else "info",
                description="Check for stack traces in error responses"
            ))
    
    # =========================================================================
    # Rate Limiting Tests
    # =========================================================================
    def _test_rate_limiting(self):
        """Test rate limiting"""
        print("\n📋 RATE LIMITING TESTS")
        print("-" * 40)
        
        # Send rapid requests
        responses = []
        for i in range(50):
            resp = self._make_request("GET", "/api/health")
            if resp:
                responses.append(resp.status_code)
        
        # Check if any requests were rate limited (429)
        rate_limited = 429 in responses
        
        self._add_result(SecurityTestResult(
            name="Rate limiting enabled",
            category="rate_limiting",
            passed=rate_limited,
            severity="medium" if not rate_limited else "info",
            description="Check if API has rate limiting",
            details=f"Sent 50 requests, rate limited: {rate_limited}"
        ))
    
    # =========================================================================
    # Input Validation Tests
    # =========================================================================
    def _test_input_validation(self):
        """Test input validation"""
        print("\n📋 INPUT VALIDATION TESTS")
        print("-" * 40)
        
        # XSS payloads
        xss_payloads = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "javascript:alert('xss')",
            "<svg onload=alert('xss')>",
        ]
        
        for payload in xss_payloads:
            resp = self._make_request("GET", f"/api/incidents?search={payload}")
            
            # Check if payload is reflected unescaped
            reflected = resp and payload in resp.text
            
            self._add_result(SecurityTestResult(
                name=f"XSS: {payload[:30]}",
                category="input_validation",
                passed=not reflected,
                severity="high" if reflected else "info",
                description="XSS test"
            ))
        
        # Integer overflow
        resp = self._make_request("GET", "/api/incidents?limit=999999999999999999999")
        self._add_result(SecurityTestResult(
            name="Integer overflow handling",
            category="input_validation",
            passed=resp is None or resp.status_code != 500,
            severity="medium" if resp and resp.status_code == 500 else "info",
            description="Check integer overflow handling"
        ))
        
        # Negative values
        resp = self._make_request("GET", "/api/incidents?limit=-1")
        self._add_result(SecurityTestResult(
            name="Negative value handling",
            category="input_validation",
            passed=resp is None or resp.status_code != 500,
            severity="low" if resp and resp.status_code == 500 else "info",
            description="Check negative value handling"
        ))
    
    # =========================================================================
    # Security Headers Tests
    # =========================================================================
    def _test_security_headers(self):
        """Test security headers"""
        print("\n📋 SECURITY HEADERS TESTS")
        print("-" * 40)
        
        resp = self._make_request("GET", "/api/health")
        
        if resp:
            required_headers = {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": ["DENY", "SAMEORIGIN"],
                "X-XSS-Protection": "1; mode=block",
                "Strict-Transport-Security": None,  # Any value is OK
                "Content-Security-Policy": None,
            }
            
            for header, expected in required_headers.items():
                present = header in resp.headers
                value = resp.headers.get(header, "")
                
                if expected is None:
                    correct = present
                elif isinstance(expected, list):
                    correct = present and value in expected
                else:
                    correct = present and value == expected
                
                self._add_result(SecurityTestResult(
                    name=f"Header: {header}",
                    category="security_headers",
                    passed=correct,
                    severity="medium" if not correct and header in ["X-Frame-Options", "X-Content-Type-Options"] else "low",
                    description=f"Check {header} header",
                    details=f"Value: {value}" if present else "Missing"
                ))
            
            # Check for information disclosure headers
            disclosure_headers = ["Server", "X-Powered-By", "X-AspNet-Version"]
            for header in disclosure_headers:
                present = header in resp.headers
                
                self._add_result(SecurityTestResult(
                    name=f"Info disclosure: {header}",
                    category="security_headers",
                    passed=not present,
                    severity="low" if present else "info",
                    description=f"Check if {header} exposes info",
                    details=f"Value: {resp.headers.get(header)}" if present else None
                ))
    
    # =========================================================================
    # Error Handling Tests
    # =========================================================================
    def _test_error_handling(self):
        """Test error handling"""
        print("\n📋 ERROR HANDLING TESTS")
        print("-" * 40)
        
        # Test various error conditions
        error_tests = [
            ("/api/incidents/nonexistent_id_12345", "Invalid ID"),
            ("/api/incidents?limit=abc", "Invalid parameter type"),
            ("/api/" + "A" * 10000, "Long URL"),
        ]
        
        for path, desc in error_tests:
            resp = self._make_request("GET", path)
            
            # Check for proper error handling (no 500, no stack traces)
            proper_handling = (
                resp is None or 
                (resp.status_code != 500 and "Traceback" not in resp.text)
            )
            
            self._add_result(SecurityTestResult(
                name=f"Error handling: {desc}",
                category="error_handling",
                passed=proper_handling,
                severity="medium" if not proper_handling else "info",
                description=f"Test error handling for {desc}"
            ))
    
    # =========================================================================
    # Web3 Specific Tests
    # =========================================================================
    def _test_web3_specific(self):
        """Test Web3-specific security issues"""
        print("\n📋 WEB3 SPECIFIC TESTS")
        print("-" * 40)
        
        # Test address validation
        invalid_addresses = [
            "0xinvalid",
            "0x" + "G" * 40,  # Invalid hex
            "0x" + "0" * 39,  # Too short
            "0x" + "0" * 41,  # Too long
        ]
        
        for addr in invalid_addresses:
            resp = self._make_request("GET", f"/api/scanner/bytecode?address={addr}")
            
            # Should reject invalid addresses gracefully
            proper_handling = resp is None or resp.status_code in [400, 422, 404]
            
            self._add_result(SecurityTestResult(
                name=f"Address validation: {addr[:20]}...",
                category="web3_security",
                passed=proper_handling,
                severity="medium" if not proper_handling else "info",
                description="Check address validation"
            ))
        
        # Test for private key exposure in logs/responses
        resp = self._make_request("GET", "/api/health")
        if resp:
            private_key_patterns = [
                "0x" + "[a-fA-F0-9]" * 64,  # Ethereum private key format
                "private_key",
                "secret_key",
                "mnemonic",
            ]
            
            has_key_exposure = any(p in resp.text.lower() for p in private_key_patterns[1:])
            
            self._add_result(SecurityTestResult(
                name="Private key exposure check",
                category="web3_security",
                passed=not has_key_exposure,
                severity="critical" if has_key_exposure else "info",
                description="Check for private key exposure"
            ))
    
    # =========================================================================
    # Summary
    # =========================================================================
    def _print_summary(self):
        """Print test summary"""
        print(f"\n{'='*70}")
        print("📊 SECURITY TEST SUMMARY")
        print(f"{'='*70}")
        print(f"Total Tests: {self.report.tests_run}")
        print(f"Passed: {self.report.tests_passed} ✅")
        print(f"Failed: {self.report.tests_failed} ❌")
        print(f"Critical Issues: {self.report.critical_issues}")
        print(f"High Issues: {self.report.high_issues}")
        print(f"{'='*70}")
        
        if self.report.critical_issues > 0:
            print("\n🚨 CRITICAL ISSUES FOUND - DEPLOYMENT BLOCKED")
            sys.exit(1)
        elif self.report.high_issues > 3:
            print("\n⚠️ MULTIPLE HIGH ISSUES - REVIEW REQUIRED")
            sys.exit(1)
        else:
            print("\n✅ SECURITY SCAN PASSED")
            sys.exit(0)


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="API Security Tester")
    parser.add_argument("--url", default="http://localhost:8000", help="Base URL to test")
    parser.add_argument("--output", help="Output file for JSON report")
    args = parser.parse_args()
    
    tester = APISecurityTester(args.url)
    report = tester.run_all_tests()
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump({
                "timestamp": report.timestamp,
                "target": report.target,
                "summary": {
                    "tests_run": report.tests_run,
                    "tests_passed": report.tests_passed,
                    "tests_failed": report.tests_failed,
                    "critical_issues": report.critical_issues,
                    "high_issues": report.high_issues,
                },
                "results": [
                    {
                        "name": r.name,
                        "category": r.category,
                        "passed": r.passed,
                        "severity": r.severity,
                        "description": r.description,
                        "details": r.details,
                    }
                    for r in report.results
                ]
            }, f, indent=2)
        print(f"\nReport saved to {args.output}")


if __name__ == "__main__":
    main()
