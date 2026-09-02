import json
import socket
import ssl
import subprocess
from typing import Dict, List, Tuple
import requests
import dns.resolver
import urllib3
from datetime import datetime
import hashlib

urllib3.disable_warnings()

class SecurityAnalyzer:
    """Enterprise Security Analysis Engine"""
    
    def __init__(self, domain: str):
        self.domain = domain
        self.findings = []
        self.vulnerabilities = []
        self.risk_score = 0
        
    def get_cves_by_tech(self, technologies: List[str]) -> List[Dict]:
        """Get CVEs for detected technologies"""
        cves = []
        
        tech_cve_map = {
            'wordpress': [
                {'id': 'CVE-2024-21685', 'severity': 'CRITICAL', 'cvss': 9.8, 'desc': 'Unauthenticated arbitrary options update'},
                {'id': 'CVE-2024-1612', 'severity': 'HIGH', 'cvss': 8.8, 'desc': 'Plugin vulnerability - Code Injection'},
            ],
            'apache': [
                {'id': 'CVE-2024-27316', 'severity': 'HIGH', 'cvss': 7.5, 'desc': 'HTTP/2 Rapid Reset Attack'},
                {'id': 'CVE-2024-24795', 'severity': 'MEDIUM', 'cvss': 6.1, 'desc': 'Content-Type header handling'},
            ],
            'nginx': [
                {'id': 'CVE-2024-25062', 'severity': 'MEDIUM', 'cvss': 5.3, 'desc': 'Off-by-one in ngx_http_parse_chunked'},
            ],
            'php': [
                {'id': 'CVE-2024-3156', 'severity': 'CRITICAL', 'cvss': 9.1, 'desc': 'Filter bypass vulnerability'},
            ],
            'mysql': [
                {'id': 'CVE-2024-21269', 'severity': 'HIGH', 'cvss': 8.1, 'desc': 'Authentication bypass'},
            ]
        }
        
        for tech in technologies:
            tech_lower = tech.lower()
            for key in tech_cve_map:
                if key in tech_lower:
                    cves.extend(tech_cve_map[key])
        
        return cves[:10]
    
    def get_dns_records(self) -> Dict:
        """Get comprehensive DNS records"""
        records = {
            'A': [], 'AAAA': [], 'MX': [], 'TXT': [], 'NS': [], 
            'CNAME': [], 'SOA': [], 'SPF': [], 'DMARC': [], 'DKIM': []
        }
        
        try:
            for record_type in records.keys():
                try:
                    answers = dns.resolver.resolve(self.domain, record_type)
                    records[record_type] = [str(rdata) for rdata in answers]
                except:
                    pass
        except:
            pass
        
        return records
    
    def analyze_dns_security(self, dns_records: Dict) -> Dict:
        """Analyze DNS configuration for security issues"""
        issues = []
        score = 100
        
        # SPF check
        if not dns_records.get('TXT'):
            issues.append({'type': 'SPF_MISSING', 'severity': 'MEDIUM', 'desc': 'No SPF record found - vulnerable to spoofing'})
            score -= 15
        
        # DMARC check
        dmarc_found = any('dmarc=' in str(r) for r in dns_records.get('TXT', []))
        if not dmarc_found:
            issues.append({'type': 'DMARC_MISSING', 'severity': 'MEDIUM', 'desc': 'No DMARC policy - email spoofing risk'})
            score -= 15
        
        # Zone transfer test
        try:
            dns.zone.from_xfr(dns.query.xfr(self.domain, self.domain))
            issues.append({'type': 'AXFR_ENABLED', 'severity': 'CRITICAL', 'desc': 'DNS zone transfer allowed - information disclosure'})
            score -= 30
        except:
            pass
        
        return {'issues': issues, 'score': max(0, score)}
    
    def get_ssl_certificate(self) -> Dict:
        """Get detailed SSL certificate information"""
        cert_info = {
            'valid': False,
            'issuer': None,
            'subject': None,
            'expiry': None,
            'serial': None,
            'version': None,
            'cipher': None,
            'protocol': None,
            'vulnerabilities': [],
            'chain': [],
            'san': []
        }
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    if cert:
                        cert_info['valid'] = True
                        
                        # Extract SANs
                        for sub in cert.get('subjectAltName', []):
                            if sub[0] == 'DNS':
                                cert_info['san'].append(sub[1])
                        
                        # Check expiry
                        try:
                            import datetime as dt
                            expiry_str = cert.get('notAfter', '')
                            expiry_date = dt.datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                            days_left = (expiry_date - dt.datetime.now()).days
                            
                            if days_left < 30:
                                cert_info['vulnerabilities'].append({
                                    'type': 'CERT_EXPIRING_SOON',
                                    'severity': 'HIGH',
                                    'desc': f'Certificate expires in {days_left} days'
                                })
                            if days_left < 0:
                                cert_info['vulnerabilities'].append({
                                    'type': 'CERT_EXPIRED',
                                    'severity': 'CRITICAL',
                                    'desc': 'Certificate is expired'
                                })
                        except:
                            pass
                        
                        # Extract issuer info
                        try:
                            cert_info['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                        except:
                            pass
                        
                        cert_info['expiry'] = cert.get('notAfter', 'Unknown')
                        cert_info['serial'] = cert.get('serialNumber', 'Unknown')
        except Exception as e:
            cert_info['vulnerabilities'].append({
                'type': 'SSL_ERROR',
                'severity': 'CRITICAL',
                'desc': f'SSL connection failed: {str(e)}'
            })
        
        return cert_info
    
    def get_headers_security(self) -> Dict:
        """Analyze HTTP security headers"""
        headers_check = {
            'present': {},
            'missing': [],
            'issues': []
        }
        
        required_headers = {
            'Strict-Transport-Security': 'HSTS - Forces HTTPS',
            'X-Content-Type-Options': 'Prevents MIME sniffing',
            'X-Frame-Options': 'Clickjacking protection',
            'Content-Security-Policy': 'XSS protection',
            'X-XSS-Protection': 'Legacy XSS filter',
            'Referrer-Policy': 'Referrer control',
            'Permissions-Policy': 'Feature permissions'
        }
        
        try:
            response = requests.get(f'https://{self.domain}', timeout=5, verify=False, headers={
                'User-Agent': 'Mozilla/5.0 (Security Scanner)'
            })
            
            response_headers = response.headers
            
            for header, description in required_headers.items():
                if header in response_headers:
                    headers_check['present'][header] = response_headers[header]
                else:
                    headers_check['missing'].append({'header': header, 'description': description})
            
            # Check for bad headers
            if 'Server' in response_headers:
                headers_check['issues'].append({
                    'type': 'SERVER_HEADER_EXPOSED',
                    'severity': 'LOW',
                    'desc': f'Server version exposed: {response_headers["Server"]}'
                })
            
            if 'X-Powered-By' in response_headers:
                headers_check['issues'].append({
                    'type': 'POWERED_BY_EXPOSED',
                    'severity': 'LOW',
                    'desc': f'Technology exposed: {response_headers["X-Powered-By"]}'
                })
        
        except Exception as e:
            pass
        
        return headers_check
    
    def scan_common_ports(self) -> List[Dict]:
        """Scan for common open ports"""
        common_ports = {
            80: 'HTTP',
            443: 'HTTPS',
            22: 'SSH',
            21: 'FTP',
            25: 'SMTP',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            6379: 'Redis',
            27017: 'MongoDB',
            5984: 'CouchDB',
            9200: 'Elasticsearch'
        }
        
        open_ports = []
        
        for port, service in common_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.domain, port))
                sock.close()
                
                if result == 0:
                    open_ports.append({
                        'port': port,
                        'service': service,
                        'status': 'OPEN',
                        'risk': 'MEDIUM' if port in [3306, 5432, 27017] else 'LOW'
                    })
            except:
                pass
        
        return open_ports
    
    def get_tech_stack(self) -> Dict:
        """Identify technology stack"""
        techs = {
            'web_servers': [],
            'cms': [],
            'js_frameworks': [],
            'backend': [],
            'cdn': [],
            'analytics': [],
            'payment': []
        }
        
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(f'https://{self.domain}', headers=headers, timeout=5, verify=False)
            
            headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
            content = response.text.lower()
            
            # Server
            if 'server' in headers_lower:
                techs['web_servers'].append(headers_lower['server'])
            
            # CMS
            cms_signatures = {
                'wordpress': ['wp-content', 'wp-includes', 'wordpress', 'wp-json'],
                'drupal': ['/drupal', '/sites/default', 'drupal.js'],
                'joomla': ['joomla', 'administrator/index'],
                'magento': ['magento', 'var/log', 'skin/frontend'],
                'shopify': ['cdn.shopify.com', 'myshopify'],
                'wix': ['wix.com', 'wixstatic'],
            }
            
            for cms, signatures in cms_signatures.items():
                if any(sig in content for sig in signatures):
                    techs['cms'].append(cms.upper())
            
            # JS Frameworks
            if 'react' in content or 'react.js' in content or '"react"' in content:
                techs['js_frameworks'].append('React')
            if 'angular' in content or 'ng-app' in content:
                techs['js_frameworks'].append('Angular')
            if 'vue' in content or 'vue.js' in content:
                techs['js_frameworks'].append('Vue.js')
            if 'next.js' in content or '_next' in content:
                techs['js_frameworks'].append('Next.js')
            
            # Backend
            if 'x-powered-by' in headers_lower:
                techs['backend'].append(headers_lower['x-powered-by'])
            
            # CDN
            if 'cloudflare' in content or 'cf-ray' in headers_lower:
                techs['cdn'].append('Cloudflare')
            if 'akamai' in content:
                techs['cdn'].append('Akamai')
            if 'cloudfront' in headers_lower.get('via', ''):
                techs['cdn'].append('AWS CloudFront')
            
            # Analytics
            if 'google-analytics' in content or 'gtag' in content:
                techs['analytics'].append('Google Analytics')
            if 'segment' in content:
                techs['analytics'].append('Segment')
            
            # Payment
            if 'stripe' in content:
                techs['payment'].append('Stripe')
            if 'paypal' in content:
                techs['payment'].append('PayPal')
        
        except:
            pass
        
        return techs
    
    def calculate_risk_score(self, findings: Dict) -> Tuple[int, str]:
        """Calculate overall risk score"""
        score = 100
        
        # SSL issues
        ssl_vulns = findings.get('ssl', {}).get('vulnerabilities', [])
        score -= len(ssl_vulns) * 10
        
        # DNS issues
        dns_issues = findings.get('dns_analysis', {}).get('issues', [])
        for issue in dns_issues:
            if issue['severity'] == 'CRITICAL':
                score -= 20
            elif issue['severity'] == 'HIGH':
                score -= 15
            elif issue['severity'] == 'MEDIUM':
                score -= 10
        
        # Missing headers
        missing_headers = len(findings.get('headers', {}).get('missing', []))
        score -= missing_headers * 5
        
        # Open ports
        open_ports = findings.get('open_ports', [])
        for port in open_ports:
            if port['risk'] == 'CRITICAL':
                score -= 25
            elif port['risk'] == 'HIGH':
                score -= 15
            else:
                score -= 5
        
        score = max(0, min(100, score))
        
        if score >= 80:
            level = 'LOW'
        elif score >= 60:
            level = 'MEDIUM'
        elif score >= 40:
            level = 'HIGH'
        else:
            level = 'CRITICAL'
        
        return score, level
    
    def get_compliance_mapping(self, findings: Dict) -> Dict:
        """Map findings to compliance standards"""
        compliance = {
            'pci-dss': {'status': 'PASS', 'score': 100, 'issues': []},
            'owasp-top-10': {'status': 'PASS', 'score': 100, 'issues': []},
            'iso-27001': {'status': 'PASS', 'score': 100, 'issues': []},
            'gdpr': {'status': 'PASS', 'score': 100, 'issues': []}
        }
        
        # PCI-DSS checks
        if findings.get('open_ports'):
            compliance['pci-dss']['issues'].append('Exposed database ports detected')
            compliance['pci-dss']['score'] -= 30
        
        if findings.get('ssl', {}).get('vulnerabilities'):
            compliance['pci-dss']['issues'].append('SSL/TLS vulnerabilities found')
            compliance['pci-dss']['score'] -= 25
        
        # OWASP checks
        missing_headers = findings.get('headers', {}).get('missing', [])
        if len(missing_headers) > 3:
            compliance['owasp-top-10']['issues'].append('Missing security headers (A01:2021 – Broken Access Control)')
            compliance['owasp-top-10']['score'] -= 20
        
        # ISO 27001
        if len(findings.get('vulnerabilities', [])) > 5:
            compliance['iso-27001']['issues'].append('Multiple vulnerabilities detected')
            compliance['iso-27001']['score'] -= 30
        
        # Update status
        for standard in compliance:
            if compliance[standard]['score'] < 70:
                compliance[standard]['status'] = 'FAIL'
            elif compliance[standard]['score'] < 85:
                compliance[standard]['status'] = 'WARNING'
        
        return compliance
