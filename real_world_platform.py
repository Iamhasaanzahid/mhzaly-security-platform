import streamlit as st
import json
from datetime import datetime
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import requests
import dns.resolver
import socket
import ssl
import subprocess
import google.generativeai as genai
import urllib3
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List

urllib3.disable_warnings()

# ==================== PAGE CONFIG ====================

st.set_page_config(
    page_title="MHZALY - Real-World Security Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==================== STYLES ====================

st.markdown("""
<style>
    .main {
        background: linear-gradient(135deg, #0D1117 0%, #1C2128 100%);
    }
    
    [data-testid="stMetricValue"] { 
        font-size: 2.5rem;
        font-weight: bold;
    }
    
    .header-title {
        font-size: 3rem;
        font-weight: 900;
        background: linear-gradient(135deg, #FF6B35 0%, #FF8C42 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
</style>
""", unsafe_allow_html=True)

# ==================== SESSION STATE INITIALIZATION ====================

if 'scan_history' not in st.session_state:
    st.session_state.scan_history = {}
if 'active_domain' not in st.session_state:
    st.session_state.active_domain = ""
if 'active_findings' not in st.session_state:
    st.session_state.active_findings = {}

# ==================== REAL API FUNCTIONS ====================

class RealSecurityScanner:
    """REAL security scanning with concurrent threading and modern API v2.0 endpoints"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        if api_key:
            genai.configure(api_key=api_key)
    
    def real_dns_lookup(self, domain: str) -> Dict:
        """REAL DNS lookup using dnspython"""
        dns_data = {
            'A': [], 'AAAA': [], 'MX': [], 'TXT': [], 'NS': [], 'CNAME': []
        }
        try:
            for record_type in dns_data.keys():
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    dns_data[record_type] = [str(rdata) for rdata in answers]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                    pass
        except Exception as e:
            return {'error': str(e)}
        return dns_data
    
    def real_ssl_check(self, domain: str) -> Dict:
        """REAL SSL certificate check"""
        cert_info = {
            'valid': False,
            'issuer': None,
            'expiry': None,
            'vulnerabilities': []
        }
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        cert_info['valid'] = True
                        try:
                            cert_info['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                        except Exception:
                            pass
                        cert_info['expiry'] = cert.get('notAfter', 'Unknown')
        except (socket.timeout, socket.gaierror, ssl.SSLError) as e:
            cert_info['vulnerabilities'].append(f"SSL Error: {str(e)}")
        return cert_info
    
    def real_port_scan(self, domain: str) -> List[Dict]:
        """REAL concurrent port scanning using ThreadPoolExecutor"""
        common_ports = {
            80: 'HTTP',
            443: 'HTTPS',
            22: 'SSH',
            21: 'FTP',
            25: 'SMTP',
            3306: 'MySQL',
            5432: 'PostgreSQL'
        }
        open_ports = []
        
        def check_port(port, service):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1.5)
                    if sock.connect_ex((domain, port)) == 0:
                        return {'port': port, 'service': service, 'status': 'OPEN'}
            except (socket.timeout, socket.error):
                pass
            return None

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_port, port, svc) for port, svc in common_ports.items()]
            for future in futures:
                res = future.result()
                if res:
                    open_ports.append(res)
                    
        return open_ports
    
    def real_tech_detection(self, domain: str) -> Dict:
        """REAL technology detection via header inspection"""
        techs = {
            'web_servers': [],
            'cms': [],
            'frameworks': [],
            'cdn': []
        }
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(f'https://{domain}', headers=headers, timeout=5, verify=False)
            
            if 'Server' in response.headers:
                techs['web_servers'].append(response.headers['Server'])
            
            content = response.text.lower()
            if 'wordpress' in content or 'wp-content' in content:
                techs['cms'].append('WordPress')
            if 'drupal' in content:
                techs['cms'].append('Drupal')
            if 'joomla' in content:
                techs['cms'].append('Joomla')
            
            if 'react' in content:
                techs['frameworks'].append('React')
            if 'angular' in content:
                techs['frameworks'].append('Angular')
            if 'vue' in content:
                techs['frameworks'].append('Vue.js')
            
            if 'cloudflare' in content or 'cf-ray' in response.headers:
                techs['cdn'].append('Cloudflare')
        except requests.exceptions.RequestException:
            pass
            
        return techs
    
    def real_virustotal_check(self, ioc: str) -> Dict:
        """REAL VirusTotal API check"""
        vt_key = st.secrets.get("VIRUSTOTAL_API_KEY", "")
        if not vt_key:
            return {'error': 'VirusTotal API key not configured'}
        try:
            url = "https://www.virustotal.com/api/v3/search"
            headers = {"x-apikey": vt_key}
            params = {"query": ioc}
            response = requests.get(url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                return {'found': True, 'data': response.json(), 'source': 'VirusTotal'}
            return {'error': 'API Error', 'status': response.status_code}
        except Exception as e:
            return {'error': str(e)}
    
    def real_abuseipdb_check(self, ip: str) -> Dict:
        """REAL AbuseIPDB check"""
        abuseipdb_key = st.secrets.get("ABUSEIPDB_API_KEY", "")
        if not abuseipdb_key:
            return {'error': 'AbuseIPDB API key not configured'}
        try:
            url = 'https://api.abuseipdb.com/api/v2/check'
            headers = {'Key': abuseipdb_key, 'Accept': 'application/json'}
            params = {'ipAddress': ip, 'maxAgeInDays': '90'}
            response = requests.get(url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                return response.json()
            return {'error': 'API Error'}
        except Exception as e:
            return {'error': str(e)}
    
    def real_cve_check(self, technologies: List[str]) -> List[Dict]:
        """REAL CVE lookup from NVD API 2.0"""
        cves = []
        nvd_key = st.secrets.get("NVD_API_KEY", "")
        headers = {"apiKey": nvd_key} if nvd_key else {}
        
        try:
            for tech in technologies:
                url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
                params = {'keywordSearch': tech, 'resultsPerPage': 3}
                response = requests.get(url, headers=headers, params=params, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    for vuln in data.get('vulnerabilities', []):
                        cve_item = vuln.get('cve', {})
                        cve_id = cve_item.get('id', 'Unknown')
                        cves.append({
                            'id': cve_id,
                            'tech': tech,
                            'source': 'NVD API v2.0'
                        })
        except Exception:
            pass
        return cves
    
    def real_subfinder_scan(self, domain: str) -> List[str]:
        """REAL subfinder tool invocation"""
        try:
            result = subprocess.run(
                ['subfinder', '-d', domain, '-silent'],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                return [s for s in result.stdout.strip().split('\n') if s]
        except FileNotFoundError:
            return ['Note: Install subfinder for real subdomain enumeration']
        except Exception:
            pass
        return []
    
    def ai_analysis(self, domain: str, findings: Dict) -> Dict:
        """REAL AI analysis using Gemini 1.5"""
        if not self.api_key:
            return {'error': 'No API key'}
        try:
            model = genai.GenerativeModel('gemini-1.5-flash')
            prompt = f"""Analyze this real security scan data for {domain}:

DNS Records: {json.dumps(findings.get('dns', {}))}
SSL Status: {findings.get('ssl', {}).get('valid', False)}
Open Ports: {findings.get('open_ports', [])}
Technologies: {findings.get('tech_stack', {})}
Subdomains: {len(findings.get('subdomains', []))}

Provide real security assessment in JSON format strictly matching:
{{
    "risk_score": <0-100>,
    "risk_level": "<CRITICAL|HIGH|MEDIUM|LOW>",
    "findings": ["finding1", "finding2"],
    "recommendations": ["rec1", "rec2"]
}}"""
            response = model.generate_content(prompt)
            response_text = response.text.strip()
            if '```' in response_text:
                response_text = response_text.split('```')[1]
                if response_text.startswith('json'):
                    response_text = response_text[4:]
            return json.loads(response_text.strip())
        except Exception as e:
            return {'error': str(e)}

# ==================== SIDEBAR ====================

with st.sidebar:
    st.markdown('<h2 style="color: #FF6B35;">🛡️ MHZALY</h2>', unsafe_allow_html=True)
    st.markdown("*Real-World Security Platform*")
    
    api_key = ""
    try:
        api_key = st.secrets.get("GEMINI_API_KEY", "")
    except Exception:
        pass
    
    if not api_key:
        api_key = st.text_input("🔑 Gemini API", type="password")
    else:
        st.success("✅ AI Configured")
    
    vt_key = st.secrets.get("VIRUSTOTAL_API_KEY", "")
    if vt_key:
        st.success("✅ VirusTotal Ready")
    else:
        st.warning("⚠️ VirusTotal not configured")
        
    nvd_key = st.secrets.get("NVD_API_KEY", "")
    if nvd_key:
        st.success("✅ NVD API v2 Ready")
    else:
        st.info("ℹ️ NVD API v2 Unauthenticated")
    
    st.markdown("---")
    
    page = st.radio("Module", [
        "🏠 Dashboard",
        "🔍 Domain Scan",
        "🌐 Threat Intel",
        "🐛 Vulnerabilities",
        "📊 Logs & SIEM"
    ])

# ==================== MAIN LOGIC ====================

scanner = RealSecurityScanner(api_key)

if page == "🏠 Dashboard":
    st.markdown('<h1 class="header-title">🛡️ Security Operations</h1>', unsafe_allow_html=True)
    
    # Real-world telemetry derived dynamically from session state scan history
    total_scans = len(st.session_state.scan_history)
    total_open_ports = sum(len(data.get('open_ports', [])) for data in st.session_state.scan_history.values())
    critical_count = sum(
        1 for data in st.session_state.scan_history.values() 
        if data.get('ai_result', {}).get('risk_level') == 'CRITICAL'
    )
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("🚨 Critical Risks", critical_count)
    with col2:
        st.metric("🔌 Total Open Ports", total_open_ports)
    with col3:
        st.metric("🌐 Domains Scanned", total_scans)
        
    if st.session_state.active_domain:
        st.markdown("---")
        st.subheader(f"⚡ Last Active Target: {st.session_state.active_domain}")
        res = st.session_state.scan_history.get(st.session_state.active_domain, {})
        if res:
            col_a, col_b = st.columns(2)
            with col_a:
                st.metric("Cached Risk Score", res.get('ai_result', {}).get('risk_score', 'N/A'))
            with col_b:
                st.metric("Open Ports Found", len(res.get('open_ports', [])))

elif page == "🔍 Domain Scan":
    st.markdown('<h1 class="header-title">🔍 Real Domain Reconnaissance</h1>', unsafe_allow_html=True)
    
    col1, col2 = st.columns([3, 1])
    with col1:
        domain = st.text_input("Target Domain", value=st.session_state.active_domain, placeholder="example.com")
    with col2:
        st.write("")
        scan = st.button("🚀 SCAN", type="primary", use_container_width=True)
    
    if scan and domain:
        domain = domain.strip().lower().replace('https://', '').replace('http://', '').replace('www.', '')
        st.session_state.active_domain = domain
        
        progress = st.progress(0)
        status = st.empty()
        
        status.text("🔍 Real DNS Lookup...")
        progress.progress(20)
        dns_data = scanner.real_dns_lookup(domain)
        
        status.text("🔒 Real SSL Check...")
        progress.progress(40)
        ssl_data = scanner.real_ssl_check(domain)
        
        status.text("🔌 Concurrent Port Scan...")
        progress.progress(60)
        ports = scanner.real_port_scan(domain)
        
        status.text("🛠️ Real Tech Detection...")
        progress.progress(80)
        techs = scanner.real_tech_detection(domain)
        
        status.text("📍 Real Subdomain Scan...")
        progress.progress(90)
        subdomains = scanner.real_subfinder_scan(domain)
        
        status.text("🤖 AI Analysis...")
        progress.progress(95)
        
        findings = {
            'dns': dns_data,
            'ssl': ssl_data,
            'open_ports': ports,
            'tech_stack': techs,
            'subdomains': subdomains
        }
        
        ai_result = scanner.ai_analysis(domain, findings)
        
        # Save to session state history
        st.session_state.scan_history[domain] = {
            'findings': findings,
            'ai_result': ai_result,
            'open_ports': ports
        }
        st.session_state.active_findings = findings
        
        progress.progress(100)
        status.empty()

    # Render results from session state if available for active domain
    target_domain = st.session_state.active_domain
    if target_domain and target_domain in st.session_state.scan_history:
        history_data = st.session_state.scan_history[target_domain]
        findings = history_data['findings']
        ai_result = history_data['ai_result']
        ports = history_data['open_ports']
        
        st.markdown("---")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("🎯 Risk Score", ai_result.get('risk_score', 'N/A'))
        with col2:
            st.metric("⚠️ Level", ai_result.get('risk_level', 'N/A'))
        with col3:
            st.metric("🔌 Open Ports", len(ports))
        
        st.markdown("---")
        st.subheader("🌐 DNS Records (REAL)")
        for record_type, values in findings['dns'].items():
            if values:
                st.write(f"**{record_type}:**")
                for value in values:
                    st.code(value)
        
        st.subheader("🔒 SSL Certificate (REAL)")
        if findings['ssl'].get('valid'):
            st.success("✅ Valid SSL")
            st.write(f"Expiry: {findings['ssl'].get('expiry')}")
        else:
            st.error("❌ SSL Issues")
        
        if ports:
            st.subheader("🔌 Open Ports (REAL)")
            st.dataframe(pd.DataFrame(ports), use_container_width=True)
        
        techs = findings['tech_stack']
        if any(techs.values()):
            st.subheader("🛠️ Technologies (REAL)")
            for category, items in techs.items():
                if items:
                    st.write(f"**{category}:** {', '.join(items)}")
        
        subdomains = findings['subdomains']
        if subdomains:
            st.subheader("📍 Subdomains (REAL)")
            st.dataframe(pd.DataFrame({'Subdomain': subdomains}), use_container_width=True)
            st.download_button(
                "📥 Download Subdomains",
                '\n'.join(subdomains),
                f"{target_domain}_subdomains.txt"
            )
        
        if not ai_result.get('error'):
            st.subheader("🤖 AI Assessment")
            st.write(f"**Risk Score:** {ai_result.get('risk_score')}/100")
            st.write(f"**Level:** {ai_result.get('risk_level')}")
            st.write("**Findings:**")
            for finding in ai_result.get('findings', []):
                st.write(f"• {finding}")
            st.write("**Recommendations:**")
            for rec in ai_result.get('recommendations', []):
                st.write(f"• {rec}")

elif page == "🌐 Threat Intel":
    st.markdown('<h1 class="header-title">🌐 Real Threat Intelligence</h1>', unsafe_allow_html=True)
    ioc = st.text_input("Search IOC (IP/Domain/Hash)")
    
    if st.button("🔍 Check Real Threat Feeds"):
        if ioc:
            st.info(f"Checking: {ioc}")
            vt_result = scanner.real_virustotal_check(ioc)
            if not vt_result.get('error'):
                st.success("✅ VirusTotal Data Found")
                st.json(vt_result)
            else:
                st.warning(f"VirusTotal: {vt_result.get('error')}")
            
            if ioc.replace('.', '').isdigit():
                abuseip_result = scanner.real_abuseipdb_check(ioc)
                if not abuseip_result.get('error'):
                    st.success("✅ AbuseIPDB Data Found")
                    st.json(abuseip_result)

elif page == "🐛 Vulnerabilities":
    st.markdown('<h1 class="header-title">🐛 Real NVD CVE Lookup (API v2.0)</h1>', unsafe_allow_html=True)
    techs = st.text_input("Technologies to check (comma-separated)", placeholder="wordpress, nginx, php")
    
    if st.button("🔍 Check Real CVEs"):
        if techs:
            tech_list = [t.strip() for t in techs.split(',')]
            st.info(f"Checking NVD for: {', '.join(tech_list)}")
            cves = scanner.real_cve_check(tech_list)
            
            if cves:
                st.success(f"Found {len(cves)} CVEs via NVD API v2.0")
                st.dataframe(pd.DataFrame(cves), use_container_width=True)
            else:
                st.info("No CVEs found or API rate limited")

elif page == "📊 Logs & SIEM":
    st.markdown('<h1 class="header-title">📊 Log Analysis</h1>', unsafe_allow_html=True)
    st.info("📝 Upload logs from your SIEM or infrastructure")
    uploaded_file = st.file_uploader("Upload log file", type=['txt', 'log', 'csv', 'json'])
    
    if uploaded_file:
        st.success("✅ File loaded")
        content = uploaded_file.read().decode()
        st.text_area("Log Preview", content[:500], height=200)

st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #888;">
    <p>🛡️ MHZALY - Real-World Security Platform</p>
    <p>Concurrent Scans | NVD v2.0 | Persistent State</p>
</div>
""", unsafe_allow_html=True)
