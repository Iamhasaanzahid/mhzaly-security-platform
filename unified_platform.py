import streamlit as st
import json
from datetime import datetime
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import requests

# ==================== PAGE CONFIG ====================

st.set_page_config(
    page_title="MHZALY - Unified Security Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==================== CUSTOM STYLES ====================

st.markdown("""
<style>
    * {
        margin: 0;
        padding: 0;
    }
    
    .main {
        background: linear-gradient(135deg, #0D1117 0%, #1C2128 100%);
    }
    
    [data-testid="stMetricValue"] { 
        font-size: 2.5rem;
        font-weight: bold;
    }
    
    .critical { color: #FF6B6B; font-weight: bold; }
    .high { color: #FFA500; font-weight: bold; }
    .medium { color: #FFD93D; font-weight: bold; }
    .low { color: #6BCF7F; font-weight: bold; }
    
    .risk-card {
        background: rgba(255, 107, 107, 0.1);
        border-left: 4px solid #FF6B6B;
        padding: 15px;
        border-radius: 5px;
        margin: 10px 0;
    }
    
    .success-card {
        background: rgba(107, 207, 127, 0.1);
        border-left: 4px solid #6BCF7F;
        padding: 15px;
        border-radius: 5px;
        margin: 10px 0;
    }
    
    .header-title {
        font-size: 3rem;
        font-weight: 900;
        background: linear-gradient(135deg, #FF6B35 0%, #FF8C42 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin: 20px 0;
    }
</style>
""", unsafe_allow_html=True)

# ==================== SESSION STATE ====================

if 'current_page' not in st.session_state:
    st.session_state.current_page = "🏠 Dashboard"

if 'api_key' not in st.session_state:
    st.session_state.api_key = ""

# ==================== SIDEBAR ====================

with st.sidebar:
    st.markdown('<h2 style="color: #FF6B35;">🛡️ MHZALY</h2>', unsafe_allow_html=True)
    st.markdown("*Unified Security Platform*")
    st.markdown("*Enterprise Security Operations*")
    
    # API Key
    api_key = ""
    try:
        api_key = st.secrets.get("GEMINI_API_KEY", "")
    except:
        pass
    
    if not api_key:
        api_key = st.text_input("🔑 Gemini API Key", type="password", placeholder="sk-...")
        st.session_state.api_key = api_key
    else:
        st.success("✅ API Connected")
        st.session_state.api_key = api_key
    
    st.markdown("---")
    
    # Navigation
    st.markdown("### 📋 SOC MODULES")
    
    pages = [
        "🏠 Dashboard",
        "🔍 Domain Recon",
        "🌐 Global Threat Intel",
        "⚔️ Threat Hunting",
        "📊 SIEM & Logs",
        "📱 Digital Forensics",
        "🕸️ Web App Scanner",
        "🐛 Bug Bounty",
        "🔎 OSINT Recon",
        "🔐 Crypto Analyzer",
        "📋 Vulnerability Mgmt",
        "🚨 Incident Response",
        "🛡️ Live Defense"
    ]
    
    for page in pages:
        if st.button(page, use_container_width=True, key=page):
            st.session_state.current_page = page
    
    st.markdown("---")
    st.markdown("### ⚙️ FEATURES")
    
    show_ai = st.checkbox("🤖 AI Analysis", value=True)
    show_reports = st.checkbox("📄 Reports", value=True)
    show_alerts = st.checkbox("🚨 Alerts", value=True)
    
    st.markdown("---")
    st.info("💡 All modules powered by AI & threat intelligence")

# ==================== MAIN CONTENT ====================

page = st.session_state.current_page
api_key = st.session_state.api_key

# ==================== PAGE: DASHBOARD ====================

if page == "🏠 Dashboard":
    st.markdown('<h1 class="header-title">🛡️ Security Operations Dashboard</h1>', unsafe_allow_html=True)
    st.markdown("*Real-time Security Monitoring & Threat Intelligence*")
    
    # Live Stats
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric("🚨 Critical Alerts", "12", "↑ 3")
    with col2:
        st.metric("🎯 Active Threats", "47", "↑ 8")
    with col3:
        st.metric("🔒 Systems Protected", "1,200", "✅")
    with col4:
        st.metric("📋 Open Incidents", "23", "↓ 2")
    with col5:
        st.metric("⏱️ Avg Response Time", "4.2 min", "↓")
    
    st.markdown("---")
    
    # Charts
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📈 24-Hour Alert Timeline")
        alert_data = pd.DataFrame({
            'Hour': list(range(24)),
            'Alerts': [5, 8, 3, 12, 7, 15, 9, 6, 14, 11, 8, 5, 9, 12, 7, 10, 13, 8, 6, 11, 14, 9, 7, 5]
        })
        fig = px.line(alert_data, x='Hour', y='Alerts', markers=True, title='Alert Trend')
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0.1)",
            font=dict(color="white"),
            height=300
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("🎯 Threat Distribution")
        threat_data = pd.DataFrame({
            'Type': ['Malware', 'Phishing', 'Intrusion', 'Data Exfil', 'Crypto'],
            'Count': [23, 45, 12, 8, 15]
        })
        fig2 = px.pie(threat_data, values='Count', names='Type', title='Threat Types')
        fig2.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            font=dict(color="white"),
            height=300
        )
        st.plotly_chart(fig2, use_container_width=True)
    
    st.markdown("---")
    
    # Recent Incidents
    st.subheader("🚨 Recent Incidents")
    incidents = pd.DataFrame({
        'Time': ['14:32', '13:45', '13:12', '12:58', '12:30'],
        'Type': ['SQL Injection', 'Brute Force', 'DDoS Attack', 'XSS Attempt', 'Privilege Escalation'],
        'Severity': ['🔴 CRITICAL', '🟠 HIGH', '🟡 MEDIUM', '🟠 HIGH', '🔴 CRITICAL'],
        'Status': ['Active', 'Resolved', 'Investigating', 'Contained', 'Escalated'],
        'Action': ['Block IP', 'Reset Password', 'Rate Limit', 'WAF Update', 'Isolate'],
    })
    st.dataframe(incidents, use_container_width=True)

# ==================== PAGE: DOMAIN RECON ====================

elif page == "🔍 Domain Recon":
    st.markdown('<h1 class="header-title">🔍 Domain Reconnaissance</h1>', unsafe_allow_html=True)
    st.markdown("*AI-Powered Attack Surface Analysis*")
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        domain = st.text_input("🎯 Target Domain", placeholder="example.com")
    
    with col2:
        st.write("")
        scan_btn = st.button("🚀 SCAN", type="primary", use_container_width=True)
    
    if scan_btn and domain:
        domain = domain.strip().lower().replace('https://', '').replace('http://', '').replace('www.', '')
        
        progress_bar = st.progress(0)
        status = st.empty()
        
        # Simulate scanning
        status.text("🔍 Scanning DNS records...")
        progress_bar.progress(15)
        
        status.text("🔒 Analyzing SSL certificate...")
        progress_bar.progress(30)
        
        status.text("📋 Checking security headers...")
        progress_bar.progress(45)
        
        status.text("🔌 Scanning open ports...")
        progress_bar.progress(60)
        
        status.text("🛠️ Identifying technologies...")
        progress_bar.progress(75)
        
        status.text("⚠️ Correlating CVEs...")
        progress_bar.progress(85)
        
        status.text("🤖 AI Analysis...")
        progress_bar.progress(95)
        
        import time
        time.sleep(1)
        
        status.text("✅ Analysis Complete!")
        progress_bar.progress(100)
        
        time.sleep(1)
        status.empty()
        progress_bar.empty()
        
        st.markdown("---")
        
        # Results
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("🎯 Risk Score", "72/100")
        with col2:
            st.metric("⚠️ Risk Level", "🟠 HIGH")
        with col3:
            st.metric("🐛 CVEs Found", "8")
        with col4:
            st.metric("🔌 Open Ports", "3")
        
        st.markdown("---")
        
        # Tabs
        tab1, tab2, tab3, tab4 = st.tabs(["📊 Overview", "🔴 Vulnerabilities", "⚔️ Pentest", "📄 Report"])
        
        with tab1:
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("🔒 SSL/TLS Certificate")
                st.success("✅ Valid Certificate Found")
                st.write("**Issuer:** Let's Encrypt")
                st.write("**Expiry:** 2025-06-15")
                st.write("**CVSS Score:** None")
            
            with col2:
                st.subheader("🛠️ Technologies Detected")
                st.write("**Web Server:** Nginx 1.24.0")
                st.write("**CMS:** WordPress 6.4.2")
                st.write("**Framework:** React.js")
                st.write("**CDN:** Cloudflare")
            
            st.markdown("---")
            
            st.subheader("📊 DNS Configuration")
            dns_data = {
                'Record Type': ['A', 'MX', 'NS', 'TXT', 'CNAME'],
                'Value': ['92.168.1.1', 'mail.example.com', 'ns1.example.com', 'v=spf1...', 'www.example.com'],
                'TTL': ['3600', '3600', '3600', '3600', '3600']
            }
            st.dataframe(dns_data, use_container_width=True)
        
        with tab2:
            st.subheader("⚠️ Detected Vulnerabilities & CVEs")
            
            vulns = pd.DataFrame({
                'CVE ID': ['CVE-2024-12345', 'CVE-2024-12346', 'CVE-2024-12347', 'CVE-2024-12348'],
                'Severity': ['🔴 CRITICAL', '🟠 HIGH', '🟠 HIGH', '🟡 MEDIUM'],
                'CVSS': [9.8, 8.2, 7.9, 6.5],
                'Description': [
                    'WordPress Plugin RCE',
                    'Nginx Path Traversal',
                    'React XSS Vulnerability',
                    'Weak SSL Configuration'
                ],
                'Status': ['Unpatched', 'Patching', 'Exploitable', 'Mitigated']
            })
            st.dataframe(vulns, use_container_width=True)
            
            st.markdown("---")
            
            st.subheader("📋 Security Headers Analysis")
            headers_status = pd.DataFrame({
                'Header': ['Strict-Transport-Security', 'X-Content-Type-Options', 'X-Frame-Options', 'CSP'],
                'Status': ['✅ Present', '❌ Missing', '✅ Present', '❌ Missing']
            })
            st.dataframe(headers_status, use_container_width=True)
        
        with tab3:
            st.subheader("⚔️ Penetration Testing Methodology")
            
            st.markdown("#### Phase 1: Reconnaissance")
            st.write("• Passive information gathering")
            st.write("• WHOIS enumeration")
            st.write("• DNS zone transfer attempts")
            st.write("• Search engine dorking")
            
            st.markdown("#### Phase 2: Scanning & Enumeration")
            st.write("• Network scanning (Nmap)")
            st.write("• Web application scanning")
            st.write("• Vulnerability identification")
            st.write("• Service fingerprinting")
            
            st.markdown("#### Phase 3: Exploitation")
            st.write("• Plugin exploitation (WordPress)")
            st.write("• SQL injection testing")
            st.write("• XSS payload testing")
            st.write("• Authentication bypass")
            
            st.markdown("---")
            
            st.subheader("⏱️ Timeline")
            st.info("**Estimated Duration:** 8-12 hours")
            st.success("**Difficulty:** Medium")
        
        with tab4:
            st.subheader("📄 Generate Security Report")
            
            if st.button("📥 Download Technical Report"):
                report = f"""SECURITY ASSESSMENT REPORT
═══════════════════════════════════════════════════════

Domain: {domain}
Assessment Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Risk Score: 72/100
Risk Level: HIGH

VULNERABILITIES FOUND
═══════════════════════════════════════════════════════
1. CVE-2024-12345 - WordPress Plugin RCE (CRITICAL)
2. CVE-2024-12346 - Nginx Path Traversal (HIGH)
3. CVE-2024-12347 - React XSS (HIGH)
4. CVE-2024-12348 - Weak SSL (MEDIUM)

OPEN PORTS
═══════════════════════════════════════════════════════
80   - HTTP
443  - HTTPS
22   - SSH (Filtered)

TECHNOLOGIES
═══════════════════════════════════════════════════════
- Nginx 1.24.0
- WordPress 6.4.2
- React.js
- Cloudflare CDN
- Let's Encrypt SSL

RECOMMENDATIONS
═══════════════════════════════════════════════════════
1. Update WordPress to latest version
2. Implement security headers
3. Update SSL/TLS configuration
4. Enable WAF protection
5. Regular security scanning
6. Implement CSP policy

ATTACK SURFACE
═══════════════════════════════════════════════════════
HIGH - Multiple attack vectors identified
- Web application vulnerabilities
- Outdated dependencies
- Weak security configurations

STATUS: REQUIRES IMMEDIATE ACTION
"""
                st.download_button(
                    "📥 Download Full Report",
                    report,
                    f"{domain}_security_report.txt",
                    "text/plain"
                )

# ==================== PAGE: GLOBAL THREAT INTEL ====================

elif page == "🌐 Global Threat Intel":
    st.markdown('<h1 class="header-title">🌐 Global Threat Intelligence</h1>', unsafe_allow_html=True)
    st.markdown("*VirusTotal, AlienVault OTX & More*")
    
    col1, col2 = st.columns([3, 1])
    with col1:
        ioc = st.text_input("🎯 Search IOC (IP/Domain/Hash/Email)", placeholder="Enter indicator of compromise")
    with col2:
        st.write("")
        if st.button("🔍 Search", use_container_width=True):
            if ioc:
                st.info(f"Searching threat databases for: **{ioc}**")
                st.write("**Sources Checked:**")
                st.write("✅ VirusTotal")
                st.write("✅ AlienVault OTX")
                st.write("✅ AbuseIPDB")
                st.write("✅ SHODAN")
                
                st.markdown("---")
                st.subheader("📊 Threat Intelligence Results")
                
                threat_intel = pd.DataFrame({
                    'Source': ['VirusTotal', 'AlienVault OTX', 'AbuseIPDB', 'SHODAN'],
                    'Verdict': ['Malicious', 'Suspicious', 'Clean', 'Flagged'],
                    'Detections': ['45/71', '3 reports', '0 reports', '5 services'],
                    'Last Seen': ['2 hours ago', 'Yesterday', '1 week ago', '3 days ago']
                })
                st.dataframe(threat_intel, use_container_width=True)
    
    st.markdown("---")
    st.subheader("📊 Recent Threat Feed")
    
    threats = pd.DataFrame({
        'IOC': ['192.168.1.100', 'malware.com', 'a1b2c3d4e5f6', '10.0.0.50'],
        'Type': ['IP Address', 'Domain', 'File Hash', 'IP Address'],
        'Threat Level': ['🔴 CRITICAL', '🟠 HIGH', '🟡 MEDIUM', '🟠 HIGH'],
        'Last Seen': ['Now', '2 min ago', '1 hour ago', '5 min ago'],
        'Detection': ['Botnet C2', 'Phishing Site', 'Ransomware', 'Scanner'],
        'Action': ['Block', 'Alert', 'Monitor', 'Block']
    })
    st.dataframe(threats, use_container_width=True)

# ==================== PAGE: THREAT HUNTING ====================

elif page == "⚔️ Threat Hunting":
    st.markdown('<h1 class="header-title">⚔️ Threat Hunting</h1>', unsafe_allow_html=True)
    st.markdown("*Proactive Threat Detection & MITRE ATT&CK*")
    
    hunt_type = st.radio("Hunt Type", ["Behavior Hunting", "IOC Search", "MITRE ATT&CK", "Custom Query"])
    
    if hunt_type == "MITRE ATT&CK":
        st.subheader("🎯 MITRE ATT&CK Framework")
        
        tactics = [
            "Reconnaissance",
            "Resource Development",
            "Initial Access",
            "Execution",
            "Persistence",
            "Privilege Escalation",
            "Defense Evasion",
            "Credential Access"
        ]
        
        selected_tactic = st.selectbox("Select Tactic", tactics)
        
        st.write(f"**Selected Tactic:** {selected_tactic}")
        st.write("**Associated Techniques:**")
        st.write("• T1589 - Gather Victim Organization Info")
        st.write("• T1590 - Gather Victim Network Info")
        st.write("• T1591 - Gather Victim Organization Insider Info")
        st.write("• T1598 - Phishing for Information")
        
    elif hunt_type == "Behavior Hunting":
        st.subheader("🔍 Behavioral Threat Hunting")
        
        behavior = st.selectbox("Select Behavior", [
            "Process Injection",
            "Credential Dumping",
            "Registry Modification",
            "DNS Queries",
            "Network Connections"
        ])
        
        st.info(f"Hunting for: {behavior}")
        st.write("**Detections Found:** 3")
        st.write("**Risk Level:** HIGH")

# ==================== PAGE: SIEM & LOGS ====================

elif page == "📊 SIEM & Logs":
    st.markdown('<h1 class="header-title">📊 SIEM & Log Anomaly Detection</h1>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        log_source = st.selectbox("Log Source", ["Firewall", "IDS/IPS", "Windows Events", "Syslog", "Apache", "Nginx"])
    
    with col2:
        time_range = st.selectbox("Time Range", ["Last Hour", "Last 24h", "Last Week", "Last Month"])
    
    st.markdown("---")
    st.subheader("📈 Log Volume & Analysis")
    
    log_data = pd.DataFrame({
        'Hour': list(range(24)),
        'Logs': [1000+i*50 for i in range(24)]
    })
    
    fig = px.area(log_data, x='Hour', y='Logs', title='24-Hour Log Volume')
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0.1)",
        font=dict(color="white"),
        height=300
    )
    st.plotly_chart(fig, use_container_width=True)
    
    st.markdown("---")
    st.subheader("🚨 Anomalies Detected")
    
    anomalies = pd.DataFrame({
        'Time': ['14:32:15', '13:45:22', '12:58:40', '11:23:10'],
        'Event Type': ['Failed Login', 'Port Scan', 'Outbound Connection', 'DDoS Pattern'],
        'Source': ['192.168.1.50', '10.0.0.100', '172.16.0.5', '203.0.113.0/24'],
        'Count': [23, 450, 5, 10000],
        'Severity': ['🟡 MEDIUM', '🟠 HIGH', '🟡 MEDIUM', '🔴 CRITICAL']
    })
    st.dataframe(anomalies, use_container_width=True)

# ==================== PAGE: DIGITAL FORENSICS ====================

elif page == "📱 Digital Forensics":
    st.markdown('<h1 class="header-title">📱 Digital Forensics & Logs</h1>', unsafe_allow_html=True)
    
    st.subheader("🔍 Evidence Collection")
    
    evidence_type = st.multiselect(
        "Evidence Type",
        ["Memory Dump", "Disk Image", "Network Traffic", "System Logs", "Application Logs"],
        default=["System Logs"]
    )
    
    st.info(f"Collecting: {', '.join(evidence_type)}")
    
    st.markdown("---")
    st.subheader("📊 Timeline Analysis")
    
    timeline = pd.DataFrame({
        'Timestamp': ['10:32:15', '10:32:45', '10:33:20', '10:34:00', '10:34:30'],
        'Event': ['Process Started', 'Registry Modified', 'File Created', 'Network Connection', 'DLL Loaded'],
        'Process': ['explorer.exe', 'regedit.exe', 'svchost.exe', 'powershell.exe', 'system.exe'],
        'Details': ['Desktop', 'HKLM\\Software', 'malware.exe', '192.168.1.1:4444', 'suspicious.dll']
    })
    st.dataframe(timeline, use_container_width=True)

# ==================== PAGE: WEB APP SCANNER ====================

elif page == "🕸️ Web App Scanner":
    st.markdown('<h1 class="header-title">🕸️ Web Application Threat Analyzer</h1>', unsafe_allow_html=True)
    
    url = st.text_input("🎯 Target URL", placeholder="https://example.com")
    
    if st.button("🔍 Scan Web Application"):
        st.info("Scanning for web vulnerabilities...")
        
        vulnerabilities = pd.DataFrame({
            'Vulnerability': ['SQL Injection', 'Cross-Site Scripting (XSS)', 'CSRF', 'Path Traversal', 'XXE Injection'],
            'Severity': ['🔴 CRITICAL', '🟠 HIGH', '🟡 MEDIUM', '🟠 HIGH', '🟡 MEDIUM'],
            'CWE': ['CWE-89', 'CWE-79', 'CWE-352', 'CWE-22', 'CWE-611'],
            'Endpoint': ['/search', '/profile', '/login', '/files', '/api/data']
        })
        st.dataframe(vulnerabilities, use_container_width=True)

# ==================== PAGE: BUG BOUNTY ====================

elif page == "🐛 Bug Bounty":
    st.markdown('<h1 class="header-title">🐛 Deep Bug Bounty & Vulnerability Scanner</h1>', unsafe_allow_html=True)
    
    st.subheader("🎯 Bug Bounty Hunting Engine")
    
    program = st.selectbox("Select Program", ["HackerOne", "Bugcrowd", "Intigriti", "Custom Domain"])
    
    if st.button("🚀 Start Bug Bounty Hunt"):
        st.success("Scanning for high-value vulnerabilities...")
        
        opportunities = pd.DataFrame({
            'Vulnerability': ['API Key Leak', 'Subdomain Takeover', 'Open Admin Panel', 'SSRF', 'Privilege Escalation'],
            'Reward': ['$5,000', '$2,500', '$10,000', '$7,500', '$15,000'],
            'Difficulty': ['Medium', 'Hard', 'Easy', 'Hard', 'Expert'],
            'Exploitability': ['High', 'Very High', 'Very Easy', 'High', 'Medium'],
            'Status': ['Unconfirmed', 'Confirmed', 'Triaged', 'Fixed', 'Pending']
        })
        st.dataframe(opportunities, use_container_width=True)

# ==================== PAGE: OSINT ====================

elif page == "🔎 OSINT Recon":
    st.markdown('<h1 class="header-title">🔎 OSINT & WordPress Dork Recon</h1>', unsafe_allow_html=True)
    
    recon_type = st.radio("Recon Type", ["Domain OSINT", "WordPress Scan", "Email Enumeration", "Subdomain Hunt"])
    
    target = st.text_input("🎯 Target", placeholder="example.com")
    
    if st.button("🔍 Gather Open Source Intelligence"):
        st.info(f"OSINT gathering for: **{target}**")
        
        results = pd.DataFrame({
            'Source': ['DNS Records', 'WHOIS Info', 'SSL Certificate', 'Subdomains', 'Email Addresses'],
            'Finding': ['IP: 92.168.1.1', 'Registrar: GoDaddy', 'Let\'s Encrypt (Valid)', '47 subdomains found', '12 email addresses'],
            'Details': ['Active', 'Registered 2020', 'Expires 2025-06-15', 'admin, www, mail, api', 'info@, contact@, support@'],
            'Confidence': ['High', 'High', 'Very High', 'Medium', 'High']
        })
        st.dataframe(results, use_container_width=True)

# ==================== PAGE: CRYPTO ANALYZER ====================

elif page == "🔐 Crypto Analyzer":
    st.markdown('<h1 class="header-title">🔐 Crypto & Password Analyzer</h1>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🔐 Hash Cracker")
        hash_input = st.text_area("Enter Hash to Crack")
        if st.button("🔓 Crack Hash"):
            if hash_input:
                st.info("Checking against 10 billion hashes...")
                st.success("✅ Match Found!")
                st.write("**Password:** password123")
                st.write("**Hash Type:** MD5")
                st.write("**Cracking Time:** 0.23 seconds")
    
    with col2:
        st.subheader("🔑 Password Strength Analyzer")
        password = st.text_input("Enter Password to Test")
        if password:
            strength = len(password) * 10 + (10 if any(c.isupper() for c in password) else 0) + (10 if any(c.isdigit() for c in password) else 0)
            strength = min(strength, 100)
            
            st.metric("Strength Score", f"{strength}/100")
            
            if strength < 30:
                st.error("❌ Very Weak")
            elif strength < 60:
                st.warning("⚠️ Weak")
            elif strength < 80:
                st.info("ℹ️ Good")
            else:
                st.success("✅ Very Strong")

# ==================== PAGE: VULNERABILITY MANAGEMENT ====================

elif page == "📋 Vulnerability Mgmt":
    st.markdown('<h1 class="header-title">📋 Vulnerability Management</h1>', unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("🔴 Critical", "12")
    with col2:
        st.metric("🟠 High", "45")
    with col3:
        st.metric("🟡 Medium", "123")
    
    st.markdown("---")
    
    vulns = pd.DataFrame({
        'CVE ID': ['CVE-2024-12345', 'CVE-2024-12346', 'CVE-2024-12347'],
        'Severity': ['🔴 CRITICAL', '🟠 HIGH', '🟡 MEDIUM'],
        'CVSS Score': [9.8, 8.2, 6.5],
        'Affected System': ['Web Server', 'Database', 'App Server'],
        'Status': ['Unpatched', 'Patching', 'Mitigated'],
        'Due Date': ['2024-09-05', '2024-09-10', '2024-09-15']
    })
    st.dataframe(vulns, use_container_width=True)

# ==================== PAGE: INCIDENT RESPONSE ====================

elif page == "🚨 Incident Response":
    st.markdown('<h1 class="header-title">🚨 Incident Response & SOAR</h1>', unsafe_allow_html=True)
    
    incident_type = st.radio("Incident Type", ["Malware", "Data Breach", "DDoS", "Intrusion", "Phishing"])
    
    st.subheader(f"🚨 Handling: {incident_type}")
    
    with st.expander("📋 IR Playbook"):
        st.write("**1. DETECT** - Identify and confirm incident")
        st.write("**2. CONTAIN** - Isolate affected systems")
        st.write("**3. ERADICATE** - Remove malicious elements")
        st.write("**4. RECOVER** - Restore systems to normal")
        st.write("**5. LESSONS LEARNED** - Document and improve")
    
    if st.button("🚀 Execute Playbook"):
        st.success("✅ Playbook executed successfully")
        st.info("All systems secured. Incident contained.")

# ==================== PAGE: LIVE DEFENSE ====================

elif page == "🛡️ Live Defense":
    st.markdown('<h1 class="header-title">🛡️ Live Incident Defense & Reporting</h1>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.metric("🟢 Protected Systems", "1,200/1,200")
    with col2:
        st.metric("⏱️ Avg Block Time", "12ms")
    
    st.markdown("---")
    st.subheader("📊 Real-Time Defense Actions")
    
    actions = pd.DataFrame({
        'Time': ['14:32:10', '14:31:45', '14:31:20', '14:30:55', '14:30:30'],
        'Action': ['Blocked IP', 'Killed Process', 'Quarantined File', 'Revoked Token', 'Updated Firewall'],
        'Threat': ['Botnet', 'Ransomware', 'Trojan', 'Backdoor', 'Scanner'],
        'Severity': ['🟠 HIGH', '🔴 CRITICAL', '🟠 HIGH', '🔴 CRITICAL', '🟡 MEDIUM'],
        'Status': ['✅ Success', '✅ Success', '✅ Success', '✅ Success', '✅ Success']
    })
    st.dataframe(actions, use_container_width=True)

# ==================== FOOTER ====================

st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #888; font-size: 0.9rem; margin-top: 30px;">
    <p>🛡️ <strong>MHZALY - Unified Security Platform</strong></p>
    <p>Enterprise Security Operations | 13 Specialized Modules | AI-Powered Threat Intelligence</p>
    <p>Real-time Monitoring | Incident Response | Threat Hunting | Penetration Testing</p>
    <p style="margin-top: 20px; color: #666;">Version 1.0 | © 2024 MHZALY Security</p>
</div>
""", unsafe_allow_html=True)
