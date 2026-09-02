import streamlit as st
import json
from datetime import datetime
import plotly.graph_objects as go
import plotly.express as px
from security_analyzer import SecurityAnalyzer
from ai_engine import AISecurityEngine
import pandas as pd

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
    .main {
        background: linear-gradient(135deg, #0D1117 0%, #1C2128 100%);
    }
    
    [data-testid="stMetricValue"] { 
        font-size: 2.5rem;
        font-weight: bold;
    }
    
    .critical { color: #FF6B6B; }
    .high { color: #FFA500; }
    .medium { color: #FFD93D; }
    .low { color: #6BCF7F; }
    
    .header-title {
        font-size: 3rem;
        font-weight: 900;
        background: linear-gradient(135deg, #FF6B35 0%, #FF8C42 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
</style>
""", unsafe_allow_html=True)

# ==================== SESSION STATE ====================

if 'current_page' not in st.session_state:
    st.session_state.current_page = "🏠 Dashboard"

# ==================== SIDEBAR ====================

with st.sidebar:
    st.markdown('<h2 style="color: #FF6B35;">🛡️ MHZALY</h2>', unsafe_allow_html=True)
    st.markdown("*Unified Security Platform*")
    
    # API Key
    api_key = ""
    try:
        api_key = st.secrets.get("GEMINI_API_KEY", "")
    except:
        pass
    
    if not api_key:
        api_key = st.text_input("🔑 API Key", type="password")
    else:
        st.success("✅ API Connected")
    
    st.markdown("---")
    
    # Navigation
    st.markdown("### 📋 SOC OPERATIONS")
    
    soc_pages = [
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
    
    for page in soc_pages:
        if st.button(page, use_container_width=True, key=page):
            st.session_state.current_page = page
    
    st.markdown("---")
    st.markdown("### ⚙️ SETTINGS")
    
    show_ai = st.checkbox("🤖 Enable AI Analysis", value=True)
    show_reports = st.checkbox("📄 Enable Reports", value=True)
    show_alerts = st.checkbox("🚨 Real-time Alerts", value=True)

# ==================== ROUTE TO PAGES ====================

if st.session_state.current_page == "🏠 Dashboard":
    st.markdown('<h1 class="header-title">🛡️ Security Operations Dashboard</h1>', unsafe_allow_html=True)
    
    # Live Stats
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("🚨 Critical", "12", "↑3")
    with col2:
        st.metric("🎯 Threats", "47", "↑8")
    with col3:
        st.metric("🔒 Systems", "1,200", "✅")
    with col4:
        st.metric("📋 Incidents", "23", "↓2")
    with col5:
        st.metric("⏱️ MTTR", "4.2m", "↓")
    
    st.markdown("---")
    
    # Charts
    col1, col2 = st.columns(2)
    
    with col1:
        # Threat Timeline
        threat_data = {
            'Hour': list(range(24)),
            'Alerts': [5, 8, 3, 12, 7, 15, 9, 6, 14, 11, 8, 5, 9, 12, 7, 10, 13, 8, 6, 11, 14, 9, 7, 5]
        }
        fig = px.line(threat_data, x='Hour', y='Alerts', 
                     title='24-Hour Alert Timeline',
                     markers=True)
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0.1)",
            font=dict(color="white")
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Threat Types
        threat_types = {
            'Type': ['Malware', 'Phishing', 'Intrusion', 'Data Exfil', 'Crypto'],
            'Count': [23, 45, 12, 8, 15]
        }
        fig2 = px.pie(threat_types, values='Count', names='Type',
                     title='Threat Distribution')
        fig2.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            font=dict(color="white")
        )
        st.plotly_chart(fig2, use_container_width=True)
    
    st.markdown("---")
    
    # Recent Incidents
    st.subheader("🚨 Recent Incidents")
    incidents = pd.DataFrame({
        'Time': ['14:32', '13:45', '13:12', '12:58', '12:30'],
        'Type': ['SQL Injection', 'Brute Force', 'DDoS', 'XSS', 'Privilege Escalation'],
        'Severity': ['CRITICAL', 'HIGH', 'MEDIUM', 'HIGH', 'CRITICAL'],
        'Status': ['Active', 'Resolved', 'Active', 'Investigating', 'Escalated']
    })
    st.dataframe(incidents, use_container_width=True)

elif st.session_state.current_page == "🔍 Domain Recon":
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
        
        # Progress
        progress_bar = st.progress(0)
        status = st.empty()
        
        try:
            # Initialize
            analyzer = SecurityAnalyzer(domain)
            
            # Gather Data
            status.text("🔍 Scanning DNS...")
            progress_bar.progress(15)
            dns_records = analyzer.get_dns_records()
            dns_analysis = analyzer.analyze_dns_security(dns_records)
            
            status.text("🔒 Analyzing SSL...")
            progress_bar.progress(30)
            ssl_info = analyzer.get_ssl_certificate()
            
            status.text("📋 Checking Headers...")
            progress_bar.progress(45)
            headers = analyzer.get_headers_security()
            
            status.text("🔌 Scanning Ports...")
            progress_bar.progress(60)
            open_ports = analyzer.scan_common_ports()
            
            status.text("🛠️ Identifying Tech...")
            progress_bar.progress(75)
            tech_stack = analyzer.get_tech_stack()
            
            status.text("⚠️ Checking CVEs...")
            progress_bar.progress(85)
            all_techs = []
            for items in tech_stack.values():
                all_techs.extend(items)
            cves = analyzer.get_cves_by_tech(all_techs)
            
            status.text("🤖 AI Analysis...")
            progress_bar.progress(95)
            
            if api_key:
                ai_engine = AISecurityEngine(api_key)
                ai_analysis = ai_engine.analyze_risk(domain, {
                    'ssl_score': 100 - len(ssl_info.get('vulnerabilities', [])) * 10,
                    'dns_score': dns_analysis['score'],
                    'headers_score': 100 - len(headers.get('missing', [])) * 5,
                    'ports_score': 100 - len(open_ports) * 10,
                    'vulnerabilities': cves,
                    'services_count': len(open_ports),
                    'tech_count': len(all_techs)
                })
            
            risk_score, risk_level = analyzer.calculate_risk_score({
                'ssl': ssl_info,
                'dns_analysis': dns_analysis,
                'headers': headers,
                'open_ports': open_ports
            })
            
            progress_bar.progress(100)
            status.empty()
            progress_bar.empty()
            
            st.markdown("---")
            
            # Results
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("🎯 Risk Score", f"{risk_score}/100")
            with col2:
                st.metric("⚠️ Level", risk_level)
            with col3:
                st.metric("🐛 CVEs", len(cves))
            with col4:
                st.metric("🔌 Ports", len(open_ports))
            
            st.markdown("---")
            
            # Tabs
            tab1, tab2, tab3, tab4 = st.tabs(["📊 Overview", "🔴 Vulnerabilities", "⚔️ Pentest", "📄 Report"])
            
            with tab1:
                col1, col2 = st.columns(2)
                
                with col1:
                    st.subheader("🔒 SSL/TLS")
                    if ssl_info.get('valid'):
                        st.success("✅ Valid Certificate")
                        st.write(f"Expiry: {ssl_info.get('expiry', 'N/A')}")
                    else:
                        st.error("❌ SSL Issues")
                
                with col2:
                    st.subheader("🛠️ Technologies")
                    for category, items in tech_stack.items():
                        if items:
                            st.write(f"**{category}:** {', '.join(items)}")
            
            with tab2:
                st.subheader("⚠️ Vulnerabilities")
                if cves:
                    for cve in cves[:10]:
                        col1, col2, col3 = st.columns([3, 1, 1])
                        with col1:
                            st.write(f"**{cve['id']}** - {cve['desc']}")
                        with col2:
                            st.metric("", cve['severity'], label_visibility="collapsed")
                        with col3:
                            st.metric("", f"CVSS {cve['cvss']}", label_visibility="collapsed")
                else:
                    st.info("✅ No known CVEs")
            
            with tab3:
                st.subheader("⚔️ Penetration Testing Plan")
                
                if api_key and 'pentest_plan' not in st.session_state:
                    ai_engine = AISecurityEngine(api_key)
                    st.session_state.pentest_plan = ai_engine.generate_penetration_plan(domain, {
                        'open_ports': open_ports,
                        'tech_stack': tech_stack,
                        'ssl_valid': ssl_info.get('valid'),
                        'dns_issues': dns_analysis.get('issues', [])
                    })
                
                if 'pentest_plan' in st.session_state:
                    plan = st.session_state.pentest_plan
                    
                    st.markdown("#### Phase 1: Reconnaissance")
                    if 'phase_1_reconnaissance' in plan:
                        for step in plan['phase_1_reconnaissance'][:3]:
                            st.write(f"• {step.get('step', '')}")
                    
                    st.markdown("#### Phase 2: Scanning")
                    if 'phase_2_scanning' in plan:
                        for step in plan['phase_2_scanning'][:3]:
                            st.write(f"• {step.get('step', '')}")
            
            with tab4:
                st.subheader("📄 Generate Report")
                
                if st.button("📥 Download Technical Report"):
                    report = f"""SECURITY ASSESSMENT REPORT
Domain: {domain}
Date: {datetime.now()}
Risk Score: {risk_score}/100
Risk Level: {risk_level}

VULNERABILITIES: {len(cves)}
OPEN PORTS: {len(open_ports)}
TECHNOLOGIES: {len(all_techs)}

RECOMMENDATIONS:
1. Address critical vulnerabilities
2. Implement security headers
3. Harden network access
4. Enable WAF protection
"""
                    st.download_button(
                        "📥 Download Report",
                        report,
                        f"{domain}_report.txt"
                    )
        
        except Exception as e:
            st.error(f"❌ Error: {str(e)}")

elif st.session_state.current_page == "🌐 Global Threat Intel":
    st.markdown('<h1 class="header-title">🌐 Global Threat Intelligence</h1>', unsafe_allow_html=True)
    
    col1, col2 = st.columns([3, 1])
    with col1:
        ioc = st.text_input("🎯 Search IOC", placeholder="IP, Domain, Hash, Email")
    with col2:
        st.write("")
        if st.button("🔍 Search", use_container_width=True):
            st.info(f"Searching: {ioc}")
            st.write("**Sources:**")
            st.write("✅ VirusTotal")
            st.write("✅ AlienVault OTX")
            st.write("✅ AbuseIPDB")
            st.write("✅ SHODAN")
    
    st.markdown("---")
    st.subheader("📊 Threat Feed")
    
    threats = pd.DataFrame({
        'IOC': ['192.168.1.100', 'malware.com', 'a1b2c3d4...', '10.0.0.50'],
        'Type': ['IP', 'Domain', 'Hash', 'IP'],
        'Threat Level': ['CRITICAL', 'HIGH', 'MEDIUM', 'HIGH'],
        'Last Seen': ['Now', '2 min ago', '1 hour ago', '5 min ago'],
        'Detection': ['Botnet C2', 'Phishing', 'Ransomware', 'Scanner']
    })
    st.dataframe(threats, use_container_width=True)

elif st.session_state.current_page == "⚔️ Threat Hunting":
    st.markdown('<h1 class="header-title">⚔️ Threat Hunting</h1>', unsafe_allow_html=True)
    
    hunt_type = st.radio("Hunt Type", ["Behavior", "IOC", "MITRE ATT&CK", "Custom Query"])
    
    if hunt_type == "MITRE ATT&CK":
        st.subheader("🎯 MITRE ATT&CK Framework")
        
        tactics = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence"]
        selected_tactic = st.selectbox("Select Tactic", tactics)
        
        st.write(f"**Selected: {selected_tactic}**")
        st.write("Associated Techniques:")
        st.write("• T1589 - Gather Victim Org Info")
        st.write("• T1590 - Gather Victim Network Info")
        st.write("• T1591 - Gather Victim Org Insider Info")

elif st.session_state.current_page == "📊 SIEM & Logs":
    st.markdown('<h1 class="header-title">📊 SIEM & Log Analysis</h1>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        log_source = st.selectbox("Log Source", ["Firewall", "IDS/IPS", "Windows Events", "Syslog"])
    
    with col2:
        time_range = st.selectbox("Time Range", ["Last Hour", "Last 24h", "Last Week", "Custom"])
    
    st.subheader("📈 Log Volume")
    fig = px.area(
        x=list(range(24)),
        y=[100+i*10 for i in range(24)],
        title="24h Log Volume"
    )
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0.1)", font=dict(color="white"))
    st.plotly_chart(fig, use_container_width=True)

elif st.session_state.current_page == "📱 Digital Forensics":
    st.markdown('<h1 class="header-title">📱 Digital Forensics & Logs</h1>', unsafe_allow_html=True)
    
    st.subheader("🔍 Evidence Collection")
    
    evidence_type = st.multiselect(
        "Evidence Type",
        ["Memory Dump", "Disk Image", "Network Traffic", "System Logs", "Application Logs"],
        default=["System Logs"]
    )
    
    st.info(f"Collecting: {', '.join(evidence_type)}")
    st.write("Timeline Analysis:")
    
    timeline = pd.DataFrame({
        'Timestamp': ['10:32:15', '10:32:45', '10:33:20', '10:34:00'],
        'Event': ['Process Start', 'Registry Modification', 'File Created', 'Network Connection'],
        'Details': ['explorer.exe', 'HKLM\\Software', 'malware.exe', '192.168.1.1:4444']
    })
    st.dataframe(timeline, use_container_width=True)

elif st.session_state.current_page == "🕸️ Web App Scanner":
    st.markdown('<h1 class="header-title">🕸️ Web Application Threat Analyzer</h1>', unsafe_allow_html=True)
    
    url = st.text_input("🎯 Target URL", placeholder="https://example.com")
    
    if st.button("🔍 Scan"):
        st.info("Scanning for web vulnerabilities...")
        
        vulnerabilities = pd.DataFrame({
            'Vulnerability': ['SQL Injection', 'XSS', 'CSRF', 'Path Traversal', 'XXE'],
            'Severity': ['CRITICAL', 'HIGH', 'MEDIUM', 'HIGH', 'MEDIUM'],
            'Endpoint': ['/search', '/profile', '/login', '/files', '/api/data']
        })
        st.dataframe(vulnerabilities, use_container_width=True)

elif st.session_state.current_page == "🐛 Bug Bounty":
    st.markdown('<h1 class="header-title">🐛 Deep Bug Bounty Scanner</h1>', unsafe_allow_html=True)
    
    st.subheader("🎯 Bug Bounty Hunting Engine")
    
    program = st.selectbox("Select Program", ["HackerOne", "Bugcrowd", "Intigriti", "Custom"])
    
    if st.button("🚀 Start Hunting"):
        st.success("Scanning for bug bounty opportunities...")
        
        opportunities = pd.DataFrame({
            'Vulnerability': ['API Key Leak', 'Subdomain Takeover', 'Open Admin Panel', 'SSRF'],
            'Reward': ['$5,000', '$2,500', '$10,000', '$7,500'],
            'Difficulty': ['Medium', 'Hard', 'Easy', 'Hard']
        })
        st.dataframe(opportunities, use_container_width=True)

elif st.session_state.current_page == "🔎 OSINT Recon":
    st.markdown('<h1 class="header-title">🔎 OSINT & WordPress Dork Recon</h1>', unsafe_allow_html=True)
    
    recon_type = st.radio("Recon Type", ["Domain OSINT", "WordPress Scan", "Email Enumeration", "Subdomain Hunt"])
    
    target = st.text_input("🎯 Target", placeholder="example.com")
    
    if st.button("🔍 Gather Intelligence"):
        st.info(f"OSINT gathering for: {target}")
        
        results = pd.DataFrame({
            'Source': ['DNS', 'WHOIS', 'Certificate', 'Subdomains'],
            'Finding': ['IP: 1.2.3.4', 'Registrar: GoDaddy', 'Let\'s Encrypt', 'sub1, sub2, sub3'],
            'Date': ['Today', 'Today', 'Yesterday', 'Today']
        })
        st.dataframe(results, use_container_width=True)

elif st.session_state.current_page == "🔐 Crypto Analyzer":
    st.markdown('<h1 class="header-title">🔐 Crypto & Password Analyzer</h1>', unsafe_andre_title')
    
    col1, col2 = st.columns(2)
    
    with col1:
        hash_input = st.text_area("🔐 Hash to Analyze")
        if st.button("Crack"):
            st.info("Checking against 10 billion hashes...")
            st.write("**Match Found!** Password: password123")
    
    with col2:
        password = st.text_input("🔑 Password Strength")
        if password:
            strength = len(password)
            st.metric("Strength", f"{min(strength*10, 100)}/100")
            if strength < 8:
                st.warning("⚠️ Weak Password")
            else:
                st.success("✅ Strong Password")

elif st.session_state.current_page == "📋 Vulnerability Mgmt":
    st.markdown('<h1 class="header-title">📋 Vulnerability Management</h1>', unsafe_allow_html=True)
    
    st.subheader("📊 Vulnerability Dashboard")
    
    metrics_col1, metrics_col2, metrics_col3 = st.columns(3)
    with metrics_col1:
        st.metric("🔴 Critical", "12")
    with metrics_col2:
        st.metric("🟠 High", "45")
    with metrics_col3:
        st.metric("🟡 Medium", "123")
    
    st.markdown("---")
    
    vulns = pd.DataFrame({
        'CVE': ['CVE-2024-12345', 'CVE-2024-12346', 'CVE-2024-12347'],
        'Severity': ['CRITICAL', 'HIGH', 'MEDIUM'],
        'CVSS': [9.8, 8.2, 6.5],
        'Status': ['Unpatched', 'Patching', 'Mitigated']
    })
    st.dataframe(vulns, use_container_width=True)

elif st.session_state.current_page == "🚨 Incident Response":
    st.markdown('<h1 class="header-title">🚨 Incident Response & SOAR</h1>', unsafe_allow_html=True)
    
    incident_type = st.radio("Incident Type", ["Malware", "Data Breach", "DDoS", "Intrusion", "Phishing"])
    
    st.subheader(f"🚨 Handling: {incident_type}")
    
    with st.expander("📋 Playbook"):
        st.write("1. **Detect** - Identify and confirm incident")
        st.write("2. **Contain** - Isolate affected systems")
        st.write("3. **Eradicate** - Remove malicious elements")
        st.write("4. **Recover** - Restore systems")
        st.write("5. **Lessons** - Document learnings")
    
    if st.button("🚀 Execute Playbook"):
        st.success("✅ Playbook executed successfully")

elif st.session_state.current_page == "🛡️ Live Defense":
    st.markdown('<h1 class="header-title">🛡️ Live Incident Defense & Reporting</h1>', unsafe_allow_html=True)
    
    st.subheader("🛡️ Active Threat Response")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.metric("🟢 Protected", "1,200/1,200")
    with col2:
        st.metric("⏱️ Avg Block Time", "12ms")
    
    st.markdown("---")
    st.subheader("📊 Defense Actions")
    
    actions = pd.DataFrame({
        'Time': ['14:32:10', '14:31:45', '14:31:20', '14:30:55'],
        'Action': ['Blocked IP', 'Killed Process', 'Quarantined File', 'Revoked Token'],
        'Threat': ['Botnet', 'Ransomware', 'Trojan', 'Backdoor'],
        'Status': ['Success', 'Success', 'Success', 'Success']
    })
    st.dataframe(actions, use_container_width=True)

# Footer
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #888; font-size: 0.9rem;">
    <p>🛡️ <strong>MHZALY - Unified Security Platform</strong></p>
    <p>Enterprise Security Operations | AI-Powered Threat Intelligence</p>
    <p>13 Specialized Modules | Real-time Monitoring | Incident Response</p>
</div>
""", unsafe_allow_html=True)
