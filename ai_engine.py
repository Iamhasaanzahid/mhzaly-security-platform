import google.generativeai as genai
import json

class AISecurityEngine:
    """Enterprise AI-Powered Security Analysis"""
    
    def __init__(self, api_key: str):
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-pro')
    
    def analyze_risk(self, domain: str, findings: Dict) -> Dict:
        """AI-powered comprehensive risk analysis"""
        
        analysis_data = {
            'domain': domain,
            'risk_metrics': {
                'ssl_score': findings.get('ssl_score', 0),
                'dns_score': findings.get('dns_score', 0),
                'headers_score': findings.get('headers_score', 0),
                'ports_score': findings.get('ports_score', 0),
            },
            'vulnerabilities': len(findings.get('vulnerabilities', [])),
            'open_services': findings.get('services_count', 0),
            'technologies': findings.get('tech_count', 0)
        }
        
        prompt = f"""You are a senior penetration tester and security architect analyzing domain security for enterprise clients.

DOMAIN ANALYSIS DATA:
{json.dumps(analysis_data, indent=2)}

Provide a comprehensive security assessment in STRICT JSON format only:

{{
    "executive_summary": "Brief 2-3 line summary suitable for C-level executives",
    "risk_rating": "CRITICAL|HIGH|MEDIUM|LOW",
    "overall_score": 0-100,
    "key_threats": [
        {{"threat": "...", "impact": "CRITICAL|HIGH|MEDIUM", "likelihood": "HIGH|MEDIUM|LOW", "business_impact": "..."}},
    ],
    "immediate_actions": [
        "Action 1 with urgency level"
    ],
    "30_day_roadmap": [
        "Task 1",
        "Task 2"
    ],
    "bug_bounty_priorities": [
        {{"priority": 1, "target": "...", "technique": "...", "severity": "CRITICAL|HIGH"}},
    ],
    "compliance_gaps": [
        {{"standard": "PCI-DSS", "gap": "...", "fix_effort": "Low|Medium|High"}}
    ],
    "estimated_remediation_cost": "...",
    "industry_comparison": "... compared to industry average ...",
    "attack_scenario": "Most likely attack path in 2-3 sentences",
    "security_recommendations": [
        "Recommendation 1"
    ]
}}

Be specific, technical, and actionable. Focus on real security risks."""
        
        try:
            response = self.model.generate_content(prompt)
            response_text = response.text.strip()
            
            # Clean JSON
            if '```' in response_text:
                response_text = response_text.split('```')[1]
                if response_text.startswith('json'):
                    response_text = response_text[4:]
            
            result = json.loads(response_text.strip())
            return result
        
        except Exception as e:
            return {'error': str(e)}
    
    def generate_penetration_plan(self, domain: str, findings: Dict) -> Dict:
        """Generate penetration testing methodology"""
        
        prompt = f"""You are a penetration testing team lead creating an attack plan for {domain}.

Given these initial findings:
- Open ports: {findings.get('open_ports', [])}
- Technologies: {findings.get('tech_stack', {})}
- SSL status: {findings.get('ssl_valid', False)}
- DNS configuration: {findings.get('dns_issues', [])}

Create a detailed pentest methodology in JSON:

{{
    "phase_1_reconnaissance": [
        {{"step": "...", "tools": ["tool1"], "expected_output": "..."}}
    ],
    "phase_2_scanning": [
        {{"step": "...", "target": "...", "tools": ["nmap", "nuclei"], "expected_output": "..."}}
    ],
    "phase_3_enumeration": [
        {{"step": "...", "focus": "..."}}
    ],
    "phase_4_exploitation": [
        {{"vulnerability": "...", "technique": "...", "impact": "HIGH|MEDIUM", "tools": []}}
    ],
    "likely_vulnerabilities": [
        {{"cve": "CVE-2024-XXXXX", "severity": "CRITICAL", "exploitability": "HIGH"}}
    ],
    "estimated_hours": 0,
    "required_skills": ["skill1"],
    "success_criteria": ["criterion1"]
}}"""
        
        try:
            response = self.model.generate_content(prompt)
            response_text = response.text.strip()
            
            if '```' in response_text:
                response_text = response_text.split('```')[1]
                if response_text.startswith('json'):
                    response_text = response_text[4:]
            
            return json.loads(response_text.strip())
        except:
            return {}
    
    def generate_executive_report(self, domain: str, analysis: Dict) -> str:
        """Generate executive-level report"""
        
        prompt = f"""Generate a professional executive security report for {domain}.

Risk Rating: {analysis.get('risk_rating')}
Overall Score: {analysis.get('overall_score')}/100
Key Threats: {analysis.get('key_threats', [])}

Write a formal 1-page executive summary suitable for board presentation. Include:
1. Risk assessment summary (2 paragraphs)
2. Business impact (1 paragraph)
3. Recommended actions (3-5 bullets)
4. Investment required (cost estimate)

Format as professional business report language."""
        
        try:
            response = self.model.generate_content(prompt)
            return response.text
        except:
            return "Report generation failed"
