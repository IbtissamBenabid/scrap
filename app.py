"""
TPRM Company Research Agent - Streamlit Web App
Free Third Party Risk Management company search engine
"""
import streamlit as st
import pandas as pd
from datetime import datetime
import logging
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent.graph import run_graph
from agent.utils.constants import LOG_LEVEL

# Configure logging
logging.basicConfig(level=getattr(logging, LOG_LEVEL))
logger = logging.getLogger(__name__)

# Page configuration
st.set_page_config(
    page_title="TPRM Company Research",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        padding: 1rem 0;
    }
    .sub-header {
        font-size: 1.2rem;
        color: #666;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
    }
    .risk-high {
        background-color: #ffcccb;
        padding: 0.5rem;
        border-radius: 0.3rem;
        border-left: 4px solid #ff0000;
    }
    .risk-medium {
        background-color: #fff3cd;
        padding: 0.5rem;
        border-radius: 0.3rem;
        border-left: 4px solid #ffc107;
    }
    .risk-low {
        background-color: #d4edda;
        padding: 0.5rem;
        border-radius: 0.3rem;
        border-left: 4px solid #28a745;
    }
    .cert-badge {
        display: inline-block;
        padding: 0.25rem 0.5rem;
        margin: 0.2rem;
        border-radius: 0.3rem;
        font-size: 0.85rem;
    }
    .cert-yes {
        background-color: #28a745;
        color: white;
    }
    .cert-no {
        background-color: #6c757d;
        color: white;
    }
</style>
""", unsafe_allow_html=True)


def display_basic_info(profile: dict):
    """Display basic company information"""
    basic = profile.get("basic_info", {})
    contact = profile.get("contact", {})
    social = profile.get("social_media", {})
    
    st.subheader("📋 Basic Information")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Company Name", basic.get("name", "N/A"))
        st.metric("Industry", basic.get("industry", "N/A")[:50] if basic.get("industry") else "N/A")
        
    with col2:
        sector = basic.get("sector", "N/A")
        sector_color = "🟢" if sector == "IT" else "🔵"
        st.metric("Sector", f"{sector_color} {sector}")
        st.metric("Employees", basic.get("employee_count", "N/A"))
        
    with col3:
        is_it = basic.get("is_it_company", False)
        st.metric("IT Company", "✅ Yes" if is_it else "❌ No")
        st.metric("IT Classification", basic.get("it_classification", "N/A"))
    
    # Services
    services = basic.get("sub_services", [])
    if services:
        st.write("**Services/Products:**")
        # Clean up services list
        clean_services = [s for s in services if len(s) < 100 and s.strip()][:10]
        if clean_services:
            st.write(", ".join(clean_services))
    
    # Contact & Social Media
    st.subheader("🌐 Contact & Online Presence")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if contact.get("official_website"):
            st.markdown(f"🔗 **Website:** [{contact['official_website']}]({contact['official_website']})")
        if contact.get("email"):
            st.write(f"📧 **Email:** {contact['email']}")
        if contact.get("phone"):
            phone = contact['phone']
            if len(phone) < 20:  # Only show valid phone numbers
                st.write(f"📞 **Phone:** {phone}")
        if contact.get("security_contact"):
            st.write(f"🔐 **Security Contact:** {contact['security_contact']}")
    
    with col2:
        if social.get("linkedin"):
            st.markdown(f"💼 **LinkedIn:** [{social['linkedin']}]({social['linkedin']})")
        if social.get("twitter"):
            st.markdown(f"🐦 **Twitter:** [{social['twitter']}]({social['twitter']})")
        if social.get("github"):
            st.markdown(f"💻 **GitHub:** [{social['github']}]({social['github']})")


def display_certifications(profile: dict):
    """Display security certifications and compliance"""
    security = profile.get("security_compliance", {})
    
    st.subheader("🔒 Security & Compliance")
    
    # ISO Certifications
    st.write("**ISO Certifications:**")
    
    iso_certs = [
        ("iso_27001", "ISO 27001", "Information Security"),
        ("iso_27017", "ISO 27017", "Cloud Security"),
        ("iso_27018", "ISO 27018", "Cloud Privacy"),
        ("iso_9001", "ISO 9001", "Quality Management"),
        ("iso_14001", "ISO 14001", "Environmental"),
        ("iso_22301", "ISO 22301", "Business Continuity"),
    ]
    
    cert_data = []
    for key, name, desc in iso_certs:
        cert = security.get(key, {})
        if isinstance(cert, dict):
            status = cert.get("status", "Not Found")
        else:
            status = "Not Found"
        cert_data.append({
            "Certification": name,
            "Description": desc,
            "Status": status,
            "✓": "✅" if status in ["Certified", "Mentioned"] else "❌"
        })
    
    df_certs = pd.DataFrame(cert_data)
    st.dataframe(df_certs, width='stretch', hide_index=True)
    
    # Other Compliance
    st.write("**Other Compliance Standards:**")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        soc2 = "✅" if security.get("soc2_type2") or security.get("soc2_type1") else "❌"
        soc_type = "Type II" if security.get("soc2_type2") else "Type I" if security.get("soc2_type1") else "N/A"
        st.metric("SOC 2", f"{soc2} {soc_type}")
    
    with col2:
        pci = "✅" if security.get("pci_dss") else "❌"
        st.metric("PCI-DSS", pci)
    
    with col3:
        hipaa = "✅" if security.get("hipaa_compliant") else "❌"
        st.metric("HIPAA", hipaa)
    
    with col4:
        gdpr = "✅" if security.get("gdpr_compliant") else "❌"
        st.metric("GDPR", gdpr)
    
    # Additional certifications
    other_certs = security.get("other_certifications", [])
    if other_certs:
        st.write("**Additional Certifications:**")
        st.write(", ".join(other_certs))
    
    # Security Practices
    st.write("**Security Practices:**")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        has_sec = "✅" if security.get("has_security_page") else "❌"
        st.metric("Security Page", has_sec)
        if security.get("security_page_url"):
            st.markdown(f"[View Page]({security['security_page_url']})")
    
    with col2:
        has_trust = "✅" if security.get("has_trust_center") else "❌"
        st.metric("Trust Center", has_trust)
    
    with col3:
        has_bounty = "✅" if security.get("has_bug_bounty") else "❌"
        st.metric("Bug Bounty", has_bounty)


def display_security_incidents(profile: dict):
    """Display security incidents and vulnerabilities"""
    incidents = profile.get("security_incidents", {})
    
    st.subheader("⚠️ Security Incidents (Risk Assessment)")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Data Breaches
        st.write("**Data Breaches:**")
        breach_count = incidents.get("breach_count", 0)
        
        if breach_count > 0:
            st.error(f"🚨 {breach_count} breach(es) found!")
            
            if incidents.get("last_breach_date"):
                st.write(f"Last breach: {incidents['last_breach_date']}")
            
            if incidents.get("ransomware_history"):
                st.error("⚠️ RANSOMWARE HISTORY DETECTED")
            
            breaches = incidents.get("data_breaches", [])
            for i, breach in enumerate(breaches[:3], 1):
                with st.expander(f"Breach #{i}"):
                    if breach.get("date"):
                        st.write(f"**Date:** {breach['date']}")
                    if breach.get("severity"):
                        st.write(f"**Severity:** {breach['severity']}")
                    if breach.get("records_affected"):
                        st.write(f"**Records:** {breach['records_affected']}")
                    if breach.get("data_types_exposed"):
                        st.write(f"**Data Types:** {', '.join(breach['data_types_exposed'])}")
        else:
            st.success("✅ No data breaches found")
    
    with col2:
        # CVE Vulnerabilities
        st.write("**CVE Vulnerabilities:**")
        cve_count = incidents.get("cve_count", 0)
        critical_count = incidents.get("critical_cve_count", 0)
        
        if cve_count > 0:
            if critical_count > 0:
                st.error(f"🚨 {cve_count} CVE(s) found ({critical_count} critical)")
            else:
                st.warning(f"⚠️ {cve_count} CVE(s) found")
            
            cves = incidents.get("cve_vulnerabilities", [])
            if cves:
                cve_data = []
                for cve in cves[:10]:
                    cve_data.append({
                        "CVE ID": cve.get("cve_id", "Unknown"),
                        "Severity": cve.get("severity", "Unknown"),
                        "CVSS": cve.get("cvss_score", "N/A"),
                        "Patched": "✅" if cve.get("patched") else "❓"
                    })
                df_cves = pd.DataFrame(cve_data)
                st.dataframe(df_cves, width='stretch', hide_index=True)
        else:
            st.success("✅ No CVE vulnerabilities found")


def display_risk_summary(profile: dict):
    """Display overall risk summary"""
    st.subheader("📊 TPRM Risk Summary")
    
    quality_score = profile.get("data_quality_score", 0)
    incidents = profile.get("security_incidents", {})
    security = profile.get("security_compliance", {})
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Quality Score
        st.metric("Data Quality Score", f"{quality_score}%")
        st.progress(quality_score / 100)
    
    with col2:
        # Risk Indicators
        risks = []
        
        if incidents.get("breach_count", 0) > 0:
            risks.append("🔴 Has data breach history")
        if incidents.get("critical_cve_count", 0) > 0:
            risks.append("🔴 Has critical CVE vulnerabilities")
        if incidents.get("ransomware_history"):
            risks.append("🔴 Has ransomware history")
        if not security.get("iso_27001", {}).get("status"):
            risks.append("🟡 No ISO 27001 certification")
        if not (security.get("soc2_type2") or security.get("soc2_type1")):
            risks.append("🟡 No SOC 2 certification")
        
        if risks:
            st.write("**Risk Indicators:**")
            for risk in risks:
                st.write(risk)
        else:
            st.success("✅ No major risks identified")


def run_research(company_name: str) -> dict:
    """Run the research workflow"""
    with st.spinner(f"🔍 Researching {company_name}..."):
        result = run_graph(company_name)
        return result.get("company_profile", {})


def main():
    # Header
    st.markdown('<div class="main-header">🔍 TPRM Company Research Agent</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Free Third Party Risk Management - Search any company</div>', unsafe_allow_html=True)
    
    # Search bar
    col1, col2 = st.columns([4, 1])
    
    with col1:
        company_name = st.text_input(
            "Enter company name",
            placeholder="e.g., Microsoft, Tesla, Cloudflare...",
            label_visibility="collapsed"
        )
    
    with col2:
        search_button = st.button("🔍 Search", type="primary", width='stretch')
    
    # Store results in session state
    if "search_results" not in st.session_state:
        st.session_state.search_results = None
        st.session_state.last_search = None
    
    # Perform search
    if search_button and company_name:
        st.session_state.search_results = run_research(company_name)
        st.session_state.last_search = company_name
    
    # Display results
    if st.session_state.search_results:
        profile = st.session_state.search_results
        
        st.divider()
        st.markdown(f"### Results for: **{st.session_state.last_search}**")
        st.caption(f"Search completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Tabs for different sections
        tab1, tab2, tab3, tab4 = st.tabs([
            "📋 Basic Info", 
            "🔒 Certifications", 
            "⚠️ Security Incidents",
            "📊 Risk Summary"
        ])
        
        with tab1:
            display_basic_info(profile)
        
        with tab2:
            display_certifications(profile)
        
        with tab3:
            display_security_incidents(profile)
        
        with tab4:
            display_risk_summary(profile)
        
        # Sources
        sources = profile.get("raw_sources", [])
        if sources:
            with st.expander(f"📚 View {len(sources)} Sources"):
                for source in sources[:10]:
                    st.markdown(f"- [{source.get('title', 'Unknown')}]({source.get('url', '')})")
        
        # Export option (JSON only, no file save)
        st.divider()
        import json
        st.download_button(
            label="📥 Download JSON Report",
            data=json.dumps(profile, indent=2, default=str),
            file_name=f"{st.session_state.last_search.lower().replace(' ', '_')}_tprm_report.json",
            mime="application/json"
        )
    
    else:
        # Show instructions when no search
        st.info("👆 Enter a company name and click Search to research TPRM information")
        
        st.markdown("""
        ### What this tool extracts:
        
        | Category | Information |
        |----------|-------------|
        | 📋 **Basic Info** | Company name, industry, sector (IT/Non-IT), services |
        | 🌐 **Contact** | Website, email, phone, social media |
        | 🔒 **Certifications** | ISO 27001, ISO 9001, SOC 2, PCI-DSS, HIPAA, GDPR |
        | ⚠️ **Security** | Data breaches, CVE vulnerabilities, ransomware history |
        | 📊 **Risk Score** | Overall data quality and risk indicators |
        
        ---
        
        **💡 Tips:**
        - Use the official company name for best results
        - The search uses multiple sources (LinkedIn, Wikipedia, security databases)
        - Results are not saved to files - use the download button to export
        """)
    
    # Footer
    st.divider()
    st.caption("🆓 100% FREE - Uses DuckDuckGo search + Groq LLM (free tier)")


if __name__ == "__main__":
    main()
