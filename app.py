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
    page_icon="TPRM",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #0b2c3d;
        text-align: center;
        padding: 1rem 0;
        letter-spacing: 0.05em;
    }
    .sub-header {
        font-size: 1.1rem;
        color: #253238;
        text-align: center;
        margin-bottom: 2rem;
    }
    .section-card {
        background-color: #f9fafb;
        padding: 1rem;
        border-radius: 0.5rem;
        border: 1px solid #e0e7ef;
        margin-bottom: 1rem;
    }
    .info-label {
        font-weight: 600;
        color: #0b2c3d;
        margin-bottom: 0.1rem;
    }
    .info-value {
        color: #1f3a4d;
        margin-bottom: 0.5rem;
    }
</style>
""", unsafe_allow_html=True)


def display_basic_info(profile: dict):
    """Display basic company information"""
    basic = profile.get("basic_info", {})
    contact = profile.get("contact", {})
    social = profile.get("social_media", {})

    st.subheader("Basic Information")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**Company Name**")
        st.write(basic.get("name", "N/A"))
        st.markdown("**Industry**")
        st.write(basic.get("industry", "N/A")[:80] if basic.get("industry") else "N/A")
        st.markdown("**Sub-Services / Offerings**")
        services = basic.get("sub_services", [])[:12]
        clean_services = [s.strip() for s in services if s and len(s) < 120]
        st.write(", ".join(clean_services) if clean_services else "No structured services found")

    with col2:
        st.markdown("**Sector**")
        st.write(basic.get("sector", "N/A"))
        st.markdown("**Employees**")
        st.write(basic.get("employee_count", "N/A"))
        st.markdown("**IT Company**")
        st.write("Yes" if basic.get("is_it_company") else "No")
        st.markdown("**IT Classification**")
        st.write(basic.get("it_classification", "N/A"))

    st.subheader("Contact & Online Presence")

    contact_table = []
    if contact.get("official_website"):
        contact_table.append(("Website", f"[{contact['official_website']}]({contact['official_website']})"))
    if contact.get("email"):
        contact_table.append(("Email", contact['email']))
    if contact.get("phone") and len(contact['phone']) < 20:
        contact_table.append(("Phone", contact['phone']))
    if contact.get("security_contact"):
        contact_table.append(("Security Contact", contact['security_contact']))

    if contact_table:
        st.table(pd.DataFrame(contact_table, columns=["Channel", "Details"]))
    else:
        st.write("No contact or website information detected")

    social_table = []
    if social.get("linkedin"):
        social_table.append(("LinkedIn", social['linkedin']))
    if social.get("twitter"):
        social_table.append(("Twitter", social['twitter']))
    if social.get("github"):
        social_table.append(("GitHub", social['github']))

    if social_table:
        st.write("**Social Profiles**")
        st.table(pd.DataFrame(social_table, columns=["Platform", "URL"]))


def display_certifications(profile: dict):
    """Display security certifications and compliance"""
    security = profile.get("security_compliance", {})
    
    st.subheader("Security & Compliance")
    
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
            "Status": status
        })
    
    df_certs = pd.DataFrame(cert_data)
    st.dataframe(df_certs, width='stretch', hide_index=True)
    
    # Other Compliance
    st.write("**Other Compliance Standards:**")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        has_soc2 = security.get("soc2_type2") or security.get("soc2_type1")
        soc_type = "Type II" if security.get("soc2_type2") else "Type I" if security.get("soc2_type1") else "Not available"
        soc_status = "Compliant" if has_soc2 else "Not detected"
        st.metric("SOC 2", f"{soc_type} ({soc_status})")
    
    with col2:
        pci_status = "Compliant" if security.get("pci_dss") else "Not detected"
        st.metric("PCI-DSS", pci_status)
    
    with col3:
        hipaa_status = "Compliant" if security.get("hipaa_compliant") else "Not detected"
        st.metric("HIPAA", hipaa_status)
    
    with col4:
        gdpr_status = "Compliant" if security.get("gdpr_compliant") else "Not detected"
        st.metric("GDPR", gdpr_status)
    
    # Additional certifications
    other_certs = security.get("other_certifications", [])
    if other_certs:
        st.write("**Additional Certifications:**")
        st.write(", ".join(other_certs))
    
    # Security Practices
    st.write("**Security Practices:**")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        has_sec = "Available" if security.get("has_security_page") else "Not detected"
        st.metric("Security Page", has_sec)
        if security.get("security_page_url"):
            st.markdown(f"[View Page]({security['security_page_url']})")

    with col2:
        has_trust = "Available" if security.get("has_trust_center") else "Not detected"
        st.metric("Trust Center", has_trust)

    with col3:
        has_bounty = "Available" if security.get("has_bug_bounty") else "Not detected"
        st.metric("Bug Bounty", has_bounty)


def display_security_incidents(profile: dict):
    """Display security incidents and vulnerabilities"""
    incidents = profile.get("security_incidents", {})
    
    st.subheader("Security Incidents & Risk")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Data Breaches
        st.write("**Data Breaches:**")
        breach_count = incidents.get("breach_count", 0)

        if breach_count > 0:
            st.warning(f"{breach_count} breach(es) recorded")

            if incidents.get("last_breach_date"):
                st.write(f"Last breach: {incidents['last_breach_date']}")

            if incidents.get("ransomware_history"):
                st.error("Ransomware history detected")

            breaches = incidents.get("data_breaches", [])
            for i, breach in enumerate(breaches[:3], 1):
                with st.expander(f"Breach {i}"):
                    if breach.get("date"):
                        st.write(f"**Date:** {breach['date']}")
                    if breach.get("severity"):
                        st.write(f"**Severity:** {breach['severity']}")
                    if breach.get("records_affected"):
                        st.write(f"**Records:** {breach['records_affected']}")
                    if breach.get("data_types_exposed"):
                        st.write(f"**Data Types:** {', '.join(breach['data_types_exposed'])}")
        else:
            st.info("No data breaches recorded")
    
    with col2:
        # CVE Vulnerabilities
        st.write("**CVE Vulnerabilities:**")
        cve_count = incidents.get("cve_count", 0)
        critical_count = incidents.get("critical_cve_count", 0)

        if cve_count > 0:
            if critical_count > 0:
                st.warning(f"{cve_count} CVE(s) identified ({critical_count} marked critical)")
            else:
                st.info(f"{cve_count} CVE(s) identified")

            cves = incidents.get("cve_vulnerabilities", [])
            if cves:
                cve_data = []
                for cve in cves[:10]:
                    cve_data.append({
                        "CVE ID": cve.get("cve_id", "Unknown"),
                        "Severity": cve.get("severity", "Unknown"),
                        "CVSS": cve.get("cvss_score", "N/A"),
                        "Patched": "Yes" if cve.get("patched") else "No"
                    })
                df_cves = pd.DataFrame(cve_data)
                st.dataframe(df_cves, width='stretch', hide_index=True)
        else:
            st.info("No CVE vulnerabilities recorded")


def display_risk_summary(profile: dict):
    """Display overall risk summary"""
    st.subheader("TPRM Risk Summary")
    
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
            risks.append("Has data breach history")
        if incidents.get("critical_cve_count", 0) > 0:
            risks.append("Has critical CVE vulnerabilities")
        if incidents.get("ransomware_history"):
            risks.append("Has ransomware history")
        if not security.get("iso_27001", {}).get("status"):
            risks.append("Missing ISO 27001 certification")
        if not (security.get("soc2_type2") or security.get("soc2_type1")):
            risks.append("Missing SOC 2 certification")

        if risks:
            st.write("Risk Indicators:")
            for risk in risks:
                st.write(f"- {risk}")
        else:
            st.info("No major risks identified")


def run_research(company_name: str) -> dict:
    """Run the research workflow"""
    with st.spinner(f"Researching {company_name}..."):
        result = run_graph(company_name)
        return result.get("company_profile", {})


def main():
    # Header
    st.markdown('<div class="main-header">TPRM Company Research Agent</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Free Third Party Risk Management research</div>', unsafe_allow_html=True)
    
    # Search bar
    col1, col2 = st.columns([4, 1])
    
    with col1:
        company_name = st.text_input(
            "Enter company name",
            placeholder="e.g., Microsoft, Tesla, Cloudflare...",
            label_visibility="collapsed"
        )
    
    with col2:
        search_button = st.button("Search", type="primary", width='stretch')
    
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
            "Basic Info",
            "Certifications",
            "Security Incidents",
            "Risk Summary"
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
            with st.expander(f"View {len(sources)} sources"):
                for source in sources[:10]:
                    st.markdown(f"- [{source.get('title', 'Unknown')}]({source.get('url', '')})")
        
        # Export option (JSON only, no file save)
        st.divider()
        import json
        st.download_button(
            label="Download JSON Report",
            data=json.dumps(profile, indent=2, default=str),
            file_name=f"{st.session_state.last_search.lower().replace(' ', '_')}_tprm_report.json",
            mime="application/json"
        )
    
    else:
        # Show instructions when no search
        st.info("Enter a company name and click Search to research TPRM information")
        
        st.markdown("""
        ### What this tool extracts:
        
        | Category | Information |
        |----------|-------------|
        | Basic Information | Company name, industry, sector (IT/Non-IT), services |
        | Contact & Online Presence | Website, email, phone, social media |
        | Certifications | ISO 27001, ISO 9001, SOC 2, PCI-DSS, HIPAA, GDPR |
        | Security Incidents | Data breaches, CVE vulnerabilities, ransomware history |
        | Risk Summary | Overall data quality and risk indicators |
        
        ---
        
        Tips:
        - Use the official company name for best results
        - The research combines DuckDuckGo, verified sources and Groq LLM inference
        - Results remain in the app; download JSON if you need an external copy
        """)
    
    # Footer
    st.divider()
    st.caption("100% FREE - Uses DuckDuckGo search + Groq LLM (free tier)")


if __name__ == "__main__":
    main()
