"""
Lightweight Streamlit frontend that calls the FastAPI `/research` endpoint
by default. Set `TPRM_API_URL` to point at your running API (default
`http://localhost:8000`). Set `TPRM_USE_LOCAL=true` to run the local
agent directly instead of the HTTP API.

Usage:
    STREAMLIT: `streamlit run streamlit_frontend.py`

This app preserves the existing API endpoint and only acts as a visualization
layer that can call the endpoint remotely or run the agent locally when needed.
"""
import os
import json
from datetime import datetime

import streamlit as st
import requests
import pandas as pd

from agent.graph import run_graph


API_URL = os.getenv("TPRM_API_URL", "http://localhost:8000")
USE_LOCAL = os.getenv("TPRM_USE_LOCAL", "false").lower() in ("1", "true", "yes")


st.set_page_config(page_title="TPRM Research Viewer", layout="wide")


def call_api(company: str):
    url = f"{API_URL.rstrip('/')}/research"
    payload = {"company": company}
    try:
        resp = requests.post(url, json=payload, timeout=60)
    except Exception as exc:
        return {"error": f"Request failed: {exc}"}

    if resp.status_code != 200:
        try:
            return {"error": resp.json()}
        except Exception:
            return {"error": f"HTTP {resp.status_code}: {resp.text}"}

    return resp.json().get("profile") or resp.json()


def run_local(company: str):
    try:
        result = run_graph(company)
    except Exception as exc:
        return {"error": f"Local agent failed: {exc}"}

    return result.get("company_profile") or result


def display_profile(profile: dict, company: str):
    if not isinstance(profile, dict):
        st.error("No structured profile returned")
        st.write(profile)
        return

    st.header(f"Results — {company}")

    # Top-line metrics
    incidents = profile.get("security_incidents", {})
    breaches_count = len(incidents.get("data_breaches", []))
    cves_count = len(incidents.get("cve_vulnerabilities", []))
    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        st.metric("Company", profile.get('basic_info', {}).get('name', 'N/A'))
    with col2:
        st.metric("Breaches", breaches_count)
    with col3:
        st.metric("CVEs", cves_count)

    st.divider()

    # Basic information - SIMPLIFIED
    st.subheader("Basic Information")
    basic = profile.get("basic_info", {})
    bcol1, bcol2 = st.columns(2)
    with bcol1:
        st.markdown("**Sector**")
        st.write(basic.get("sector", "N/A"))
        st.markdown("**Country**")
        st.write(basic.get("country", "N/A"))
        st.markdown("**Service Type**")
        st.write("IT" if basic.get("is_it_company") else "Non-IT")
    with bcol2:
        st.markdown("**Employees**")
        st.write(basic.get("employee_count", "N/A"))
        st.markdown("**Website**")
        website = profile.get("contact", {}).get("official_website", "N/A")
        st.write(website[:60] + "..." if isinstance(website, str) and len(website) > 60 else website)
        st.markdown("**LinkedIn**")
        linkedin = profile.get("social_media", {}).get("linkedin", "N/A")
        st.write(linkedin[:60] + "..." if isinstance(linkedin, str) and len(linkedin) > 60 else linkedin)

    # Contact
    contact = profile.get("contact", {})
    st.subheader("Contact & Online Presence")
    contact_table = []
    if contact.get("official_website"):
        contact_table.append(("Website", contact["official_website"]))
    if contact.get("email"):
        contact_table.append(("Email", contact["email"]))
    if contact.get("phone") and len(contact["phone"]) < 40:
        contact_table.append(("Phone", contact["phone"]))
    if contact.get("security_contact"):
        contact_table.append(("Security Contact", contact["security_contact"]))

    if contact_table:
        st.table(pd.DataFrame(contact_table, columns=["Channel", "Details"]))
    else:
        st.write("No contact or website information detected")

    # Certifications / compliance - SIMPLIFIED (booleans only)
    st.subheader("Security Certifications")
    security = profile.get("security_compliance", {})
    iso_certs = [
        ("ISO 27001 (Info Security)", "✅" if security.get("iso_27001") else "❌"),
        ("ISO 27017 (Cloud Security)", "✅" if security.get("iso_27017") else "❌"),
        ("ISO 27018 (Cloud Privacy)", "✅" if security.get("iso_27018") else "❌"),
        ("ISO 9001 (Quality)", "✅" if security.get("iso_9001") else "❌"),
    ]
    st.table(pd.DataFrame(iso_certs, columns=["ISO Certification", "Status"]))

    st.subheader("Compliance Standards")
    comp_cols = st.columns(4)
    with comp_cols[0]:
        st.metric("SOC 2", "✅" if security.get("soc2") else "❌")
    with comp_cols[1]:
        st.metric("PCI-DSS", "✅" if security.get("pci_dss") else "❌")
    with comp_cols[2]:
        st.metric("HIPAA", "✅" if security.get("hipaa") else "❌")
    with comp_cols[3]:
        st.metric("GDPR", "✅" if security.get("gdpr_compliant") else "❌")
    
    other_certs = security.get("other_certifications", [])
    if other_certs:
        st.info(f"**Other Certifications:** {', '.join(other_certs)}")

    # Security incidents
    st.subheader("🚨 Security Incidents & Vulnerabilities")
    
    # Data breaches
    breaches = incidents.get("data_breaches", [])
    if breaches:
        st.warning(f"⚠️ {len(breaches)} Data Breach(es) Found")
        for i, breach in enumerate(breaches, 1):
            with st.expander(f"Breach #{i}: {breach.get('affected_entity', 'Unknown')}"):
                st.write(f"**Affected Entity:** {breach.get('affected_entity', 'Unknown')}")
                st.write(f"**Date:** {breach.get('date', 'Unknown date')}")
                st.write(f"**Description:** {breach.get('description', 'No details available')}")
    else:
        st.info("✅ No data breaches recorded")

    # CVEs
    cves = incidents.get("cve_vulnerabilities", [])
    if cves:
        st.warning(f"⚠️ {len(cves)} CVE(s) Found")
        cve_rows = []
        for cve in cves[:20]:
            cve_rows.append({
                "CVE ID": cve.get("cve_id", "-"),
                "Affected Product": cve.get("affected_product", "-"),
                "Description": cve.get("description", "-")[:50] + "..." if len(cve.get("description", "")) > 50 else cve.get("description", "-"),
            })
        st.dataframe(pd.DataFrame(cve_rows), use_container_width=True)
    else:
        st.info("✅ No CVE vulnerabilities recorded")

    # Risk summary (simplified - no scoring)
    st.subheader("Summary")
    rcol1, rcol2, rcol3 = st.columns(3)
    with rcol1:
        breach_count = len(incidents.get("data_breaches", []))
        st.metric("Data Breaches", breach_count)
    with rcol2:
        cve_count = len(incidents.get("cve_vulnerabilities", []))
        st.metric("CVEs Found", cve_count)
    with rcol3:
        # Count certificates
        security = profile.get("security_compliance", {})
        cert_count = sum([
            1 for key in ["iso_27001", "iso_27017", "iso_27018", "iso_9001", 
                          "soc2", "soc1", "pci_dss", "hipaa", "gdpr_compliant", "fedramp"]
            if security.get(key)
        ])
        st.metric("Certifications", cert_count)

    # Sources
    st.subheader("Top Sources")
    sources = profile.get("raw_sources", [])
    if sources:
        for s in sources[:10]:
            title = s.get("title") or s.get("url")
            url = s.get("url", "")
            if url:
                st.markdown(f"- [{title}]({url})")
            else:
                st.write(f"- {title}")
    else:
        st.write("No sources found")


def main():
    st.title("TPRM Research Viewer")
    st.caption("Uses the existing FastAPI endpoint or runs the agent locally.")

    company = st.text_input("Company name", placeholder="e.g., Cloudflare, Microsoft")
    do_search = st.button("Research")

    st.sidebar.markdown("**Settings**")
    st.sidebar.write(f"Using API: {API_URL}")
    st.sidebar.write(f"Use local agent: {USE_LOCAL}")
    if st.sidebar.button("Toggle use-local"):
        st.sidebar.info("To change `TPRM_USE_LOCAL` restart Streamlit with env var set.")

    if do_search and company:
        with st.spinner("Running research..."):
            if USE_LOCAL:
                profile = run_local(company)
            else:
                profile = call_api(company)

        if isinstance(profile, dict) and profile.get("error"):
            st.error(f"Error: {profile.get('error')}" )
        else:
            display_profile(profile, company)

        # Download button
        try:
            st.download_button(
                "Download JSON",
                data=json.dumps(profile, indent=2, default=str),
                file_name=f"{company.lower().replace(' ', '_')}_tprm.json",
                mime="application/json",
            )
        except Exception:
            pass


if __name__ == "__main__":
    main()
