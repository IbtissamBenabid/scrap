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
    incidents = profile.get("security_indicidents", {}) if False else profile.get("security_incidents", {})
    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        st.metric("Data quality", f"{profile.get('data_quality_score', 'N/A')}%")
    with col2:
        st.metric("Breaches", incidents.get("breach_count", 0))
    with col3:
        st.metric("CVEs", incidents.get("cve_count", 0))

    st.divider()

    # Basic information
    st.subheader("Basic Information")
    basic = profile.get("basic_info", {})
    bcol1, bcol2 = st.columns(2)
    with bcol1:
        st.markdown("**Company Name**")
        st.write(basic.get("name", "N/A"))
        st.markdown("**Industry**")
        st.write(basic.get("industry", "N/A"))
        st.markdown("**Sub-services / Offerings**")
        services = basic.get("sub_services", [])
        clean_services = [s.strip() for s in services if s]
        st.write(", ".join(clean_services[:12]) if clean_services else "No structured services found")
    with bcol2:
        st.markdown("**Sector**")
        st.write(basic.get("sector", "N/A"))
        st.markdown("**Employees**")
        st.write(basic.get("employee_count", "N/A"))
        st.markdown("**IT Company**")
        st.write("Yes" if basic.get("is_it_company") else "No")

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

    # Certifications / compliance
    st.subheader("Security & Compliance")
    security = profile.get("security_compliance", {})
    iso_certs = [
        ("ISO 27001", security.get("iso_27001", {}).get("status", "Not Found")),
        ("ISO 27017", security.get("iso_27017", {}).get("status", "Not Found")),
        ("ISO 9001", security.get("iso_9001", {}).get("status", "Not Found")),
    ]
    st.table(pd.DataFrame(iso_certs, columns=["Certification", "Status"]))

    comp_cols = st.columns(4)
    with comp_cols[0]:
        has_soc2 = security.get("soc2_type2") or security.get("soc2_type1")
        soc_type = "Type II" if security.get("soc2_type2") else "Type I" if security.get("soc2_type1") else "N/A"
        st.metric("SOC 2", soc_type if has_soc2 else "Not detected")
    with comp_cols[1]:
        st.metric("PCI-DSS", "Compliant" if security.get("pci_dss") else "Not detected")
    with comp_cols[2]:
        st.metric("HIPAA", "Compliant" if security.get("hipaa_compliant") else "Not detected")
    with comp_cols[3]:
        st.metric("GDPR", "Compliant" if security.get("gdpr_compliant") else "Not detected")

    # Security incidents
    st.subheader("Security Incidents & Vulnerabilities")
    if incidents.get("breach_count", 0) > 0:
        st.warning(f"{incidents.get('breach_count')} breach(es) recorded")
        if incidents.get("last_breach_date"):
            st.write(f"Last breach: {incidents.get('last_breach_date')}")
        breaches = incidents.get("data_breaches", [])
        for i, breach in enumerate(breaches[:5], 1):
            with st.expander(f"Breach {i}"):
                for k, v in breach.items():
                    st.write(f"**{k}**: {v}")
    else:
        st.info("No data breaches recorded")

    cves = incidents.get("cve_vulnerabilities", [])
    if cves:
        cve_rows = []
        for cve in cves[:20]:
            cve_rows.append({
                "CVE ID": cve.get("cve_id", "-"),
                "Severity": cve.get("severity", "-"),
                "CVSS": cve.get("cvss_score", "-"),
                "Patched": "Yes" if cve.get("patched") else "No",
            })
        st.dataframe(pd.DataFrame(cve_rows))
    else:
        st.write("No CVE vulnerabilities recorded")

    # Risk summary
    st.subheader("TPRM Risk Summary")
    quality_score = profile.get("data_quality_score", 0) or 0
    rcol1, rcol2 = st.columns(2)
    with rcol1:
        st.metric("Data Quality Score", f"{quality_score}%")
        st.progress(min(max(int(quality_score), 0), 100) / 100)
    with rcol2:
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
            for r in risks:
                st.write(f"- {r}")
        else:
            st.write("No major risks identified")

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
