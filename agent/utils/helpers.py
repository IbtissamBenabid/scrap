"""
Helper utilities for scraping agent
"""
import re
import json
import random
import time
import hashlib
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin
from pathlib import Path
from typing import Optional
import logging

from .constants import USER_AGENTS, SKIP_DOMAINS, PRIORITY_DOMAINS, OUTPUT_DIR

logger = logging.getLogger(__name__)


def get_random_user_agent() -> str:
    """Get a random user agent string"""
    return random.choice(USER_AGENTS)


def get_headers() -> dict:
    """Get headers for HTTP requests"""
    return {
        "User-Agent": get_random_user_agent(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Cache-Control": "max-age=0",
    }


def extract_domain(url: str) -> str:
    """Extract domain from URL"""
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower().replace("www.", "")
    except Exception:
        return ""


def is_valid_url(url: str) -> bool:
    """Check if URL is valid"""
    try:
        result = urlparse(url)
        return all([result.scheme in ["http", "https"], result.netloc])
    except Exception:
        return False


def should_skip_url(url: str) -> bool:
    """Check if URL should be skipped"""
    domain = extract_domain(url)
    for skip_domain in SKIP_DOMAINS:
        if skip_domain in domain:
            return True
    return False


def get_domain_priority(url: str) -> int:
    """Get priority score for domain (higher = better)"""
    domain = extract_domain(url)
    for i, priority_domain in enumerate(PRIORITY_DOMAINS):
        if priority_domain in domain:
            return len(PRIORITY_DOMAINS) - i
    return 0


def sort_urls_by_priority(urls: list[str]) -> list[str]:
    """Sort URLs by domain priority"""
    return sorted(urls, key=get_domain_priority, reverse=True)


def clean_text(text: str) -> str:
    """Clean extracted text"""
    if not text:
        return ""
    text = re.sub(r'\s+', ' ', text)
    text = re.sub(r'[^\w\s.,;:!?@#$%&*()\'"-/]', '', text)
    return text.strip()


def extract_emails(text: str) -> list[str]:
    """Extract email addresses from text"""
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    emails = re.findall(email_pattern, text)
    return list(set(emails))


def extract_phones(text: str) -> list[str]:
    """Extract phone numbers from text"""
    patterns = [
        r'\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}',
        r'\+[0-9]{1,3}[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,9}',
    ]
    phones = []
    for pattern in patterns:
        phones.extend(re.findall(pattern, text))
    return list(set(phones))


def extract_social_links(html: str, base_url: str = "") -> dict:
    """Extract social media links from HTML"""
    social_patterns = {
        "linkedin": r'https?://(?:www\.)?linkedin\.com/company/[a-zA-Z0-9_-]+',
        "twitter": r'https?://(?:www\.)?(?:twitter|x)\.com/[a-zA-Z0-9_]+',
        "facebook": r'https?://(?:www\.)?facebook\.com/[a-zA-Z0-9.]+',
        "github": r'https?://(?:www\.)?github\.com/[a-zA-Z0-9_-]+',
        "youtube": r'https?://(?:www\.)?youtube\.com/(?:channel|c|user|@)[/a-zA-Z0-9_-]+',
    }

    results = {}
    for platform, pattern in social_patterns.items():
        matches = re.findall(pattern, html, re.IGNORECASE)
        if matches:
            results[platform] = matches[0]
    return results


def extract_links(html: str, base_url: str) -> list[str]:
    """Extract all links from HTML"""
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html, 'lxml')
    links = []

    for a in soup.find_all('a', href=True):
        href = a['href']
        if href.startswith('http'):
            links.append(href)
        elif href.startswith('/'):
            links.append(urljoin(base_url, href))

    return list(set(links))


def truncate_text(text: str, max_length: int = 10000) -> str:
    """Truncate text to max length while preserving word boundaries"""
    if len(text) <= max_length:
        return text

    truncated = text[:max_length]
    last_space = truncated.rfind(' ')
    if last_space > max_length * 0.8:
        truncated = truncated[:last_space]

    return truncated + "..."


def generate_output_filename(company_name: str, extension: str = "json") -> str:
    """Generate output filename for company data"""
    safe_name = re.sub(r'[^\w\s-]', '', company_name.lower())
    safe_name = re.sub(r'[-\s]+', '_', safe_name)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{safe_name}_{timestamp}.{extension}"


def save_output(data: dict, company_name: str, format: str = "json") -> str:
    """Save scraped data to file"""
    output_path = Path(OUTPUT_DIR)
    output_path.mkdir(parents=True, exist_ok=True)

    if format == "json" or format == "both":
        json_file = output_path / generate_output_filename(company_name, "json")
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        logger.info(f"Saved JSON output to {json_file}")

    if format == "markdown" or format == "both":
        md_file = output_path / generate_output_filename(company_name, "md")
        md_content = convert_to_markdown(data, company_name)
        with open(md_file, 'w', encoding='utf-8') as f:
            f.write(md_content)
        logger.info(f"Saved Markdown output to {md_file}")

    return str(output_path / generate_output_filename(company_name, format if format != "both" else "json"))


def convert_to_markdown(data: dict, company_name: str) -> str:
    """Convert full TPRM company data to Markdown format"""
    md = f"# TPRM Company Report: {company_name}\n\n"
    md += f"*Generated on: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}*\n\n"
    md += "---\n\n"

    # ── Basic Information ──
    basic = data.get("basic_info", {})
    if basic:
        md += "## 📋 Basic Information\n\n"
        fields = [
            ("name", "Company Name"),
            ("description", "Description"),
            ("industry", "Industry"),
            ("sector", "Sector"),
            ("founded", "Founded"),
            ("headquarters", "Headquarters"),
            ("country", "Country"),
            ("employees", "Employees"),
            ("employee_count", "Employee Count"),
        ]
        for key, label in fields:
            val = basic.get(key)
            if val:
                md += f"**{label}:** {val}\n"

        if basic.get("is_it_company") is not None:
            md += f"**IT Company:** {'Yes ✅' if basic['is_it_company'] else 'No'}\n"
        if basic.get("it_classification"):
            md += f"**IT Classification:** {basic['it_classification']}\n"
        if basic.get("sub_services"):
            md += f"**Services:** {', '.join(basic['sub_services'][:10])}\n"
        md += "\n"

    # ── Contact & Social Media ──
    contact = data.get("contact", {})
    social = data.get("social_media", {})
    if contact or social:
        md += "## 🌐 Contact & Online Presence\n\n"
        contact_fields = [
            ("official_website", "Official Website"),
            ("email", "Email"),
            ("phone", "Phone"),
            ("address", "Address"),
            ("support_email", "Support Email"),
            ("security_contact", "Security Contact"),
        ]
        for key, label in contact_fields:
            val = contact.get(key)
            if val:
                md += f"**{label}:** {val}\n"

        social_fields = [
            ("linkedin", "LinkedIn"),
            ("twitter", "Twitter"),
            ("facebook", "Facebook"),
            ("github", "GitHub"),
            ("youtube", "YouTube"),
        ]
        for key, label in social_fields:
            val = social.get(key)
            if val:
                md += f"**{label}:** {val}\n"
        md += "\n"

    # ── Security & Compliance ──
    security = data.get("security_compliance", {})
    if security:
        md += "## 🔒 Security & Compliance (TPRM)\n\n"

        md += "### ISO Certifications\n\n"
        md += "| Certification | Status | Expiry | Body | Scope |\n"
        md += "|---------------|--------|--------|------|-------|\n"

        iso_fields = [
            ("iso_27001", "ISO 27001 (Info Security)"),
            ("iso_27017", "ISO 27017 (Cloud Security)"),
            ("iso_27018", "ISO 27018 (Cloud Privacy)"),
            ("iso_9001", "ISO 9001 (Quality)"),
            ("iso_14001", "ISO 14001 (Environmental)"),
            ("iso_22301", "ISO 22301 (Business Continuity)"),
        ]
        for key, name in iso_fields:
            cert = security.get(key)
            if isinstance(cert, dict) and cert.get("status"):
                emoji = "✅" if cert["status"] == "Certified" else "⚠️"
                md += f"| {name} | {emoji} {cert['status']} | {cert.get('expiry_date', '-')} | {cert.get('certification_body', '-')} | {cert.get('scope', '-')} |\n"
            else:
                md += f"| {name} | ❌ Not Found | - | - | - |\n"
        md += "\n"

        md += "### Other Certifications & Compliance\n\n"
        md += "| Standard | Status |\n"
        md += "|----------|--------|\n"
        md += f"| SOC 2 Type II | {'✅ Certified' if security.get('soc2_type2') else '❌ Not Found'} |\n"
        md += f"| SOC 2 Type I | {'✅ Certified' if security.get('soc2_type1') else '❌ Not Found'} |\n"
        md += f"| SOC 1 | {'✅ Certified' if security.get('soc1') else '❌ Not Found'} |\n"
        md += f"| PCI-DSS | {'✅ Compliant' if security.get('pci_dss') else '❌ Not Found'} |\n"
        md += f"| HIPAA | {'✅ Compliant' if security.get('hipaa_compliant') else '❌ Not Found'} |\n"
        md += f"| GDPR | {'✅ Compliant' if security.get('gdpr_compliant') else '❌ Not Found'} |\n"
        md += f"| FedRAMP | {'✅ Authorized' if security.get('fedramp') else '❌ Not Found'} |\n"
        md += "\n"

        other_certs = security.get("other_certifications", [])
        if other_certs:
            md += f"**Other Certifications:** {', '.join(other_certs)}\n\n"

        # Security pages
        if security.get("has_security_page"):
            md += f"🔗 **Security Page:** {security.get('security_page_url', 'Yes')}\n"
        if security.get("has_trust_center"):
            md += f"🔗 **Trust Center:** {security.get('trust_center_url', 'Yes')}\n"
        if security.get("has_bug_bounty"):
            md += f"🔗 **Bug Bounty:** {security.get('bug_bounty_url', 'Yes')}\n"
        md += "\n"

    # ── Security Incidents ──
    incidents = data.get("security_incidents", {})
    if incidents:
        md += "## ⚠️ Security Incidents (TPRM Risk)\n\n"

        md += "### Data Breaches\n\n"
        breach_count = incidents.get("breach_count", 0)
        if breach_count > 0:
            md += f"**⚠️ {breach_count} breach(es) found**\n"
            if incidents.get("last_breach_date"):
                md += f"**Last Breach Date:** {incidents['last_breach_date']}\n"
            if incidents.get("ransomware_history"):
                md += "**🔴 Ransomware History: YES**\n"
            md += "\n"
            for i, breach in enumerate(incidents.get("data_breaches", [])[:5], 1):
                md += f"#### Breach #{i}\n"
                if breach.get("date"):
                    md += f"- **Date:** {breach['date']}\n"
                if breach.get("description"):
                    md += f"- **Description:** {breach['description'][:300]}\n"
                if breach.get("records_affected"):
                    md += f"- **Records Affected:** {breach['records_affected']}\n"
                if breach.get("severity"):
                    md += f"- **Severity:** {breach['severity']}\n"
                if breach.get("data_types_exposed"):
                    md += f"- **Data Types Exposed:** {', '.join(breach['data_types_exposed'])}\n"
                if breach.get("source_url"):
                    md += f"- **Source:** {breach['source_url']}\n"
                md += "\n"
        else:
            md += "✅ **No data breaches found**\n\n"

        md += "### CVE Vulnerabilities\n\n"
        cve_count = incidents.get("cve_count", 0)
        critical_count = incidents.get("critical_cve_count", 0)
        if cve_count > 0:
            md += f"**⚠️ {cve_count} CVE(s) found ({critical_count} critical)**\n\n"
            md += "| CVE ID | Severity | CVSS | Product | Patched |\n"
            md += "|--------|----------|------|---------|--------|\n"
            for cve in incidents.get("cve_vulnerabilities", [])[:10]:
                cve_id = cve.get("cve_id", "?")
                severity = cve.get("severity", "?")
                cvss = cve.get("cvss_score", "-") or "-"
                product = cve.get("affected_product", "?")[:40]
                patched = "✅" if cve.get("patched") else "⚠️"
                md += f"| {cve_id} | {severity} | {cvss} | {product} | {patched} |\n"
            md += "\n"
        else:
            md += "✅ **No CVE vulnerabilities found**\n\n"

    # ── Risk Indicators ──
    risk_indicators = data.get("overall_risk_indicators", [])
    if risk_indicators:
        md += "## 🎯 Risk Indicators\n\n"
        md += "| Category | Indicator | Severity | Details |\n"
        md += "|----------|-----------|----------|--------|\n"
        for ri in risk_indicators:
            cat = ri.get("category", "")
            ind = ri.get("indicator", "")
            sev = ri.get("severity", "")
            det = ri.get("details", "")
            emoji = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(sev, "⚪")
            md += f"| {cat} | {ind} | {emoji} {sev} | {det} |\n"
        md += "\n"

    # ── Data Quality ──
    quality = data.get("data_quality_score", 0)
    md += "## 📊 Data Quality\n\n"
    pct = int(quality * 100) if quality <= 1.0 else int(quality)
    color = "🟢" if pct >= 70 else "🟡" if pct >= 40 else "🔴"
    md += f"**Data Quality Score:** {color} {pct}%\n\n"

    # ── Sources ──
    sources = data.get("raw_sources", [])
    if sources:
        md += "## 📚 Sources\n\n"
        for src in sources[:15]:
            title = src.get("title", "Unknown")
            url = src.get("url", "")
            conf = src.get("confidence", 0)
            md += f"- [{title}]({url}) (confidence: {conf:.0%})\n"

    return md


def rate_limit_delay(delay: float = 0.3):
    """Add small delay between requests to be respectful"""
    time.sleep(delay + random.uniform(0, 0.2))


def hash_url(url: str) -> str:
    """Generate hash for URL (for caching)"""
    return hashlib.md5(url.encode()).hexdigest()
