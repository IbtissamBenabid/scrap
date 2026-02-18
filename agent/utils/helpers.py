"""
Helper utilities for scraping agent
"""
import re
import json
import random
import time
import hashlib
from datetime import datetime
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
    # Remove extra whitespace
    text = re.sub(r'\s+', ' ', text)
    # Remove special characters but keep basic punctuation
    text = re.sub(r'[^\w\s.,;:!?@#$%&*()-]', '', text)
    return text.strip()


def extract_emails(text: str) -> list[str]:
    """Extract email addresses from text"""
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    emails = re.findall(email_pattern, text)
    return list(set(emails))


def extract_phones(text: str) -> list[str]:
    """Extract phone numbers from text"""
    # Various phone patterns
    patterns = [
        r'\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}',  # US format
        r'\+[0-9]{1,3}[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,9}',  # International
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
        "youtube": r'https?://(?:www\.)?youtube\.com/(?:channel|c|user)/[a-zA-Z0-9_-]+',
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
    """Convert TPRM company data to Markdown format"""
    md = f"# TPRM Company Report: {company_name}\n\n"
    md += f"*Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n\n"
    md += "---\n\n"
    
    # Basic Information Section
    basic = data.get("basic_info", {})
    if basic:
        md += "## 📋 Basic Information\n\n"
        if basic.get("name"):
            md += f"**Company Name:** {basic['name']}\n"
        if basic.get("industry"):
            md += f"**Industry:** {basic['industry']}\n"
        if basic.get("sector"):
            md += f"**Sector:** {basic['sector']}\n"
        if basic.get("is_it_company") is not None:
            it_status = "Yes ✅" if basic["is_it_company"] else "No"
            md += f"**IT Company:** {it_status}\n"
        if basic.get("it_classification"):
            md += f"**IT Classification:** {basic['it_classification']}\n"
        if basic.get("sub_services"):
            md += f"**Services:** {', '.join(basic['sub_services'][:10])}\n"
        if basic.get("employee_count"):
            md += f"**Employees:** {basic['employee_count']}\n"
        if basic.get("headquarters") or basic.get("country"):
            location = f"{basic.get('headquarters', '')} {basic.get('country', '')}".strip()
            md += f"**Location:** {location}\n"
        md += "\n"
    
    # Contact & Social Media Section
    contact = data.get("contact", {})
    social = data.get("social_media", {})
    if contact or social:
        md += "## 🌐 Contact & Online Presence\n\n"
        if contact.get("official_website"):
            md += f"**Official Website:** {contact['official_website']}\n"
        if social.get("linkedin"):
            md += f"**LinkedIn:** {social['linkedin']}\n"
        if social.get("twitter"):
            md += f"**Twitter:** {social['twitter']}\n"
        if social.get("github"):
            md += f"**GitHub:** {social['github']}\n"
        if contact.get("email"):
            md += f"**Email:** {contact['email']}\n"
        if contact.get("phone"):
            md += f"**Phone:** {contact['phone']}\n"
        if contact.get("security_contact"):
            md += f"**Security Contact:** {contact['security_contact']}\n"
        md += "\n"
    
    # Security & Compliance Section - MOST IMPORTANT FOR TPRM
    security = data.get("security_compliance", {})
    if security:
        md += "## 🔒 Security & Compliance (TPRM)\n\n"
        md += "### ISO Certifications\n\n"
        
        # ISO certs are now simple booleans
        iso_certs = [
            ("iso_27001", "ISO 27001 (Information Security)"),
            ("iso_27017", "ISO 27017 (Cloud Security)"),
            ("iso_27018", "ISO 27018 (Cloud Privacy)"),
            ("iso_9001", "ISO 9001 (Quality Management)"),
            ("iso_14001", "ISO 14001 (Environmental)"),
            ("iso_22301", "ISO 22301 (Business Continuity)"),
        ]
        
        md += "| Certification | Status |\n"
        md += "|---------------|--------|\n"
        for key, name in iso_certs:
            is_certified = security.get(key, False)
            emoji = "✅" if is_certified else "❌"
            status = "Certified" if is_certified else "Not Found"
            md += f"| {name} | {emoji} {status} |\n"
        md += "\n"
        
        md += "### Other Certifications & Compliance\n\n"
        md += "| Standard | Status |\n"
        md += "|----------|--------|\n"
        if security.get("soc2"):
            md += "| SOC 2 | ✅ Certified |\n"
        else:
            md += "| SOC 2 | ❌ Not Found |\n"
        
        md += f"| SOC 1 | {'✅ Certified' if security.get('soc1') else '❌ Not Found'} |\n"
        md += f"| PCI-DSS | {'✅ Compliant' if security.get('pci_dss') else '❌ Not Found'} |\n"
        md += f"| HIPAA | {'✅ Compliant' if security.get('hipaa') else '❌ Not Found'} |\n"
        md += f"| GDPR | {'✅ Compliant' if security.get('gdpr_compliant') else '❌ Not Found'} |\n"
        md += f"| FedRAMP | {'✅ Authorized' if security.get('fedramp') else '❌ Not Found'} |\n"
        md += "\n"
        
        other_certs = security.get("other_certifications", [])
        if other_certs:
            md += "**Other Certifications:** " + ", ".join(other_certs) + "\n\n"
        md += "\n"
    
    # Security Incidents Section - CRITICAL FOR TPRM RISK
    incidents = data.get("security_incidents", {})
    if incidents:
        md += "## ⚠️ Security Incidents (TPRM Risk Assessment)\n\n"
        
        # Data Breaches
        md += "### Data Breaches\n\n"
        breach_count = incidents.get("breach_count", 0)
        if breach_count > 0:
            md += f"**⚠️ {breach_count} breach(es) found**\n\n"
            if incidents.get("last_breach_date"):
                md += f"**Last Breach Date:** {incidents['last_breach_date']}\n\n"
            
            breaches = incidents.get("data_breaches", [])
            for i, breach in enumerate(breaches[:5], 1):
                md += f"#### Breach #{i}\n"
                if breach.get("affected_entity"):
                    md += f"- **Affected Entity:** {breach['affected_entity']}\n"
                if breach.get("date"):
                    md += f"- **Date:** {breach['date']}\n"
                if breach.get("description"):
                    md += f"- **Description:** {breach['description'][:200]}...\n"
                md += "\n"
        else:
            md += "✅ **No data breaches found**\n\n"
        
        # CVE Vulnerabilities
        md += "### CVE Vulnerabilities\n\n"
        cve_count = len(incidents.get("cve_vulnerabilities", []))
        if cve_count > 0:
            md += f"**⚠️ {cve_count} CVE(s) found**\n\n"
            
            cves = incidents.get("cve_vulnerabilities", [])
            if cves:
                md += "| CVE ID | Affected Product |\n"
                md += "|--------|------------------|\n"
                for cve in cves[:10]:
                    cve_id = cve.get("cve_id", "Unknown")
                    product = cve.get("affected_product", "Unknown")
                    md += f"| {cve_id} | {product} |\n"
                md += "\n"
        else:
            md += "✅ **No CVE vulnerabilities found**\n\n"
    # Risk Summary
    md += "## 📊 TPRM Risk Summary\n\n"
    quality_score = data.get("data_quality_score", 0)
    md += f"**Data Quality Score:** {quality_score}%\n\n"
    
    # Risk indicators
    risk_indicators = data.get("overall_risk_indicators", [])
    if risk_indicators:
        md += "**Risk Indicators:**\n"
        for indicator in risk_indicators:
            md += f"- ⚠️ {indicator}\n"
        md += "\n"
    
    # Auto-generated risk assessment - fixed for simplified model
    risks = []
    if incidents.get("breach_count", 0) > 0:
        risks.append("Has data breach history")
    if incidents.get("critical_cve_count", 0) > 0:
        risks.append("Has critical CVE vulnerabilities")
    if incidents.get("ransomware_history"):
        risks.append("Has ransomware history")
    if not security.get("iso_27001", False):
        risks.append("No ISO 27001 certification found")
    
    if risks:
        md += "**Identified Risks:**\n"
        for risk in risks:
            md += f"- 🔴 {risk}\n"
    else:
        md += "**No major risks identified** ✅\n"
    md += "\n"
    
    # Add sources
    if "raw_sources" in data and data["raw_sources"]:
        md += "## 📚 Sources\n\n"
        for source in data["raw_sources"][:10]:
            title = source.get('title', 'Unknown')
            url = source.get('url', '')
            score = source.get('relevance_score', 0)
            md += f"- [{title}]({url}) (relevance: {score:.2f})\n"
    
    return md


def rate_limit_delay(delay: float = 1.0):
    """Add delay between requests to be respectful"""
    time.sleep(delay + random.uniform(0, 0.5))


def hash_url(url: str) -> str:
    """Generate hash for URL (for caching)"""
    return hashlib.md5(url.encode()).hexdigest()
