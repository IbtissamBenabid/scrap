"""
TPRM-focused Company Information Extraction Utilities
Extracts: Basic Info, Contact, Industry/IT Classification, Social Media,
ISO Certifications, Data Breaches, CVE Vulnerabilities
"""
import re
import logging
from typing import Optional
from datetime import datetime
from bs4 import BeautifulSoup

from .states import (
    CompanyTPRMProfile, ScrapedPage, ISOCertification,
    DataBreach, CVEVulnerability
)
from .constants import IT_INDUSTRY_KEYWORDS, IT_SUB_SERVICES
from .helpers import (
    extract_emails,
    extract_phones,
    extract_social_links,
    clean_text,
)
from .llm import extract_tprm_info_with_llm, analyze_company_relevance

logger = logging.getLogger(__name__)


class TPRMExtractor:
    """Extract TPRM-focused company information from scraped pages"""
    
    def __init__(self, company_name: str, use_llm: bool = True):
        self.company_name = company_name
        self.use_llm = use_llm
        self.profile = CompanyTPRMProfile()
        self.profile.basic_info.name = company_name
        self.profile.search_timestamp = datetime.now().isoformat()
    
    def extract_from_pages(self, pages: list[ScrapedPage]) -> CompanyTPRMProfile:
        """
        Extract TPRM company information from multiple scraped pages
        """
        # Filter successful pages
        successful_pages = [p for p in pages if p.success and p.content]
        
        if not successful_pages:
            logger.warning("No successful pages to extract from")
            return self.profile
        
        # Sort by relevance
        scored_pages = []
        for page in successful_pages:
            score = analyze_company_relevance(page.content, self.company_name)
            scored_pages.append((score, page))
        
        scored_pages.sort(reverse=True, key=lambda x: x[0])
        
        # Extract from each page
        for score, page in scored_pages:
            if score < 0.1:
                continue
            
            self._extract_from_page(page)
            
            # Store as source
            self.profile.raw_sources.append({
                "url": page.url,
                "title": page.title,
                "relevance_score": score,
            })
        
        # Use LLM for deeper extraction if enabled
        if self.use_llm and scored_pages:
            self._llm_extract(scored_pages[:5])
        
        # Calculate IT classification
        self._classify_it_company()
        
        # Calculate data quality score
        self._calculate_quality_score()
        
        return self.profile
    
    def _extract_from_page(self, page: ScrapedPage):
        """Extract TPRM information from a single page"""
        content = page.content
        html = page.html
        url = page.url
        
        # Basic contact info
        self._extract_contact_info(content, html, url)
        
        # Social media links
        self._extract_social_media(html, url)
        
        # Industry and services
        self._extract_industry_info(content)
        
        # ISO Certifications
        self._extract_certifications(content, url)
        
        # Data Breaches
        self._extract_breach_info(content, url)
        
        # CVE Vulnerabilities
        self._extract_cve_info(content, url)
        
        # Security pages
        self._extract_security_info(content, url)
        
        # LinkedIn specific extraction
        if "linkedin.com" in url:
            self._extract_from_linkedin(content, page.metadata)
    
    def _extract_contact_info(self, content: str, html: str, url: str):
        """Extract contact information"""
        # Emails
        emails = extract_emails(content)
        if emails:
            for email in emails:
                if "security" in email.lower() and not self.profile.contact.security_contact:
                    self.profile.contact.security_contact = email
                elif "support" in email.lower() and not self.profile.contact.support_email:
                    self.profile.contact.support_email = email
                elif not self.profile.contact.email:
                    self.profile.contact.email = email
        
        # Phones
        phones = extract_phones(content)
        if phones and not self.profile.contact.phone:
            self.profile.contact.phone = phones[0]
        
        # Address patterns
        address_patterns = [
            r'(?:headquarters|address|location)[:\s]+([^.]+(?:street|avenue|road|blvd|drive|st\.|ave\.|rd\.|dr\.)[^.]+)',
            r'(\d+\s+[A-Z][a-z]+\s+(?:Street|Avenue|Road|Blvd|Drive|St\.|Ave\.|Rd\.|Dr\.)[^,]+,\s*[A-Z][a-z]+[^,]*,\s*[A-Z]{2}\s*\d{5})',
        ]
        for pattern in address_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match and not self.profile.contact.address:
                self.profile.contact.address = clean_text(match.group(1))[:200]
                break
    
    def _extract_social_media(self, html: str, url: str):
        """Extract social media and official website links"""
        social_links = extract_social_links(html, url)
        
        if social_links.get("linkedin") and not self.profile.social_media.linkedin:
            self.profile.social_media.linkedin = social_links["linkedin"]
        if social_links.get("twitter") and not self.profile.social_media.twitter:
            self.profile.social_media.twitter = social_links["twitter"]
        if social_links.get("facebook") and not self.profile.social_media.facebook:
            self.profile.social_media.facebook = social_links["facebook"]
        if social_links.get("github") and not self.profile.social_media.github:
            self.profile.social_media.github = social_links["github"]
        
        # Try to extract official website from content
        if not self.profile.contact.official_website:
            website_patterns = [
                rf'{re.escape(self.company_name.lower())}\.com',
                rf'www\.{re.escape(self.company_name.lower())}\.com',
            ]
            for pattern in website_patterns:
                match = re.search(pattern, html.lower())
                if match:
                    self.profile.contact.official_website = f"https://{match.group(0)}"
                    break
    
    def _extract_industry_info(self, content: str):
        """Extract industry, sector, and IT classification"""
        content_lower = content.lower()
        
        # Industry patterns
        industry_patterns = [
            r'industry[:\s]+([^.\n]+)',
            r'sector[:\s]+([^.\n]+)',
            r'operates in (?:the )?([^.]+) (?:industry|sector)',
        ]
        for pattern in industry_patterns:
            match = re.search(pattern, content_lower)
            if match and not self.profile.basic_info.industry:
                self.profile.basic_info.industry = clean_text(match.group(1))[:100]
                break
        
        # Extract services
        services_patterns = [
            r'(?:services|products|offerings)[:\s]+([^.]+)',
            r'(?:we )?(?:provide|offer)[s]?[:\s]+([^.]+)',
            r'(?:specializ(?:e|ing) in)[:\s]+([^.]+)',
        ]
        for pattern in services_patterns:
            match = re.search(pattern, content_lower)
            if match:
                services_text = match.group(1)
                services = [s.strip() for s in re.split(r'[,;]', services_text) if s.strip()]
                for service in services[:10]:
                    if service not in self.profile.basic_info.sub_services:
                        self.profile.basic_info.sub_services.append(service)
        
        # Employee count
        employee_patterns = [
            r'(\d+(?:,\d+)?)\s*(?:\+\s*)?employees',
            r'team\s+of\s+(\d+(?:,\d+)?)',
            r'(\d+(?:,\d+)?)\s*(?:\+\s*)?team\s+members',
            r'(\d+-\d+)\s*employees',
        ]
        for pattern in employee_patterns:
            match = re.search(pattern, content_lower)
            if match and not self.profile.basic_info.employee_count:
                self.profile.basic_info.employee_count = match.group(1)
                break
    
    def _extract_certifications(self, content: str, url: str):
        """Extract ISO and security certifications"""
        content_lower = content.lower()
        
        # ISO 27001 - Information Security
        if re.search(r'iso\s*27001|iso/iec\s*27001', content_lower):
            self.profile.security_compliance.iso_27001.name = "ISO 27001"
            if re.search(r'iso\s*27001[:\s]+certified|certified.*iso\s*27001', content_lower):
                self.profile.security_compliance.iso_27001.status = "Certified"
            else:
                self.profile.security_compliance.iso_27001.status = "Mentioned"
        
        # ISO 27017 - Cloud Security
        if re.search(r'iso\s*27017|iso/iec\s*27017', content_lower):
            self.profile.security_compliance.iso_27017.name = "ISO 27017"
            self.profile.security_compliance.iso_27017.status = "Certified"
        
        # ISO 27018 - Cloud Privacy
        if re.search(r'iso\s*27018|iso/iec\s*27018', content_lower):
            self.profile.security_compliance.iso_27018.name = "ISO 27018"
            self.profile.security_compliance.iso_27018.status = "Certified"
        
        # ISO 9001 - Quality
        if re.search(r'iso\s*9001|iso/iec\s*9001', content_lower):
            self.profile.security_compliance.iso_9001.name = "ISO 9001"
            if re.search(r'iso\s*9001[:\s]+certified|certified.*iso\s*9001', content_lower):
                self.profile.security_compliance.iso_9001.status = "Certified"
            else:
                self.profile.security_compliance.iso_9001.status = "Mentioned"
        
        # ISO 14001 - Environmental
        if re.search(r'iso\s*14001', content_lower):
            self.profile.security_compliance.iso_14001.name = "ISO 14001"
            self.profile.security_compliance.iso_14001.status = "Certified"
        
        # ISO 22301 - Business Continuity
        if re.search(r'iso\s*22301', content_lower):
            self.profile.security_compliance.iso_22301.name = "ISO 22301"
            self.profile.security_compliance.iso_22301.status = "Certified"
        
        # SOC 2
        if re.search(r'soc\s*2\s*type\s*(?:ii|2)', content_lower):
            self.profile.security_compliance.soc2_type2 = True
        elif re.search(r'soc\s*2\s*type\s*(?:i|1)', content_lower):
            self.profile.security_compliance.soc2_type1 = True
        elif re.search(r'soc\s*2', content_lower):
            self.profile.security_compliance.soc2_type1 = True  # Assume at least Type 1
        
        # SOC 1
        if re.search(r'soc\s*1|ssae\s*18', content_lower):
            self.profile.security_compliance.soc1 = True
        
        # PCI-DSS
        if re.search(r'pci[\s-]?dss|payment\s+card\s+industry', content_lower):
            self.profile.security_compliance.pci_dss = True
        
        # HIPAA
        if re.search(r'hipaa\s+complian|hipaa\s+certif', content_lower):
            self.profile.security_compliance.hipaa_compliant = True
        
        # GDPR
        if re.search(r'gdpr\s+complian', content_lower):
            self.profile.security_compliance.gdpr_compliant = True
        
        # FedRAMP
        if re.search(r'fedramp', content_lower):
            self.profile.security_compliance.fedramp = True
        
        # Other certifications
        other_certs = [
            (r'csa\s+star', "CSA STAR"),
            (r'cyber\s*essentials', "Cyber Essentials"),
            (r'nist\s+800', "NIST 800"),
            (r'hitrust', "HITRUST"),
            (r'iso\s*27701', "ISO 27701 (Privacy)"),
            (r'tisax', "TISAX"),
            (r'c5', "C5 (German Cloud)"),
        ]
        for pattern, cert_name in other_certs:
            if re.search(pattern, content_lower):
                if cert_name not in self.profile.security_compliance.other_certifications:
                    self.profile.security_compliance.other_certifications.append(cert_name)
    
    def _extract_breach_info(self, content: str, url: str):
        """Extract data breach information"""
        content_lower = content.lower()
        company_name_lower = self.company_name.lower()
        
        # Check if page is about a breach for this company
        breach_keywords = [
            'data breach', 'data leak', 'security incident', 'hack', 
            'compromised', 'exposed', 'stolen data', 'cyberattack',
            'ransomware', 'data exposed'
        ]
        
        has_breach_content = any(kw in content_lower for kw in breach_keywords)
        has_company_name = company_name_lower in content_lower
        
        if has_breach_content and has_company_name:
            # Extract breach details
            breach = DataBreach()
            breach.source_url = url
            
            # Date patterns
            date_patterns = [
                r'(?:in|on|during)\s+(january|february|march|april|may|june|july|august|september|october|november|december)\s+(\d{4})',
                r'(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})',
                r'(20\d{2})',
            ]
            for pattern in date_patterns:
                match = re.search(pattern, content_lower)
                if match:
                    breach.date = match.group(0)
                    break
            
            # Records affected
            records_patterns = [
                r'(\d+(?:,\d{3})*(?:\.\d+)?)\s*(?:million|billion)?\s*(?:records|users|customers|accounts)',
                r'(?:affected|impacted|compromised)\s+(\d+(?:,\d{3})*(?:\.\d+)?)\s*(?:million|billion)?',
            ]
            for pattern in records_patterns:
                match = re.search(pattern, content_lower)
                if match:
                    breach.records_affected = match.group(0)
                    break
            
            # Data types
            data_types = ['email', 'password', 'credit card', 'ssn', 'social security',
                         'personal data', 'financial', 'medical', 'phone', 'address']
            for dt in data_types:
                if dt in content_lower:
                    breach.data_types_exposed.append(dt)
            
            # Description
            breach.description = content[:500] if content else ""
            
            # Severity based on records
            if breach.records_affected:
                if 'million' in breach.records_affected.lower() or 'billion' in breach.records_affected.lower():
                    breach.severity = "Critical"
                elif any(c.isdigit() for c in breach.records_affected):
                    num = int(''.join(filter(str.isdigit, breach.records_affected.split()[0])))
                    if num > 100000:
                        breach.severity = "High"
                    elif num > 10000:
                        breach.severity = "Medium"
                    else:
                        breach.severity = "Low"
            
            # Ransomware check
            if 'ransomware' in content_lower:
                self.profile.security_incidents.ransomware_history = True
            
            # Add breach if not duplicate
            existing_urls = [b.source_url for b in self.profile.security_incidents.data_breaches]
            if url not in existing_urls:
                self.profile.security_incidents.data_breaches.append(breach)
                self.profile.security_incidents.breach_count = len(self.profile.security_incidents.data_breaches)
                if breach.date and not self.profile.security_incidents.last_breach_date:
                    self.profile.security_incidents.last_breach_date = breach.date
    
    def _extract_cve_info(self, content: str, url: str):
        """Extract CVE vulnerability information"""
        # CVE ID pattern
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cve_matches = re.findall(cve_pattern, content, re.IGNORECASE)
        
        for cve_id in set(cve_matches):
            # Check if we already have this CVE
            existing_cves = [v.cve_id for v in self.profile.security_incidents.cve_vulnerabilities]
            if cve_id.upper() in existing_cves:
                continue
            
            cve = CVEVulnerability()
            cve.cve_id = cve_id.upper()
            cve.source_url = url
            
            # Try to extract CVSS score
            cvss_pattern = rf'{re.escape(cve_id)}[^.]*?(?:cvss|score)[:\s]*(\d+\.?\d*)'
            cvss_match = re.search(cvss_pattern, content, re.IGNORECASE)
            if cvss_match:
                cve.cvss_score = cvss_match.group(1)
                score = float(cve.cvss_score)
                if score >= 9.0:
                    cve.severity = "Critical"
                elif score >= 7.0:
                    cve.severity = "High"
                elif score >= 4.0:
                    cve.severity = "Medium"
                else:
                    cve.severity = "Low"
            
            # Try to extract description around CVE mention
            cve_pos = content.find(cve_id)
            if cve_pos >= 0:
                start = max(0, cve_pos - 100)
                end = min(len(content), cve_pos + 300)
                cve.description = content[start:end].strip()
            
            # Check if patched
            if any(kw in content.lower() for kw in ['patched', 'fixed', 'remediated', 'resolved']):
                cve.patched = True
            
            self.profile.security_incidents.cve_vulnerabilities.append(cve)
        
        # Update counts
        self.profile.security_incidents.cve_count = len(self.profile.security_incidents.cve_vulnerabilities)
        self.profile.security_incidents.critical_cve_count = sum(
            1 for v in self.profile.security_incidents.cve_vulnerabilities 
            if v.severity == "Critical"
        )
    
    def _extract_security_info(self, content: str, url: str):
        """Extract security page and trust center information"""
        url_lower = url.lower()
        content_lower = content.lower()
        
        # Security/Trust page detection
        if any(kw in url_lower for kw in ['security', 'trust', 'compliance']):
            self.profile.security_compliance.has_security_page = True
            if not self.profile.security_compliance.security_page_url:
                self.profile.security_compliance.security_page_url = url
        
        if 'trust' in url_lower or 'trust center' in content_lower:
            self.profile.security_compliance.has_trust_center = True
            if not self.profile.security_compliance.trust_center_url:
                self.profile.security_compliance.trust_center_url = url
        
        # Bug bounty detection
        if any(kw in content_lower for kw in ['bug bounty', 'vulnerability disclosure', 'responsible disclosure', 'hackerone', 'bugcrowd']):
            self.profile.security_compliance.has_bug_bounty = True
    
    def _extract_from_linkedin(self, content: str, metadata: dict):
        """Extract information specific to LinkedIn pages"""
        if metadata.get("schema"):
            schema = metadata["schema"]
            if isinstance(schema, dict):
                if schema.get("name") and not self.profile.basic_info.name:
                    self.profile.basic_info.name = schema["name"]
                if schema.get("description") and not self.profile.basic_info.description:
                    self.profile.basic_info.description = schema["description"]
    
    def _classify_it_company(self):
        """Classify if the company is an IT company and set sector to IT/Non-IT"""
        # Combine relevant text for classification
        text = f"{self.profile.basic_info.industry} {self.profile.basic_info.description} {' '.join(self.profile.basic_info.sub_services)}".lower()
        
        # Check against IT keywords
        it_keyword_matches = sum(1 for kw in IT_INDUSTRY_KEYWORDS if kw in text)
        
        if it_keyword_matches >= 2 or any(kw in text for kw in ['software', 'technology', 'it services', 'tech', 'cyber', 'cloud', 'saas', 'digital']):
            self.profile.basic_info.is_it_company = True
            self.profile.basic_info.sector = "IT"  # Simplified sector
            
            # Determine IT sub-classification
            for service_type, keywords in IT_SUB_SERVICES.items():
                if any(kw in text for kw in keywords):
                    if not self.profile.basic_info.it_classification:
                        self.profile.basic_info.it_classification = service_type.replace('_', ' ').title()
                    break
            
            if not self.profile.basic_info.it_classification:
                self.profile.basic_info.it_classification = "General IT"
        else:
            self.profile.basic_info.is_it_company = False
            self.profile.basic_info.sector = "Non-IT"  # Simplified sector
            self.profile.basic_info.it_classification = "Non-IT"
    
    def _calculate_quality_score(self):
        """Calculate data quality score based on completeness"""
        score = 0.0
        max_score = 10.0
        
        # Basic info (2 points)
        if self.profile.basic_info.name: score += 0.5
        if self.profile.basic_info.industry: score += 0.5
        if self.profile.basic_info.description: score += 0.5
        if self.profile.contact.official_website or self.profile.social_media.linkedin: score += 0.5
        
        # Contact (1 point)
        if self.profile.contact.email: score += 0.5
        if self.profile.contact.phone or self.profile.contact.address: score += 0.5
        
        # Social Media (1 point)
        if self.profile.social_media.linkedin: score += 0.5
        if self.profile.social_media.twitter or self.profile.social_media.github: score += 0.5
        
        # Security & Compliance (4 points - most important for TPRM)
        if self.profile.security_compliance.iso_27001.status: score += 1.0
        if self.profile.security_compliance.soc2_type2 or self.profile.security_compliance.soc2_type1: score += 1.0
        if self.profile.security_compliance.has_security_page: score += 1.0
        if len(self.profile.security_compliance.other_certifications) > 0: score += 1.0
        
        # Security Incidents (2 points - valuable to have this info)
        if self.profile.security_incidents.breach_count > 0 or len(self.profile.raw_sources) >= 3:
            score += 1.0  # We searched for breaches
        if self.profile.security_incidents.cve_count > 0 or len(self.profile.raw_sources) >= 5:
            score += 1.0  # We searched for CVEs
        
        self.profile.data_quality_score = round((score / max_score) * 100, 1)
    
    def _llm_extract(self, scored_pages: list[tuple[float, ScrapedPage]]):
        """Use LLM for deeper TPRM extraction"""
        combined_content = ""
        for score, page in scored_pages[:3]:
            combined_content += f"\n---\nSource: {page.url}\n{page.content[:5000]}\n"
        
        try:
            extracted = extract_tprm_info_with_llm(combined_content, self.company_name)
            
            if extracted:
                self._merge_extracted_data(extracted)
                
        except Exception as e:
            logger.error(f"LLM extraction failed: {str(e)}")
    
    def _merge_extracted_data(self, extracted: dict):
        """Merge LLM-extracted data with existing profile"""
        # Basic info
        if "basic_info" in extracted:
            bi = extracted["basic_info"]
            if bi.get("name") and not self.profile.basic_info.name:
                self.profile.basic_info.name = bi["name"]
            if bi.get("description") and not self.profile.basic_info.description:
                self.profile.basic_info.description = bi["description"]
            if bi.get("industry") and not self.profile.basic_info.industry:
                self.profile.basic_info.industry = bi["industry"]
            if bi.get("sector") and not self.profile.basic_info.sector:
                self.profile.basic_info.sector = bi["sector"]
            if bi.get("is_it_company") is not None:
                self.profile.basic_info.is_it_company = bi["is_it_company"]
            if bi.get("it_classification"):
                self.profile.basic_info.it_classification = bi["it_classification"]
            if bi.get("sub_services"):
                for svc in bi["sub_services"]:
                    if svc not in self.profile.basic_info.sub_services:
                        self.profile.basic_info.sub_services.append(svc)
        
        # Contact
        if "contact" in extracted:
            ct = extracted["contact"]
            if ct.get("official_website") and not self.profile.contact.official_website:
                self.profile.contact.official_website = ct["official_website"]
            if ct.get("email") and not self.profile.contact.email:
                self.profile.contact.email = ct["email"]
            if ct.get("phone") and not self.profile.contact.phone:
                self.profile.contact.phone = ct["phone"]
        
        # Certifications from LLM
        if "certifications" in extracted:
            certs = extracted["certifications"]
            if certs.get("iso_27001") and not self.profile.security_compliance.iso_27001.status:
                self.profile.security_compliance.iso_27001.name = "ISO 27001"
                self.profile.security_compliance.iso_27001.status = "Certified"
            if certs.get("iso_9001") and not self.profile.security_compliance.iso_9001.status:
                self.profile.security_compliance.iso_9001.name = "ISO 9001"
                self.profile.security_compliance.iso_9001.status = "Certified"
            if certs.get("soc2"):
                self.profile.security_compliance.soc2_type2 = True
        
        # Security incidents from LLM
        if "security_incidents" in extracted:
            incidents = extracted["security_incidents"]
            if incidents.get("has_breaches"):
                breach = DataBreach()
                breach.description = incidents.get("breach_summary", "")
                self.profile.security_incidents.data_breaches.append(breach)


# Keep backward compatible function name
CompanyInfoExtractor = TPRMExtractor


def extract_company_info(company_name: str, pages: list[ScrapedPage], use_llm: bool = True) -> dict:
    """
    Convenience function to extract TPRM company information
    """
    extractor = TPRMExtractor(company_name, use_llm)
    profile = extractor.extract_from_pages(pages)
    return profile.model_dump()
