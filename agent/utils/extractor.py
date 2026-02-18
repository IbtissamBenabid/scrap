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
    CompanyTPRMProfile, ScrapedPage,
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
        Extract ESSENTIAL company information from multiple scraped pages
        SIMPLIFIED: Only extract 6 core fields + security info
        """
        # Filter successful pages
        successful_pages = [p for p in pages if p.success and p.content]
        
        if not successful_pages:
            logger.warning("No successful pages to extract from")
            return self.profile
        
        # Extract from each page (no scoring, just process sequentially)
        for page in successful_pages[:5]:  # Limit to first 5 relevant pages
            self._extract_from_page(page)
        
        # Use LLM for extraction if enabled
        if self.use_llm and successful_pages:
            self._llm_extract(successful_pages[:3])
        
        # Simple IT classification (binary: true or false)
        self._classify_it_company()
        
        return self.profile
    
    def _extract_from_page(self, page: ScrapedPage):
        """Extract ONLY essential information from a single page"""
        content = page.content
        html = page.html
        url = page.url
        
        # 1. Website
        self._extract_website(content, html, url)
        
        # 2. LinkedIn
        self._extract_linkedin(html, url)
        
        # 3. Industry/Sector & Country
        self._extract_sector_and_country(content)
        
        # 4. Company Size
        self._extract_company_size(content)
        
        # 5. Certifications
        self._extract_certifications_simple(content)
        
        # 6. Data Breaches
        self._extract_breach_info(content, url)
        
        # 7. CVE Vulnerabilities
        self._extract_cve_info(content, url)
    
    def _extract_website(self, content: str, html: str, url: str):
        """Extract official website - SIMPLIFIED"""
        if self.profile.contact.official_website:
            return
        
        # Check if current URL is official site
        url_lower = url.lower()
        company_lower = self.company_name.lower().replace(" ", "")
        
        if company_lower in url_lower and any(x in url_lower for x in ['.com', '.fr', '.org', '.io']):
            self.profile.contact.official_website = url
            return
        
        # Look for website patterns in content
        url_patterns = [
            rf'(?:https?://)?(?:www\.)?{re.escape(company_lower)}\.(?:com|fr|org|io|de|uk|co)',
            r'(?:https?://)?(?:www\.)?[a-z0-9\-\.]+\.(?:com|fr|org|io|de)',
        ]
        
        for pattern in url_patterns:
            match = re.search(pattern, html.lower(), re.IGNORECASE)
            if match:
                self.profile.contact.official_website = match.group(0)
                if not self.profile.contact.official_website.startswith('http'):
                    self.profile.contact.official_website = f"https://{self.profile.contact.official_website}"
                break
    
    def _extract_linkedin(self, html: str, url: str):
        """Extract LinkedIn URL - SIMPLIFIED"""
        if self.profile.social_media.linkedin:
            return
        
        # If current URL is LinkedIn, use it
        if "linkedin.com" in url.lower() and "/company/" in url.lower():
            self.profile.social_media.linkedin = url
            return
        
        # Look for LinkedIn profile in HTML
        linkedin_pattern = r'(https?://(?:www\.)?linkedin\.com/company/[a-z0-9\-]+)'
        match = re.search(linkedin_pattern, html, re.IGNORECASE)
        if match:
            self.profile.social_media.linkedin = match.group(1)
    
    def _extract_sector_and_country(self, content: str):
        """Extract industry sector and country - SIMPLIFIED"""
        content_lower = content.lower()
        
        # Industry/Sector - simple extraction
        sector_patterns = [
            r'(?:industry|sector|specializes in)[:\s]+([^.\n]+)',
            r'(?:software|technology|finance|manufacturing|healthcare|retail|education|consulting)[^\n.]*',
        ]
        
        for pattern in sector_patterns:
            match = re.search(pattern, content_lower)
            if match and not self.profile.basic_info.sector:
                sector = clean_text(match.group(1) if match.lastindex else match.group(0))
                self.profile.basic_info.sector = sector[:80]
                break
        
        # Country - simple patterns
        country_patterns = [
            r'(?:headquarters|based in|located in|country)[:\s]+([A-Z][a-z]+(?:\s[A-Z][a-z]+)*)',
            r'(United States|France|Germany|UK|Canada|Australia|India|Singapore|Switzerland)',
        ]
        
        for pattern in country_patterns:
            match = re.search(pattern, content_lower, re.IGNORECASE)
            if match and not self.profile.basic_info.country:
                self.profile.basic_info.country = match.group(1)
                break
    
    def _extract_company_size(self, content: str):
        """Extract employee count - SIMPLIFIED"""
        if self.profile.basic_info.employee_count:
            return
        
        content_lower = content.lower()
        
        # Simple patterns for employee count
        patterns = [
            r'(\d+(?:,\d+)?)\s*(?:\+\s*)?employees',
            r'team\s+of\s+(\d+(?:,\d+)?)',
            r'(\d+-\d+)\s*employees',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, content_lower)
            if match:
                self.profile.basic_info.employee_count = match.group(1)
                return
    
    def _extract_certifications_simple(self, content: str):
        """Extract certifications - SIMPLIFIED, just check presence"""
        content_lower = content.lower()
        
        certs = {
            'iso_27001': [r'iso\s*27001', r'iso/iec\s*27001'],
            'iso_27017': [r'iso\s*27017'],
            'iso_27018': [r'iso\s*27018'],
            'iso_9001': [r'iso\s*9001'],
            'soc2': [r'soc\s*2', r'soc2'],
            'pci_dss': [r'pci\s*dss', r'pci-dss'],
            'hipaa': [r'hipaa'],
            'gdpr_compliant': [r'gdpr'],
            'fedramp': [r'fedramp'],
        }
        
        for cert_field, patterns in certs.items():
            for pattern in patterns:
                if re.search(pattern, content_lower):
                    setattr(self.profile.security_compliance, cert_field, True)
                    break
    
    
    def _extract_breach_info(self, content: str, url: str):
        """Extract data breach information - SIMPLIFIED"""
        content_lower = content.lower()
        company_name_lower = self.company_name.lower()
        
        # Check if page is about a breach
        breach_keywords = ['data breach', 'data leak', 'hack', 'compromised', 'exposed', 'ransomware']
        
        if any(kw in content_lower for kw in breach_keywords) and company_name_lower in content_lower:
            breach = DataBreach()
            
            # Try to extract affected entity and date
            date_match = re.search(r'(january|february|march|april|may|june|july|august|september|october|november|december|20\d{2})', content_lower)
            if date_match:
                breach.date = date_match.group(0)
            
            # Affected entity - either company name or specific target
            breach.affected_entity = self.company_name
            
            # Brief description
            breach.description = content[:300]
            
            # Add if not duplicate
            existing_breaches = [b.affected_entity + b.date for b in self.profile.security_incidents.data_breaches]
            breach_id = breach.affected_entity + breach.date
            if breach_id not in existing_breaches:
                self.profile.security_incidents.data_breaches.append(breach)
    
    def _extract_cve_info(self, content: str, url: str):
        """Extract CVE vulnerability information - SIMPLIFIED"""
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
            
            # Try to extract affected product
            product_pattern = rf'{re.escape(cve_id)}[^.]*?(?:affects?|affects?ing|in)\s+([^,.\n]+)'
            product_match = re.search(product_pattern, content, re.IGNORECASE)
            if product_match:
                cve.affected_product = product_match.group(1).strip()[:200]
            
            # Brief description
            cve.description = content[:500]
            
            self.profile.security_incidents.cve_vulnerabilities.append(cve)
    
    def _classify_it_company(self):
        """Simple IT/Non-IT classification - BINARY"""
        sector_text = f"{self.profile.basic_info.sector}".lower()
        
        # Simple IT keywords
        it_keywords = [
            "software", "technology", "it", "cloud", "saas", "data", 
            "cyber", "security", "ai", "digital", "tech", "development", 
            "programming", "engineering", "it services", "consulting"
        ]
        
        # Check if any IT keyword is in sector
        self.profile.basic_info.is_it_company = any(kw in sector_text for kw in it_keywords)
    
    def _llm_extract(self, pages: list[ScrapedPage]):
        """Use LLM for extraction if enabled"""
        combined_content = ""
        for page in pages[:3]:
            combined_content += f"\n---\nSource: {page.url}\n{page.content[:5000]}\n"
        
        try:
            extracted = extract_tprm_info_with_llm(combined_content, self.company_name)
            
            if extracted:
                self._merge_extracted_data(extracted)
                
        except Exception as e:
            logger.error(f"LLM extraction failed: {str(e)}")
    
    def _merge_extracted_data(self, extracted: dict):
        """Merge LLM-extracted data with existing profile"""
        try:
            # Website
            if extracted.get("website") and not self.profile.contact.official_website:
                self.profile.contact.official_website = extracted["website"]
            
            # LinkedIn
            if extracted.get("linkedin") and not self.profile.social_media.linkedin:
                self.profile.social_media.linkedin = extracted["linkedin"]
            
            # Sector
            if extracted.get("sector") and not self.profile.basic_info.sector:
                self.profile.basic_info.sector = extracted["sector"]
            
            # Country
            if extracted.get("country") and not self.profile.basic_info.country:
                self.profile.basic_info.country = extracted["country"]
            
            # Employee count
            if extracted.get("employee_count") and not self.profile.basic_info.employee_count:
                self.profile.basic_info.employee_count = extracted["employee_count"]
            
            # IT classification
            if extracted.get("is_it_company") is not None:
                self.profile.basic_info.is_it_company = extracted["is_it_company"]
            
            # Certifications
            if extracted.get("certifications"):
                certs = extracted["certifications"]
                for cert_name in certs:
                    cert_name_lower = cert_name.lower().replace("-", "_").replace(" ", "_")
                    if hasattr(self.profile.security_compliance, cert_name_lower):
                        setattr(self.profile.security_compliance, cert_name_lower, True)
            
            # Data breaches
            if extracted.get("data_breaches"):
                for breach_desc in extracted["data_breaches"]:
                    breach = DataBreach()
                    breach.description = str(breach_desc)[:300]
                    self.profile.security_incidents.data_breaches.append(breach)
            
            # CVEs
            if extracted.get("cves"):
                for cve_desc in extracted["cves"]:
                    cve_obj = CVEVulnerability()
                    if isinstance(cve_desc, dict):
                        cve_obj.cve_id = cve_desc.get("cve_id", "")
                        cve_obj.description = cve_desc.get("description", "")
                    else:
                        cve_obj.description = str(cve_desc)
                    if cve_obj.cve_id or cve_obj.description:
                        self.profile.security_incidents.cve_vulnerabilities.append(cve_obj)
                        
        except Exception as e:
            logger.error(f"Error merging extracted data: {str(e)}")


# Keep backward compatible function name
CompanyInfoExtractor = TPRMExtractor


def extract_company_info(company_name: str, pages: list[ScrapedPage], use_llm: bool = True) -> dict:
    """
    Convenience function to extract company information (simplified)
    """
    extractor = TPRMExtractor(company_name, use_llm)
    profile = extractor.extract_from_pages(pages)
    return profile.model_dump()
