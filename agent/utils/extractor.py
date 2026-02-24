"""
TPRM-focused Company Information Extraction
Combines fast regex pre-extraction with LLM-powered deep extraction
to produce the full target JSON structure.
"""
import re
import logging
from typing import Optional
from datetime import datetime, timezone

from .states import (
    CompanyTPRMProfile, CompanyBasicInfo, CompanyContact,
    CompanySocialMedia, CompanySecurityCompliance,
    CompanySecurityIncidents, ISOCertification,
    DataBreach, CVEVulnerability, RiskIndicator, RawSource,
    ScrapedPage,
)
from .constants import IT_INDUSTRY_KEYWORDS, IT_SUB_SERVICES
from .helpers import extract_emails, extract_phones, extract_social_links, clean_text
from .llm import extract_tprm_info_with_llm

logger = logging.getLogger(__name__)


class TPRMExtractor:
    """Extract TPRM-focus company information from scraped pages."""

    def __init__(self, company_name: str, use_llm: bool = True):
        self.company_name = company_name
        self.use_llm = use_llm
        self.profile = CompanyTPRMProfile()
        self.profile.basic_info.name = company_name
        self.profile.search_timestamp = datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def extract_from_pages(self, pages: list[ScrapedPage]) -> CompanyTPRMProfile:
        """Extract company profile from scraped pages."""
        successful = [p for p in pages if p.success and p.content]
        if not successful:
            logger.warning("No successful pages to extract from")
            return self.profile

        # Phase 1 – Quick regex extraction from ALL pages
        for page in successful:
            self._regex_extract(page)
            self._collect_source(page)

        # Phase 2 – LLM deep extraction (combine top pages into one call)
        if self.use_llm and successful:
            self._llm_extract(successful[:5])

        # Phase 3 – Post-processing
        self._classify_it_company()
        self._compute_incident_counts()
        self._generate_risk_indicators()
        self._compute_data_quality()

        return self.profile

    # ------------------------------------------------------------------
    # PHASE 1: Regex-based fast extraction
    # ------------------------------------------------------------------

    def _regex_extract(self, page: ScrapedPage):
        content = page.content
        html = page.html
        url = page.url

        self._extract_website(content, html, url)
        self._extract_linkedin(html, url)
        self._extract_social_media(html, url)
        self._extract_contact_info(content, html, url)
        self._extract_sector_and_country(content)
        self._extract_company_size(content)
        self._extract_description(content, page.metadata, url)
        self._extract_founded(content)
        self._extract_headquarters(content)
        self._extract_certifications(content)
        self._extract_security_pages(content, html, url)
        self._extract_breach_info(content, url)
        self._extract_cve_info(content, url)

    # Domains that should NEVER be treated as the company's official website
    _THIRD_PARTY_DOMAINS = {
        'linkedin.com', 'wikipedia.org', 'crunchbase.com', 'bloomberg.com',
        'reuters.com', 'github.com', 'twitter.com', 'x.com', 'facebook.com',
        'youtube.com', 'glassdoor.com', 'indeed.com', 'zoominfo.com',
        'dnb.com', 'nvd.nist.gov', 'cve.mitre.org', 'bleepingcomputer.com',
        'securityweek.com', 'therecord.media', 'darkreading.com',
        'hackerone.com', 'bugcrowd.com',
    }

    def _is_third_party(self, url: str) -> bool:
        """Check if a URL belongs to a known third-party domain."""
        domain = url.lower().replace('www.', '')
        return any(tp in domain for tp in self._THIRD_PARTY_DOMAINS)

    def _is_company_page(self, url: str) -> bool:
        """Check if a URL likely belongs to the company itself."""
        company_lower = self.company_name.lower().replace(" ", "").replace("-", "")
        domain = url.lower().replace('www.', '')
        return company_lower in domain and not self._is_third_party(url)

    def _extract_website(self, content: str, html: str, url: str):
        if self.profile.contact.official_website:
            return
        company_lower = self.company_name.lower().replace(" ", "")
        url_lower = url.lower()

        # Only accept the URL as official site if it's NOT a third-party domain
        if (company_lower in url_lower
                and not self._is_third_party(url)
                and any(x in url_lower for x in ['.com', '.fr', '.org', '.io', '.de', '.uk', '.co'])):
            self._set_website(url)
            return

        # Search the HTML for the company's own domain
        pattern = rf'(https?://(?:www\.)?{re.escape(company_lower)}\.(?:com|fr|org|io|de|uk|co))'
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            w = match.group(1).rstrip('/')
            if not self._is_third_party(w):
                self._set_website(w)

    def _set_website(self, url: str):
        self.profile.contact.official_website = url
        self.profile.basic_info.website = url
        self.profile.basic_info.website_url = url

    def _extract_linkedin(self, html: str, url: str):
        if self.profile.social_media.linkedin:
            return
        company_lower = self.company_name.lower().replace(" ", "").replace("-", "")
        # If current URL is a LinkedIn company page for THIS company
        if "linkedin.com" in url.lower() and "/company/" in url.lower():
            # Make sure the LinkedIn page is for our company
            if company_lower in url.lower().replace("-", ""):
                # Normalize: strip /about/ and locale prefixes
                clean = re.search(r'(https?://(?:\w+\.)?linkedin\.com/company/[a-z0-9\-]+)', url, re.IGNORECASE)
                if clean:
                    self._set_linkedin(clean.group(1))
                    return
        # Search HTML for LinkedIn company link matching our company
        for m in re.finditer(r'(https?://(?:www\.)?linkedin\.com/company/([a-z0-9\-]+))', html, re.IGNORECASE):
            slug = m.group(2).lower().replace("-", "")
            if company_lower in slug or slug in company_lower:
                self._set_linkedin(m.group(1))
                return

    def _set_linkedin(self, url: str):
        self.profile.social_media.linkedin = url
        self.profile.basic_info.linkedin_url = url
        self.profile.basic_info.linkedin = url

    def _extract_social_media(self, html: str, url: str):
        """Only extract social links from pages that BELONG to the company."""
        if not self._is_company_page(url):
            return  # Don't pick up NIST/other org social links from CVE pages etc.

        social = extract_social_links(html)
        if social.get("twitter") and not self.profile.social_media.twitter:
            self.profile.social_media.twitter = social["twitter"]
        if social.get("facebook") and not self.profile.social_media.facebook:
            self.profile.social_media.facebook = social["facebook"]
        if social.get("github") and not self.profile.social_media.github:
            self.profile.social_media.github = social["github"]
        if social.get("youtube") and not self.profile.social_media.youtube:
            self.profile.social_media.youtube = social["youtube"]

    def _extract_contact_info(self, content: str, html: str, url: str):
        """Extract contact info – only trust emails from company-owned pages."""
        if not self._is_company_page(url):
            return  # Don't pick up random emails from third-party pages

        if not self.profile.contact.email:
            emails = extract_emails(content + " " + html)
            company_lower = self.company_name.lower().replace(" ", "")
            # Prefer emails that belong to the company domain
            company_emails = [e for e in emails if company_lower in e.lower().replace("-", "").replace(".", "")]
            generic_prefixes = ['info@', 'contact@', 'support@', 'hello@', 'sales@']
            for e in (company_emails or emails):
                if any(p in e.lower() for p in generic_prefixes):
                    self.profile.contact.email = e
                    break
            if not self.profile.contact.email and company_emails:
                self.profile.contact.email = company_emails[0]
            # secondary roles
            for e in (company_emails or emails):
                if 'support@' in e.lower() and not self.profile.contact.support_email:
                    self.profile.contact.support_email = e
                if 'security@' in e.lower() and not self.profile.contact.security_contact:
                    self.profile.contact.security_contact = e

        if not self.profile.contact.phone:
            phones = extract_phones(content)
            if phones:
                self.profile.contact.phone = phones[0]

    def _extract_sector_and_country(self, content: str):
        content_lower = content.lower()

        if not self.profile.basic_info.sector:
            patterns = [
                r'(?:industry|sector|specializ(?:es|ing) in)[:\s]+([^.\n]{3,80})',
            ]
            for p in patterns:
                m = re.search(p, content_lower)
                if m:
                    self.profile.basic_info.sector = clean_text(m.group(1))[:80]
                    break

        if not self.profile.basic_info.country:
            # Only extract country from headquarter-context patterns (not stray mentions)
            country_with_context = [
                r'(?:headquartered|headquarters|based|located)\s+(?:in|at)\s+[^,]*?,\s*([A-Z][a-z]+(?:\s[A-Z][a-z]+)*)',
                r'(?:headquartered|headquarters|based|located)\s+(?:in|at)\s+([A-Z][a-z]+(?:\s[A-Z][a-z]+)*)',
                r'country[:\s]+([A-Z][a-z]+(?:\s[A-Z][a-z]+)*)',
            ]
            countries_set = {
                "united states", "usa", "france", "germany", "united kingdom", "canada",
                "australia", "india", "singapore", "switzerland", "netherlands",
                "japan", "israel", "spain", "italy", "brazil", "china",
                "south korea", "sweden", "norway", "denmark", "finland",
                "belgium", "ireland", "new zealand", "uae", "morocco",
            }
            for p in country_with_context:
                m = re.search(p, content, re.IGNORECASE)
                if m:
                    candidate = m.group(1).strip()
                    if candidate.lower() in countries_set:
                        self.profile.basic_info.country = candidate
                        break

    def _extract_company_size(self, content: str):
        if self.profile.basic_info.employee_count:
            return
        patterns = [
            r'(\d{1,3}(?:,\d{3})*)\s*(?:\+\s*)?employees',
            r'team\s+of\s+(\d{1,3}(?:,\d{3})*)',
            r'(\d{1,6})-(\d{1,6})\s*employees',
            r'(\d+(?:,\d+)?)\s*staff',
        ]
        for p in patterns:
            m = re.search(p, content.lower())
            if m:
                val = m.group(1)
                self.profile.basic_info.employee_count = val
                self.profile.basic_info.employees = val
                return

    # Country normalization map
    _COUNTRY_NORMALIZE = {
        'us': 'United States', 'usa': 'United States', 'u.s.': 'United States',
        'u.s.a.': 'United States', 'uk': 'United Kingdom', 'u.k.': 'United Kingdom',
        'uae': 'United Arab Emirates',
    }

    def _normalize_country(self, country: str) -> str:
        """Normalize country abbreviations to full names."""
        if not country:
            return country
        normalized = self._COUNTRY_NORMALIZE.get(country.lower().strip(), country)
        # Title-case if it looks like an abbreviation was expanded
        return normalized

    def _extract_description(self, content: str, metadata: dict, url: str = ""):
        if self.profile.basic_info.description:
            return

        # Skip generic third-party descriptions (LinkedIn login, Wikipedia boilerplate)
        skip_desc_patterns = ['login to linkedin', 'sign in', 'from wikipedia',
                              'free encyclopedia', 'create an account']

        # Use meta description only from company-owned pages
        desc = metadata.get("description", "")
        if desc and len(desc) > 30:
            desc_lower = desc.lower()
            if not any(sp in desc_lower for sp in skip_desc_patterns):
                if self._is_company_page(url) or self.company_name.lower() in desc_lower:
                    self.profile.basic_info.description = desc[:500]
                    return

        # Fallback: first 2 sentences containing company name
        company_lower = self.company_name.lower()
        sentences = re.split(r'[.!?]\s+', content)
        relevant = [s.strip() for s in sentences
                    if company_lower in s.lower() and len(s.strip()) > 30
                    and not any(sp in s.lower() for sp in skip_desc_patterns)]
        if relevant:
            self.profile.basic_info.description = ". ".join(relevant[:2])[:500]

    def _extract_founded(self, content: str):
        if self.profile.basic_info.founded:
            return
        patterns = [
            r'(?:founded|established|incorporated)\s+(?:in\s+)?(\d{4})',
            r'since\s+(\d{4})',
        ]
        for p in patterns:
            m = re.search(p, content.lower())
            if m and 1800 <= int(m.group(1)) <= 2026:
                self.profile.basic_info.founded = m.group(1)
                return

    def _extract_headquarters(self, content: str):
        if self.profile.basic_info.headquarters:
            return
        patterns = [
            r'(?:headquartered|headquarters|based)\s+(?:in|at)\s+([^.\n]{5,80})',
            r'(?:head\s*office)[:\s]+([^.\n]{5,80})',
        ]
        for p in patterns:
            m = re.search(p, content, re.IGNORECASE)
            if m:
                hq = clean_text(m.group(1))[:100]
                self.profile.basic_info.headquarters = hq
                if not self.profile.contact.address:
                    self.profile.contact.address = hq
                return

    def _extract_certifications(self, content: str):
        content_lower = content.lower()
        sc = self.profile.security_compliance

        cert_checks = {
            'iso_27001': [r'iso\s*27001', r'iso/iec\s*27001'],
            'iso_27017': [r'iso\s*27017'],
            'iso_27018': [r'iso\s*27018'],
            'iso_9001':  [r'iso\s*9001'],
            'iso_14001': [r'iso\s*14001'],
            'iso_22301': [r'iso\s*22301'],
        }
        for field, patterns in cert_checks.items():
            for pat in patterns:
                if re.search(pat, content_lower):
                    if getattr(sc, field) is None:
                        setattr(sc, field, ISOCertification(
                            name=field.replace("_", " ").upper(),
                            status="Certified",
                        ))
                    break

        # Boolean certs
        bool_checks = {
            'soc2_type2': [r'soc\s*2\s*type\s*(?:ii|2)', r'soc2\s*type\s*(?:ii|2)'],
            'soc2_type1': [r'soc\s*2\s*type\s*(?:i|1)', r'soc2\s*type\s*(?:i|1)'],
            'soc1': [r'soc\s*1(?!\d)'],
            'pci_dss': [r'pci[\s\-]*dss'],
            'hipaa_compliant': [r'hipaa'],
            'gdpr_compliant': [r'gdpr'],
            'fedramp': [r'fedramp'],
        }
        for field, patterns in bool_checks.items():
            for pat in patterns:
                if re.search(pat, content_lower):
                    setattr(sc, field, True)
                    break

        # Generic SOC 2 → default to type 2
        if re.search(r'soc\s*2(?!\s*type)', content_lower) and not sc.soc2_type2 and not sc.soc2_type1:
            sc.soc2_type2 = True

    def _extract_security_pages(self, content: str, html: str, url: str):
        sc = self.profile.security_compliance
        url_lower = url.lower()

        # Only detect from company-owned or company-related domains
        is_own = self._is_company_page(url)

        if is_own and ('/security' in url_lower or '/trust' in url_lower):
            if 'trust' in url_lower:
                sc.has_trust_center = True
                if not sc.trust_center_url:
                    sc.trust_center_url = url
            if 'security' in url_lower:
                sc.has_security_page = True
                if not sc.security_page_url:
                    sc.security_page_url = url

        # Detect security/trust links in HTML — only from company-owned pages
        if self._is_company_page(url):
            for m in re.finditer(r'href=["\']([^"\']*(?:security|trust)[^"\']*)["\']', html, re.IGNORECASE):
                link = m.group(1)
                if 'trust' in link.lower():
                    sc.has_trust_center = True
                    if not sc.trust_center_url:
                        sc.trust_center_url = link
                if 'security' in link.lower() and 'incident' not in link.lower():
                    sc.has_security_page = True
                    if not sc.security_page_url:
                        sc.security_page_url = link

        # Bug bounty
        bounty_patterns = [r'bug\s*bounty', r'hackerone\.com', r'bugcrowd\.com', r'responsible\s*disclosure']
        if any(re.search(p, content.lower()) for p in bounty_patterns):
            sc.has_bug_bounty = True
            bounty_url_m = re.search(r'(https?://(?:www\.)?(?:hackerone|bugcrowd)\.com/[^\s"<>]+)', html, re.IGNORECASE)
            if bounty_url_m and not sc.bug_bounty_url:
                sc.bug_bounty_url = bounty_url_m.group(1)

    def _extract_breach_info(self, content: str, url: str):
        content_lower = content.lower()
        company_lower = self.company_name.lower()

        # Require at least TWO breach-indicating keywords to avoid false positives
        breach_keywords = ['data breach', 'data leak', 'hacked', 'compromised',
                           'exposed data', 'ransomware attack', 'security breach',
                           'unauthorized access', 'data exposed']
        matches = [kw for kw in breach_keywords if kw in content_lower]
        if len(matches) < 1:
            return
        if company_lower not in content_lower:
            return

        # Extra guard: skip encyclopedia / about pages (avoid Wikipedia false positives)
        skip_indicators = ['from wikipedia', 'free encyclopedia', 'company type', 'traded as']
        skip_count = sum(1 for s in skip_indicators if s in content_lower)
        if skip_count >= 2 and len(matches) < 2:
            return  # Likely an about/wiki page, not a breach report

        breach = DataBreach()
        breach.source_url = url

        # Extract date – prefer dates near breach keywords for accuracy
        date_near_breach = None
        for kw in matches:
            idx = content_lower.find(kw)
            if idx >= 0:
                context = content[max(0, idx - 200):idx + 200]
                dm = re.search(r'((?:january|february|march|april|may|june|july|august|september|october|november|december)\s+\d{1,2},?\s*\d{4}|\d{4}-\d{2}-\d{2})', context, re.IGNORECASE)
                if dm:
                    date_near_breach = dm.group(0).strip()
                    break
        if date_near_breach:
            breach.date = date_near_breach
        else:
            dm = re.search(r'((?:january|february|march|april|may|june|july|august|september|october|november|december)\s+\d{1,2},?\s*\d{4}|\d{4}-\d{2}-\d{2})', content_lower)
            if dm:
                breach.date = dm.group(0).strip()

        # Description – take content near the first breach keyword
        first_kw_idx = min(content_lower.find(kw) for kw in matches if content_lower.find(kw) >= 0)
        desc_start = max(0, first_kw_idx - 50)
        breach.description = content[desc_start:desc_start + 300].strip()

        # severity heuristic
        if any(w in content_lower for w in ['critical', 'massive', 'millions']):
            breach.severity = "Critical"
        elif any(w in content_lower for w in ['significant', 'major', 'serious']):
            breach.severity = "High"
        else:
            breach.severity = "Medium"

        # records
        rm = re.search(r'(\d[\d,.]*)\s*(?:records|accounts|users|customers)\s*(?:affected|exposed|compromised)', content_lower)
        if rm:
            breach.records_affected = rm.group(1)

        # types exposed
        type_keywords = {'email': 'email addresses', 'password': 'passwords', 'credit card': 'credit card numbers',
                         'ssn': 'SSN', 'social security': 'SSN', 'personal': 'personal information',
                         'health': 'health records', 'financial': 'financial data'}
        for kw, label in type_keywords.items():
            if kw in content_lower:
                breach.data_types_exposed.append(label)

        # ransomware
        if 'ransomware' in content_lower:
            self.profile.security_incidents.ransomware_history = True

        # dedup
        existing = {b.source_url + b.date for b in self.profile.security_incidents.data_breaches}
        if (breach.source_url + breach.date) not in existing:
            self.profile.security_incidents.data_breaches.append(breach)

    def _extract_cve_info(self, content: str, url: str):
        cve_ids = set(re.findall(r'CVE-\d{4}-\d{4,7}', content, re.IGNORECASE))
        for cve_id in cve_ids:
            cid = cve_id.upper()
            if cid in {v.cve_id for v in self.profile.security_incidents.cve_vulnerabilities}:
                continue

            cve = CVEVulnerability(cve_id=cid)

            # severity
            sev_m = re.search(rf'{re.escape(cve_id)}[^.]*?(critical|high|medium|low)', content, re.IGNORECASE)
            if sev_m:
                cve.severity = sev_m.group(1).capitalize()

            # CVSS
            cvss_m = re.search(rf'{re.escape(cve_id)}[^.]*?(\d\.\d)', content, re.IGNORECASE)
            if cvss_m:
                try:
                    cve.cvss_score = float(cvss_m.group(1))
                except ValueError:
                    pass

            # patched
            if re.search(rf'{re.escape(cve_id)}[^.]*?(?:patched|fixed|resolved)', content, re.IGNORECASE):
                cve.patched = True

            # affected product
            prod_m = re.search(rf'{re.escape(cve_id)}[^.]*?(?:affects?|in)\s+([^,.;\n]+)', content, re.IGNORECASE)
            if prod_m:
                cve.affected_product = prod_m.group(1).strip()[:150]

            # description
            ctx_m = re.search(rf'(.{{0,200}}{re.escape(cve_id)}.{{0,200}})', content, re.IGNORECASE)
            if ctx_m:
                cve.description = ctx_m.group(1).strip()[:300]

            self.profile.security_incidents.cve_vulnerabilities.append(cve)

    def _collect_source(self, page: ScrapedPage):
        """Add page as a raw source."""
        src = RawSource(
            title=page.title or page.url,
            snippet=(page.metadata.get("description", "") or page.content[:200])[:200],
            url=page.url,
            source="website",
            type=self._classify_source_type(page.url, page.content),
            confidence=round(self._page_confidence(page), 2),
        )
        self.profile.raw_sources.append(src)

    def _classify_source_type(self, url: str, content: str) -> str:
        url_lower = url.lower()
        content_lower = content.lower()
        if any(k in url_lower for k in ['security', 'trust', 'compliance']):
            return "security"
        if any(k in url_lower for k in ['about', 'company', 'who-we-are']):
            return "company_info"
        if 'linkedin.com' in url_lower:
            return "social"
        if any(k in content_lower for k in ['breach', 'cve', 'vulnerability']):
            return "security"
        return "general"

    def _page_confidence(self, page: ScrapedPage) -> float:
        score = 0.5
        url_lower = page.url.lower()
        company_lower = self.company_name.lower().replace(" ", "")
        if company_lower in url_lower:
            score += 0.3
        if page.content and len(page.content) > 500:
            score += 0.1
        if page.title and self.company_name.lower() in page.title.lower():
            score += 0.1
        return min(score, 1.0)

    # ------------------------------------------------------------------
    # PHASE 2: LLM extraction
    # ------------------------------------------------------------------

    def _llm_extract(self, pages: list[ScrapedPage]):
        combined = ""
        for page in pages[:5]:
            combined += f"\n---\nSource: {page.url}\nTitle: {page.title}\n{page.content[:4000]}\n"

        try:
            extracted = extract_tprm_info_with_llm(combined, self.company_name)
            if extracted:
                self._merge_llm_data(extracted)
        except Exception as e:
            logger.error(f"LLM extraction failed: {e}")

    def _merge_llm_data(self, data: dict):
        """Merge LLM-extracted data into profile; LLM wins for empty fields."""
        p = self.profile

        # Basic info
        bi = data.get("basic_info", {})
        if isinstance(bi, dict):
            for field in ['name', 'website', 'website_url', 'linkedin_url', 'linkedin',
                          'description', 'founded', 'headquarters', 'employees',
                          'employee_count', 'industry', 'sector', 'country',
                          'it_classification']:
                val = bi.get(field, "")
                if val and not getattr(p.basic_info, field, ""):
                    # Normalize country
                    if field == 'country':
                        val = self._normalize_country(str(val))
                    # Skip generic descriptions
                    if field == 'description':
                        skip = ['login to linkedin', 'sign in', 'from wikipedia']
                        if any(s in str(val).lower() for s in skip):
                            continue
                    setattr(p.basic_info, field, str(val))

            if bi.get("is_it_company") is True:
                p.basic_info.is_it_company = True

            if bi.get("sub_services") and not p.basic_info.sub_services:
                p.basic_info.sub_services = bi["sub_services"][:20]

        # Contact
        ct = data.get("contact", {})
        if isinstance(ct, dict):
            for field in ['official_website', 'email', 'phone', 'address', 'support_email', 'security_contact']:
                val = ct.get(field, "")
                if val and not getattr(p.contact, field, ""):
                    setattr(p.contact, field, str(val))

        # Social media — validate that URLs plausibly belong to this company
        sm = data.get("social_media", {})
        if isinstance(sm, dict):
            company_lower = self.company_name.lower().replace(" ", "").replace("-", "")
            for field in ['linkedin', 'twitter', 'facebook', 'github', 'youtube']:
                val = sm.get(field, "")
                if val and not getattr(p.social_media, field, ""):
                    # Validate: the social URL should contain the company name in the path/handle
                    val_lower = val.lower().replace("-", "").replace("_", "")
                    if company_lower in val_lower:
                        setattr(p.social_media, field, str(val))

        # Security compliance
        sc_data = data.get("security_compliance", {})
        if isinstance(sc_data, dict):
            # ISO certs (dict or null)
            for iso_field in ['iso_27001', 'iso_27017', 'iso_27018', 'iso_9001', 'iso_14001', 'iso_22301']:
                iso_val = sc_data.get(iso_field)
                if isinstance(iso_val, dict) and iso_val.get("status"):
                    if getattr(p.security_compliance, iso_field) is None:
                        setattr(p.security_compliance, iso_field, ISOCertification(**{
                            k: iso_val.get(k, "") for k in ['name', 'status', 'expiry_date', 'certification_body', 'scope']
                        }))

            # boolean certs
            for bool_field in ['soc2_type1', 'soc2_type2', 'soc1', 'pci_dss',
                               'hipaa_compliant', 'gdpr_compliant', 'fedramp',
                               'has_security_page', 'has_trust_center', 'has_bug_bounty']:
                val = sc_data.get(bool_field)
                if val is True:
                    setattr(p.security_compliance, bool_field, True)

            # URL fields
            for url_field in ['security_page_url', 'trust_center_url', 'bug_bounty_url']:
                val = sc_data.get(url_field, "")
                if val and not getattr(p.security_compliance, url_field, ""):
                    setattr(p.security_compliance, url_field, str(val))

            # other certs
            oc = sc_data.get("other_certifications", [])
            if oc and isinstance(oc, list):
                existing = set(p.security_compliance.other_certifications)
                for c in oc:
                    if isinstance(c, str) and c not in existing:
                        p.security_compliance.other_certifications.append(c)

        # Security incidents
        si_data = data.get("security_incidents", {})
        if isinstance(si_data, dict):
            for breach_data in si_data.get("data_breaches", []):
                if isinstance(breach_data, dict):
                    breach = DataBreach(**{k: breach_data.get(k, v)
                                          for k, v in [('date', ''), ('description', ''),
                                                       ('records_affected', ''), ('source_url', ''),
                                                       ('severity', '')]})
                    if breach_data.get('data_types_exposed'):
                        breach.data_types_exposed = breach_data['data_types_exposed']
                    # dedup
                    existing = {b.description[:50] for b in p.security_incidents.data_breaches}
                    if breach.description[:50] not in existing:
                        p.security_incidents.data_breaches.append(breach)

            for cve_data in si_data.get("cve_vulnerabilities", []):
                if isinstance(cve_data, dict) and cve_data.get("cve_id"):
                    existing_ids = {v.cve_id for v in p.security_incidents.cve_vulnerabilities}
                    if cve_data["cve_id"] not in existing_ids:
                        cve = CVEVulnerability(**{k: cve_data.get(k, v)
                                                  for k, v in [('cve_id', ''), ('description', ''),
                                                               ('severity', ''), ('affected_product', ''),
                                                               ('published_date', '')]})
                        if cve_data.get('cvss_score') is not None:
                            cve.cvss_score = cve_data['cvss_score']
                        if cve_data.get('patched') is True:
                            cve.patched = True
                        p.security_incidents.cve_vulnerabilities.append(cve)

            if si_data.get("ransomware_history") is True:
                p.security_incidents.ransomware_history = True

        # Risk indicators
        ri_data = data.get("overall_risk_indicators", [])
        if isinstance(ri_data, list):
            for ri in ri_data:
                if isinstance(ri, dict):
                    p.overall_risk_indicators.append(RiskIndicator(**{
                        k: ri.get(k, "") for k in ['category', 'indicator', 'severity', 'details']
                    }))

    # ------------------------------------------------------------------
    # PHASE 3: Post-processing
    # ------------------------------------------------------------------

    def _classify_it_company(self):
        text = f"{self.profile.basic_info.sector} {self.profile.basic_info.industry} {self.profile.basic_info.description}".lower()

        it_keywords = [
            "software", "technology", "it", "cloud", "saas", "data",
            "cyber", "security", "ai", "digital", "tech", "development",
            "programming", "engineering", "it services", "consulting",
            "platform", "api", "devops", "infrastructure",
        ]

        if any(kw in text for kw in it_keywords):
            self.profile.basic_info.is_it_company = True

            # IT classification
            if not self.profile.basic_info.it_classification:
                for cat, keywords in IT_SUB_SERVICES.items():
                    if any(kw in text for kw in keywords):
                        self.profile.basic_info.it_classification = f"IT - {cat.replace('_', ' ').title()}"
                        break

            # Sub-services
            if not self.profile.basic_info.sub_services:
                subs = []
                for cat, keywords in IT_SUB_SERVICES.items():
                    if any(kw in text for kw in keywords):
                        subs.append(cat.replace("_", " ").title())
                self.profile.basic_info.sub_services = subs[:10]

    def _compute_incident_counts(self):
        si = self.profile.security_incidents
        si.breach_count = len(si.data_breaches)
        if si.data_breaches:
            dates = [b.date for b in si.data_breaches if b.date]
            si.last_breach_date = max(dates) if dates else ""

        si.cve_count = len(si.cve_vulnerabilities)
        si.critical_cve_count = sum(
            1 for v in si.cve_vulnerabilities
            if v.severity.lower() == "critical" or (v.cvss_score and v.cvss_score >= 9.0)
        )

    def _generate_risk_indicators(self):
        """Auto-generate risk indicators based on findings."""
        if self.profile.overall_risk_indicators:
            return  # LLM already provided them

        indicators = []
        si = self.profile.security_incidents
        sc = self.profile.security_compliance
        bi = self.profile.basic_info

        if si.breach_count > 0:
            indicators.append(RiskIndicator(
                category="Security",
                indicator=f"{si.breach_count} data breach(es) recorded",
                severity="High" if si.breach_count > 1 else "Medium",
                details=f"Last breach: {si.last_breach_date}" if si.last_breach_date else "",
            ))

        if si.ransomware_history:
            indicators.append(RiskIndicator(
                category="Security",
                indicator="Ransomware history detected",
                severity="Critical",
                details="Company has been a victim of ransomware attack(s)",
            ))

        if si.critical_cve_count > 0:
            indicators.append(RiskIndicator(
                category="Security",
                indicator=f"{si.critical_cve_count} critical CVE(s)",
                severity="High",
                details=f"Total CVEs: {si.cve_count}",
            ))

        if sc.iso_27001 is None:
            indicators.append(RiskIndicator(
                category="Compliance",
                indicator="No ISO 27001 certification found",
                severity="Medium",
                details="Information security management certification not detected",
            ))

        if bi.country:
            indicators.append(RiskIndicator(
                category="Geopolitical",
                indicator=f"Based in {bi.country}",
                severity="Low",
                details=f"Headquartered in {bi.headquarters}" if bi.headquarters else "",
            ))

        self.profile.overall_risk_indicators = indicators

    def _compute_data_quality(self):
        """Score from 0.0 to 1.0 indicating how complete the profile is."""
        filled = 0
        total = 0

        # Basic info checks
        for f in ['name', 'description', 'sector', 'country', 'employee_count', 'founded', 'headquarters']:
            total += 1
            if getattr(self.profile.basic_info, f, ""):
                filled += 1

        # Contact
        for f in ['official_website', 'email', 'phone']:
            total += 1
            if getattr(self.profile.contact, f, ""):
                filled += 1

        # Social
        for f in ['linkedin', 'twitter']:
            total += 1
            if getattr(self.profile.social_media, f, ""):
                filled += 1

        # Security – just check if ANY cert info exists
        total += 1
        sc = self.profile.security_compliance
        has_any_cert = any([
            sc.iso_27001, sc.iso_27017, sc.iso_9001,
            sc.soc2_type1, sc.soc2_type2, sc.soc1,
            sc.pci_dss, sc.hipaa_compliant, sc.gdpr_compliant,
        ])
        if has_any_cert:
            filled += 1

        # Sources
        total += 1
        if len(self.profile.raw_sources) >= 3:
            filled += 1

        self.profile.data_quality_score = round(filled / total, 2) if total > 0 else 0.0


# Backward compat
CompanyInfoExtractor = TPRMExtractor


def extract_company_info(company_name: str, pages: list[ScrapedPage], use_llm: bool = True) -> dict:
    """Convenience function."""
    extractor = TPRMExtractor(company_name, use_llm)
    profile = extractor.extract_from_pages(pages)
    return profile.model_dump()
