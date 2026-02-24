"""
State management for the TPRM (Third Party Risk Management) scraping agent
Full-fidelity models matching the target JSON output structure
"""
from typing import TypedDict, Optional, Annotated, Any
from operator import add
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Profile sub-models – mirrors the target JSON exactly
# ---------------------------------------------------------------------------

class CompanyBasicInfo(BaseModel):
    """Essential company identification fields"""
    name: str = ""
    website: str = ""
    website_url: str = ""
    linkedin_url: str = ""
    linkedin: str = ""
    description: str = ""
    founded: str = ""
    headquarters: str = ""
    employees: str = ""
    employee_count: str = ""
    industry: str = ""
    sector: str = ""
    country: str = ""
    is_it_company: bool = False
    it_classification: str = ""
    sub_services: list[str] = Field(default_factory=list)


class CompanyContact(BaseModel):
    """Contact information"""
    official_website: str = ""
    email: str = ""
    phone: str = ""
    address: str = ""
    support_email: str = ""
    security_contact: str = ""


class CompanySocialMedia(BaseModel):
    """Social media presence"""
    linkedin: str = ""
    twitter: str = ""
    facebook: str = ""
    github: str = ""
    youtube: str = ""


class ISOCertification(BaseModel):
    """Detailed ISO certification record"""
    name: str = ""
    status: str = ""  # "Certified" | "Not Certified" | ""
    expiry_date: str = ""
    certification_body: str = ""
    scope: str = ""


class CompanySecurityCompliance(BaseModel):
    """Security and compliance certifications"""
    # ISO Certifications – rich objects or None
    iso_27001: Optional[ISOCertification] = None
    iso_27017: Optional[ISOCertification] = None
    iso_27018: Optional[ISOCertification] = None
    iso_9001: Optional[ISOCertification] = None
    iso_14001: Optional[ISOCertification] = None
    iso_22301: Optional[ISOCertification] = None

    # SOC split
    soc2_type1: bool = False
    soc2_type2: bool = False
    soc1: bool = False

    # Other security standards
    pci_dss: bool = False
    hipaa_compliant: bool = False
    gdpr_compliant: bool = False
    fedramp: bool = False

    other_certifications: list[str] = Field(default_factory=list)

    # Security pages
    has_security_page: bool = False
    security_page_url: str = ""
    has_trust_center: bool = False
    trust_center_url: str = ""
    has_bug_bounty: bool = False
    bug_bounty_url: str = ""


class DataBreach(BaseModel):
    """Data breach incident record"""
    date: str = ""
    description: str = ""
    records_affected: str = ""
    data_types_exposed: list[str] = Field(default_factory=list)
    source_url: str = ""
    severity: str = ""  # "High", "Medium", "Low", "Critical"


class CVEVulnerability(BaseModel):
    """CVE vulnerability record"""
    cve_id: str = ""
    description: str = ""
    severity: str = ""
    cvss_score: Optional[float] = None
    affected_product: str = ""
    patched: bool = False
    published_date: str = ""


class CompanySecurityIncidents(BaseModel):
    """Security incidents – data breaches and CVEs"""
    data_breaches: list[DataBreach] = Field(default_factory=list)
    breach_count: int = 0
    last_breach_date: str = ""
    cve_vulnerabilities: list[CVEVulnerability] = Field(default_factory=list)
    cve_count: int = 0
    critical_cve_count: int = 0
    security_incidents: list[dict] = Field(default_factory=list)
    ransomware_history: bool = False


class RiskIndicator(BaseModel):
    """Overall risk indicator"""
    category: str = ""
    indicator: str = ""
    severity: str = ""  # "Low", "Medium", "High", "Critical"
    details: str = ""


class RawSource(BaseModel):
    """Source from which data was collected"""
    title: str = ""
    snippet: str = ""
    url: str = ""
    source: str = ""
    type: str = ""
    confidence: float = 0.0


class CompanyTPRMProfile(BaseModel):
    """Full TPRM company profile matching the target JSON"""
    basic_info: CompanyBasicInfo = Field(default_factory=CompanyBasicInfo)
    contact: CompanyContact = Field(default_factory=CompanyContact)
    social_media: CompanySocialMedia = Field(default_factory=CompanySocialMedia)
    security_compliance: CompanySecurityCompliance = Field(default_factory=CompanySecurityCompliance)
    security_incidents: CompanySecurityIncidents = Field(default_factory=CompanySecurityIncidents)
    overall_risk_indicators: list[RiskIndicator] = Field(default_factory=list)
    raw_sources: list[RawSource] = Field(default_factory=list)
    search_timestamp: str = ""
    data_quality_score: float = 0.0


# Backward compat alias
CompanyProfile = CompanyTPRMProfile


# ---------------------------------------------------------------------------
# Search / scraping intermediary models
# ---------------------------------------------------------------------------

class SearchResult(BaseModel):
    """Search result from DuckDuckGo"""
    title: str
    url: str
    snippet: str
    source: str = ""


class ScrapedPage(BaseModel):
    """Scraped page content"""
    url: str
    title: str = ""
    content: str = ""
    html: str = ""
    links: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)
    success: bool = True
    error: str = ""


# ---------------------------------------------------------------------------
# LangGraph agent state
# ---------------------------------------------------------------------------

class AgentState(TypedDict):
    """State for the LangGraph agent"""
    # Input
    company_name: str
    search_queries: list[str]

    # Search phase
    search_results: Annotated[list[dict], add]
    urls_to_scrape: list[str]

    # Scraping phase
    scraped_pages: Annotated[list[dict], add]
    failed_urls: list[str]

    # Extraction phase
    extracted_info: dict
    company_profile: Optional[dict]

    # Workflow control
    current_step: str
    errors: Annotated[list[str], add]
    messages: Annotated[list[str], add]
    iteration_count: int
    max_iterations: int
