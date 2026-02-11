"""
State management for the TPRM (Third Party Risk Management) scraping agent
"""
from typing import TypedDict, Optional, Annotated
from operator import add
from pydantic import BaseModel, Field


class CompanyBasicInfo(BaseModel):
    """Basic company information for TPRM"""
    name: str = ""
    description: str = ""
    industry: str = ""
    sector: str = ""
    is_it_company: bool = False  # Whether it's an IT/Technology company
    it_classification: str = ""  # e.g., "IT Services", "Software", "Hardware", "Non-IT"
    sub_services: list[str] = Field(default_factory=list)  # Specific services offered
    founded: str = ""
    headquarters: str = ""
    country: str = ""
    employee_count: str = ""


class CompanyContact(BaseModel):
    """Company contact information"""
    official_website: str = ""
    email: str = ""
    phone: str = ""
    address: str = ""
    support_email: str = ""
    security_contact: str = ""  # Security team contact for TPRM


class CompanySocialMedia(BaseModel):
    """Company official online presence"""
    linkedin: str = ""
    twitter: str = ""
    facebook: str = ""
    github: str = ""  # Important for IT companies
    youtube: str = ""


class ISOCertification(BaseModel):
    """ISO and security certification details"""
    name: str = ""  # e.g., "ISO 27001", "ISO 9001"
    status: str = ""  # "Certified", "In Progress", "Expired", "Unknown"
    expiry_date: str = ""
    certification_body: str = ""
    scope: str = ""


class CompanySecurityCompliance(BaseModel):
    """Security and compliance information - CRITICAL for TPRM"""
    # ISO Certifications
    iso_27001: ISOCertification = Field(default_factory=ISOCertification)  # Information Security
    iso_27017: ISOCertification = Field(default_factory=ISOCertification)  # Cloud Security
    iso_27018: ISOCertification = Field(default_factory=ISOCertification)  # Cloud Privacy
    iso_9001: ISOCertification = Field(default_factory=ISOCertification)   # Quality Management
    iso_14001: ISOCertification = Field(default_factory=ISOCertification)  # Environmental
    iso_22301: ISOCertification = Field(default_factory=ISOCertification)  # Business Continuity
    
    # Other Security Certifications
    soc2_type1: bool = False
    soc2_type2: bool = False
    soc1: bool = False
    pci_dss: bool = False  # Payment Card Industry
    hipaa_compliant: bool = False  # Healthcare
    gdpr_compliant: bool = False  # EU Data Protection
    fedramp: bool = False  # US Government cloud
    
    # Additional certifications found
    other_certifications: list[str] = Field(default_factory=list)
    
    # Security practices
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
    severity: str = ""  # "Critical", "High", "Medium", "Low"


class CVEVulnerability(BaseModel):
    """CVE vulnerability record"""
    cve_id: str = ""  # e.g., "CVE-2024-12345"
    description: str = ""
    cvss_score: str = ""
    severity: str = ""  # "Critical", "High", "Medium", "Low"
    affected_product: str = ""
    published_date: str = ""
    patched: bool = False
    source_url: str = ""


class CompanySecurityIncidents(BaseModel):
    """Security incidents and vulnerabilities - CRITICAL for TPRM"""
    # Data Breaches
    data_breaches: list[DataBreach] = Field(default_factory=list)
    breach_count: int = 0
    last_breach_date: str = ""
    
    # CVE Vulnerabilities
    cve_vulnerabilities: list[CVEVulnerability] = Field(default_factory=list)
    cve_count: int = 0
    critical_cve_count: int = 0
    
    # General security news
    security_incidents: list[dict] = Field(default_factory=list)
    ransomware_history: bool = False


class CompanyTPRMProfile(BaseModel):
    """Complete TPRM-focused company profile"""
    # Core Information
    basic_info: CompanyBasicInfo = Field(default_factory=CompanyBasicInfo)
    contact: CompanyContact = Field(default_factory=CompanyContact)
    social_media: CompanySocialMedia = Field(default_factory=CompanySocialMedia)
    
    # TPRM Critical: Security & Compliance
    security_compliance: CompanySecurityCompliance = Field(default_factory=CompanySecurityCompliance)
    security_incidents: CompanySecurityIncidents = Field(default_factory=CompanySecurityIncidents)
    
    # Risk Assessment
    overall_risk_indicators: list[str] = Field(default_factory=list)
    
    # Metadata
    raw_sources: list[dict] = Field(default_factory=list)
    search_timestamp: str = ""
    data_quality_score: float = 0.0


# Keep old CompanyProfile for backwards compatibility but mark as TPRM
CompanyProfile = CompanyTPRMProfile


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
