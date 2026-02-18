"""
State management for the TPRM (Third Party Risk Management) scraping agent
Simplified to extract ONLY essential fields for speed and accuracy
"""
from typing import TypedDict, Optional, Annotated
from operator import add
from pydantic import BaseModel, Field


class CompanyBasicInfo(BaseModel):
    """Essential company information"""
    name: str = ""
    sector: str = ""  # Industry sector (secteur d'activité)
    country: str = ""  # Country (pays)
    employee_count: str = ""  # Company size (taille de l'entreprise)
    is_it_company: bool = False  # Service type: IT or Non-IT


class CompanyContact(BaseModel):
    """Contact information - essential fields only"""
    official_website: str = ""  # Site web


class CompanySocialMedia(BaseModel):
    """Social media presence - essential fields only"""
    linkedin: str = ""  # LinkedIn URL


class SecurityCertification(BaseModel):
    """Single certification record"""
    name: str = ""  # e.g., "ISO 27001", "SOC 2"
    certified: bool = False  # Whether they have this certification


class CompanySecurityCompliance(BaseModel):
    """Security and compliance certifications - streamlined"""
    # ISO Certifications (Security & Cloud)
    iso_27001: bool = False  # Information Security
    iso_27017: bool = False  # Cloud Security
    iso_27018: bool = False  # Cloud Privacy
    iso_9001: bool = False   # Quality Management
    
    # Other Security Certifications
    soc2: bool = False
    soc1: bool = False
    pci_dss: bool = False
    hipaa: bool = False
    gdpr_compliant: bool = False
    fedramp: bool = False
    
    # Additional certifications found
    other_certifications: list[str] = Field(default_factory=list)


class DataBreach(BaseModel):
    """Data breach incident record - essential fields only"""
    affected_entity: str = ""  # Who was affected
    description: str = ""
    date: str = ""  # When it happened


class CVEVulnerability(BaseModel):
    """CVE vulnerability record - essential fields only"""
    cve_id: str = ""  # e.g., "CVE-2024-12345"
    description: str = ""
    affected_product: str = ""


class CompanySecurityIncidents(BaseModel):
    """Security incidents - data breaches and CVEs only"""
    data_breaches: list[DataBreach] = Field(default_factory=list)
    cve_vulnerabilities: list[CVEVulnerability] = Field(default_factory=list)


class CompanyTPRMProfile(BaseModel):
    """Simplified company profile with only essential fields"""
    # Core Information (6 fields user needs)
    basic_info: CompanyBasicInfo = Field(default_factory=CompanyBasicInfo)
    contact: CompanyContact = Field(default_factory=CompanyContact)
    social_media: CompanySocialMedia = Field(default_factory=CompanySocialMedia)
    
    # Security & Compliance
    security_compliance: CompanySecurityCompliance = Field(default_factory=CompanySecurityCompliance)
    security_incidents: CompanySecurityIncidents = Field(default_factory=CompanySecurityIncidents)
    
    # Metadata
    raw_sources: list[dict] = Field(default_factory=list)
    search_timestamp: str = ""


# Keep old CompanyProfile for backwards compatibility
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
