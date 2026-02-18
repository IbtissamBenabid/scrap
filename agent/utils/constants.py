"""
Constants and configuration for the scraping agent
"""
import os
from dotenv import load_dotenv

load_dotenv()

# LLM Configuration
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "groq")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

# Search Configuration
SEARCH_MAX_RESULTS = int(os.getenv("SEARCH_MAX_RESULTS", "10"))
SEARCH_REGION = os.getenv("SEARCH_REGION", "wt-wt")
SEARCH_SAFESEARCH = os.getenv("SEARCH_SAFESEARCH", "moderate")

# Scraping Configuration
URL_LIMIT = int(os.getenv("URL_LIMIT", "10"))
PAGE_LIMIT = int(os.getenv("PAGE_LIMIT", "5"))
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "30"))
REQUEST_DELAY = float(os.getenv("REQUEST_DELAY", "1.0"))
USE_PLAYWRIGHT = os.getenv("USE_PLAYWRIGHT", "false").lower() == "true"

# Output Configuration
OUTPUT_FORMAT = os.getenv("OUTPUT_FORMAT", "both")
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "./output")

# Logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# User Agent rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]

# Company information categories to extract - TPRM focused
COMPANY_INFO_CATEGORIES = [
    "basic_info",        # Name, description, industry, sector, IT classification
    "contact",           # Email, phone, address, website
    "social_media",      # LinkedIn, Twitter, GitHub (for IT)
    "certifications",    # ISO 27001, ISO 9001, SOC 2, etc.
    "security",          # Security practices, trust center
    "data_breaches",     # Breach history
    "cve_vulnerabilities",  # Known CVEs
]

# Search query templates - SIMPLIFIED for speed and accuracy
SEARCH_TEMPLATES = {
    # Essential: Basic Information
    "general": "{company} company information",
    "official_site": "{company} official website",
    
    # Essential: LinkedIn
    "linkedin": "{company} LinkedIn company page",
    
    # Essential: Industry & Country
    "industry_location": "{company} industry sector country location",
    
    # Essential: Company Size & Services
    "company_size": "{company} employees staff size how many",
    "services": "{company} services IT technology what they do",
    
    # Essential: Security Certifications
    "iso_27001": "{company} ISO 27001 security certified",
    "soc2": "{company} SOC 2 compliance certified",
    "certifications": "{company} security certifications compliance",
    
    # Essential: Data Breaches & CVEs
    "breaches": "{company} data breach security incident hack",
    "cve": "{company} CVE vulnerability security",
}

# IT Industry keywords for classification
IT_INDUSTRY_KEYWORDS = [
    "software", "technology", "it services", "information technology",
    "cloud", "saas", "paas", "iaas", "cybersecurity", "data", 
    "artificial intelligence", "ai", "machine learning", "analytics",
    "fintech", "healthtech", "edtech", "proptech", "regtech",
    "telecommunications", "internet", "digital", "computing",
    "hardware", "semiconductor", "electronics", "network",
    "consulting it", "managed services", "system integrator",
]

# IT Sub-services classification
IT_SUB_SERVICES = {
    "cloud_services": ["cloud", "aws", "azure", "gcp", "hosting", "infrastructure"],
    "software_development": ["software", "development", "engineering", "programming"],
    "cybersecurity": ["security", "cybersecurity", "infosec", "penetration", "soc", "siem"],
    "data_analytics": ["analytics", "data", "business intelligence", "bi", "reporting"],
    "managed_services": ["managed services", "msp", "outsourcing", "support"],
    "consulting": ["consulting", "advisory", "implementation", "strategy"],
    "networking": ["network", "connectivity", "wan", "lan", "sd-wan"],
    "ai_ml": ["artificial intelligence", "machine learning", "ai", "ml", "nlp"],
}

# Domains to prioritize for TPRM company info
PRIORITY_DOMAINS = [
    # Official sources
    "linkedin.com",
    
    # Security & Compliance sources
    "nvd.nist.gov",          # CVE database
    "cve.mitre.org",         # CVE database
    "haveibeenpwned.com",    # Breach database
    "securityweek.com",      # Security news
    "therecord.media",       # Security news
    "bleepingcomputer.com",  # Security news
    "cyberscoop.com",        # Security news
    "darkreading.com",       # Security news
    "threatpost.com",        # Security news
    
    # Business info
    "crunchbase.com",
    "bloomberg.com",
    "reuters.com",
    "zoominfo.com",
    "dnb.com",
    "wikipedia.org",
    
    # Trust pages
    "trust.",                # Trust centers
    "security.",             # Security pages
]

# Domains to skip (social media posts, forums, etc.)
SKIP_DOMAINS = [
    "twitter.com",
    "facebook.com",
    "instagram.com",
    "tiktok.com",
    "reddit.com",
    "quora.com",
    "pinterest.com",
    "youtube.com",
]
