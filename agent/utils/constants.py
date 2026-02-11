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

# Search query templates for TPRM company research
SEARCH_TEMPLATES = {
    # Basic Information
    "general": "{company} company information about",
    "official_site": "{company} official website",
    "linkedin": "{company} LinkedIn company page",
    
    # Industry & Services (for both IT and Non-IT)
    "industry": "{company} industry sector services",
    "services": "{company} products services offerings what they do",
    "it_services": "{company} IT services technology software",
    
    # TPRM Critical: Certifications
    "iso_27001": "{company} ISO 27001 certified information security",
    "iso_9001": "{company} ISO 9001 certified quality management",
    "soc2": "{company} SOC 2 Type II compliance audit",
    "certifications": "{company} security certifications compliance standards",
    
    # TPRM Critical: Security
    "security_page": "{company} security trust center",
    "gdpr": "{company} GDPR compliant data protection",
    
    # TPRM Critical: Data Breaches
    "data_breach": "{company} data breach security incident",
    "breach_news": "{company} data leak hack breach 2024 2025 2026",
    
    # TPRM Critical: CVE Vulnerabilities
    "cve": "{company} CVE vulnerability security advisory",
    "security_advisory": "{company} security vulnerability disclosure",
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
