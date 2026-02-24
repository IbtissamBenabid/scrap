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
SEARCH_MAX_RESULTS = int(os.getenv("SEARCH_MAX_RESULTS", "8"))
SEARCH_REGION = os.getenv("SEARCH_REGION", "wt-wt")
SEARCH_SAFESEARCH = os.getenv("SEARCH_SAFESEARCH", "moderate")

# Scraping Configuration
URL_LIMIT = int(os.getenv("URL_LIMIT", "8"))
PAGE_LIMIT = int(os.getenv("PAGE_LIMIT", "5"))
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "15"))
REQUEST_DELAY = float(os.getenv("REQUEST_DELAY", "0.3"))
USE_PLAYWRIGHT = os.getenv("USE_PLAYWRIGHT", "false").lower() == "true"
MAX_CONCURRENT_SCRAPES = int(os.getenv("MAX_CONCURRENT_SCRAPES", "5"))

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

# Search query templates – targeted for TPRM
SEARCH_TEMPLATES = {
    # Core info
    "general": "{company} company about overview",
    "official_site": "{company} official website",
    "linkedin": "{company} site:linkedin.com/company",

    # Security & Compliance (most valuable for TPRM)
    "certifications": "{company} ISO 27001 SOC 2 security certifications",
    "trust_center": "{company} trust center security compliance page",
    "breaches": "{company} data breach security incident",
    "cve": "{company} CVE vulnerability",

    # Business context
    "industry_location": "{company} industry sector headquarters country employees",
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
    "linkedin.com",
    "nvd.nist.gov",
    "cve.mitre.org",
    "haveibeenpwned.com",
    "securityweek.com",
    "therecord.media",
    "bleepingcomputer.com",
    "cyberscoop.com",
    "darkreading.com",
    "threatpost.com",
    "crunchbase.com",
    "bloomberg.com",
    "reuters.com",
    "zoominfo.com",
    "dnb.com",
    "wikipedia.org",
    "trust.",
    "security.",
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
