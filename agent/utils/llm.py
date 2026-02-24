"""
LLM Integration - FREE options using Groq or Ollama
Produces extraction aligned with the full TPRM target schema
"""
import json
import re
import logging
from typing import Optional
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage

from .constants import LLM_PROVIDER, GROQ_API_KEY, OLLAMA_MODEL, OLLAMA_BASE_URL

logger = logging.getLogger(__name__)

# LLM instance cache
_llm_instance: Optional[BaseChatModel] = None


def get_llm() -> Optional[BaseChatModel]:
    """
    Get LLM instance based on configuration.
    Returns None if LLM is not configured (falls back to regex extraction).
    """
    global _llm_instance

    if _llm_instance is not None:
        return _llm_instance

    try:
        if LLM_PROVIDER.lower() == "groq":
            _llm_instance = _get_groq_llm()
        elif LLM_PROVIDER.lower() == "ollama":
            _llm_instance = _get_ollama_llm()
        else:
            logger.warning(f"Unsupported LLM provider: {LLM_PROVIDER}. Using regex-only.")
            return None
    except Exception as e:
        logger.warning(f"LLM not available: {str(e)}. Using regex-only.")
        return None

    return _llm_instance


def _get_groq_llm() -> BaseChatModel:
    """Get Groq LLM (FREE tier available)"""
    try:
        from langchain_groq import ChatGroq
    except ImportError:
        raise ImportError("langchain-groq not installed. Run: pip install langchain-groq")

    if not GROQ_API_KEY or GROQ_API_KEY == "your_groq_api_key_here":
        raise ValueError(
            "GROQ_API_KEY not configured. "
            "Get a FREE API key at https://console.groq.com/keys"
        )

    logger.info("Using Groq LLM (FREE tier)")

    return ChatGroq(
        api_key=GROQ_API_KEY,
        model_name="llama-3.3-70b-versatile",
        temperature=0.05,  # Very low for factual extraction
        max_tokens=4096,
    )


def _get_ollama_llm() -> BaseChatModel:
    """Get Ollama LLM (100% FREE, runs locally)"""
    try:
        from langchain_ollama import ChatOllama
    except ImportError:
        raise ImportError(
            "langchain-ollama not installed. Run: pip install langchain-ollama\n"
            "Then install Ollama from https://ollama.ai and run: ollama pull llama3.2"
        )

    logger.info(f"Using Ollama LLM (model: {OLLAMA_MODEL})")
    return ChatOllama(model=OLLAMA_MODEL, base_url=OLLAMA_BASE_URL, temperature=0.05)


# ---------------------------------------------------------------------------
# Extraction prompt – aligned with the exact target JSON structure
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """You are a TPRM (Third Party Risk Management) research analyst.
Your task is to extract structured company intelligence from raw web content.

CRITICAL RULES:
1. Extract ONLY information that is EXPLICITLY stated or strongly implied by the text.
2. Never invent data. Use empty strings "" for missing text fields, null for missing objects, false for unknown booleans, and 0 for unknown numbers.
3. Return ONLY valid JSON – no markdown, no explanation, no code fences.
4. For ISO certifications: return an object {"name":"ISO 27001","status":"Certified","expiry_date":"","certification_body":"","scope":""} when the company IS certified; return null if not mentioned or not certified.
5. For data breaches: only include breaches CONFIRMED to involve this company.
6. For CVEs: only include CVEs that affect products made by this company.

Respond with the JSON object and nothing else."""

_USER_PROMPT_TEMPLATE = """Analyze the following web content about "{company}" and extract a TPRM profile.

=== WEB CONTENT ===
{content}
=== END CONTENT ===

Return JSON matching this EXACT schema (fill in real data where available):
{{
  "basic_info": {{
    "name": "",
    "website": "",
    "website_url": "",
    "linkedin_url": "",
    "linkedin": "",
    "description": "",
    "founded": "",
    "headquarters": "",
    "employees": "",
    "employee_count": "",
    "industry": "",
    "sector": "",
    "country": "",
    "is_it_company": false,
    "it_classification": "",
    "sub_services": []
  }},
  "contact": {{
    "official_website": "",
    "email": "",
    "phone": "",
    "address": "",
    "support_email": "",
    "security_contact": ""
  }},
  "social_media": {{
    "linkedin": "",
    "twitter": "",
    "facebook": "",
    "github": "",
    "youtube": ""
  }},
  "security_compliance": {{
    "iso_27001": null,
    "iso_27017": null,
    "iso_27018": null,
    "iso_9001": null,
    "iso_14001": null,
    "iso_22301": null,
    "soc2_type1": false,
    "soc2_type2": false,
    "soc1": false,
    "pci_dss": false,
    "hipaa_compliant": false,
    "gdpr_compliant": false,
    "fedramp": false,
    "other_certifications": [],
    "has_security_page": false,
    "security_page_url": "",
    "has_trust_center": false,
    "trust_center_url": "",
    "has_bug_bounty": false,
    "bug_bounty_url": ""
  }},
  "security_incidents": {{
    "data_breaches": [],
    "breach_count": 0,
    "last_breach_date": "",
    "cve_vulnerabilities": [],
    "cve_count": 0,
    "critical_cve_count": 0,
    "security_incidents": [],
    "ransomware_history": false
  }},
  "overall_risk_indicators": []
}}

For each data breach use: {{"date":"","description":"","records_affected":"","data_types_exposed":[],"source_url":"","severity":""}}
For each CVE use: {{"cve_id":"","description":"","severity":"","cvss_score":null,"affected_product":"","patched":false,"published_date":""}}
For each risk indicator use: {{"category":"","indicator":"","severity":"","details":""}}
For ISO certs that ARE present use: {{"name":"ISO 27001","status":"Certified","expiry_date":"","certification_body":"","scope":""}}
"""


def extract_tprm_info_with_llm(content: str, company_name: str) -> dict:
    """
    Use LLM to extract full TPRM profile JSON from raw scraped content.
    Returns a dict matching the target schema fields.
    """
    llm = get_llm()
    if llm is None:
        logger.info("LLM not configured – skipping AI extraction")
        return {}

    # Trim content to fit context window while keeping most useful parts
    trimmed = content[:14000]

    user_prompt = _USER_PROMPT_TEMPLATE.format(company=company_name, content=trimmed)

    try:
        messages = [
            SystemMessage(content=_SYSTEM_PROMPT),
            HumanMessage(content=user_prompt),
        ]
        response = llm.invoke(messages)
        response_text = response.content

        # Extract JSON from response (handles code fences too)
        json_match = re.search(r'\{[\s\S]*\}', response_text)
        if json_match:
            extracted = json.loads(json_match.group())
            return extracted

        return {}

    except json.JSONDecodeError as e:
        logger.error(f"LLM returned invalid JSON: {e}")
        return {}
    except Exception as e:
        logger.error(f"LLM extraction error: {str(e)}")
        return {}


# Backward-compat alias
extract_company_info_with_llm = extract_tprm_info_with_llm


def analyze_company_relevance(content: str, company_name: str) -> float:
    """Quick keyword-based relevance score (0.0 – 1.0)."""
    content_lower = content.lower()
    company_lower = company_name.lower()

    if company_lower not in content_lower:
        return 0.1

    base_score = 0.5

    tprm_keywords = [
        'security', 'compliance', 'iso', 'soc', 'certification',
        'breach', 'cve', 'vulnerability', 'gdpr', 'hipaa', 'pci',
        'trust', 'privacy', 'data protection',
    ]
    general_keywords = [
        'company', 'about', 'team', 'contact',
        'services', 'founded', 'headquarters', 'industry',
    ]

    tprm_score = min(sum(1 for kw in tprm_keywords if kw in content_lower) * 0.15, 0.4)
    general_score = min(sum(1 for kw in general_keywords if kw in content_lower) * 0.05, 0.1)

    return base_score + tprm_score + general_score
