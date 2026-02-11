"""
LLM Integration - FREE options using Groq or Ollama
"""
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
    Get LLM instance based on configuration
    
    Supports:
    - Groq: FREE tier with generous limits
    - Ollama: 100% FREE, runs locally
    
    Returns None if LLM is not configured (falls back to regex extraction)
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
            logger.warning(f"Unsupported LLM provider: {LLM_PROVIDER}. Using regex-only extraction.")
            return None
    except Exception as e:
        logger.warning(f"LLM not available: {str(e)}. Using regex-only extraction.")
        return None
    
    return _llm_instance


def _get_groq_llm() -> BaseChatModel:
    """Get Groq LLM (FREE tier available)"""
    try:
        from langchain_groq import ChatGroq
        
        if not GROQ_API_KEY or GROQ_API_KEY == "your_groq_api_key_here":
            raise ValueError(
                "GROQ_API_KEY not configured. "
                "Get a FREE API key at https://console.groq.com/keys"
            )
        
        logger.info("Using Groq LLM (FREE tier)")
        
        return ChatGroq(
            api_key=GROQ_API_KEY,
            model_name="llama-3.3-70b-versatile",  # Fast and powerful
            temperature=0.1,
            max_tokens=4096,
        )
    except ImportError:
        raise ImportError("langchain-groq not installed. Run: pip install langchain-groq")


def _get_ollama_llm() -> BaseChatModel:
    """Get Ollama LLM (100% FREE, runs locally)"""
    try:
        from langchain_ollama import ChatOllama
        
        logger.info(f"Using Ollama LLM (model: {OLLAMA_MODEL})")
        
        return ChatOllama(
            model=OLLAMA_MODEL,
            base_url=OLLAMA_BASE_URL,
            temperature=0.1,
        )
    except ImportError:
        raise ImportError(
            "langchain-ollama not installed. Run: pip install langchain-ollama\n"
            "Then install Ollama from https://ollama.ai and run: ollama pull llama3.2"
        )


def extract_company_info_with_llm(content: str, company_name: str) -> dict:
    """
    Use LLM to extract structured company information from text
    Now redirects to TPRM-focused extraction
    """
    return extract_tprm_info_with_llm(content, company_name)


def extract_tprm_info_with_llm(content: str, company_name: str) -> dict:
    """
    Use LLM to extract TPRM-focused company information from text
    
    Focuses on:
    - Basic info, industry, IT classification
    - Contact info, social media
    - ISO certifications and compliance
    - Data breaches and CVE vulnerabilities
    """
    llm = get_llm()
    
    if llm is None:
        logger.info("LLM not configured - skipping AI extraction")
        return {}
    
    system_prompt = """You are an expert TPRM (Third Party Risk Management) analyst.
Extract company information focused on security and compliance assessment.

IMPORTANT: 
- Only extract information that is explicitly stated in the text
- Use empty strings, false, or empty lists for missing information
- Be accurate and factual - this is for risk assessment
- Focus on security-relevant information

Return a JSON object with these fields:
{
    "basic_info": {
        "name": "",
        "description": "",
        "industry": "",
        "sector": "",
        "is_it_company": false,
        "it_classification": "",
        "sub_services": [],
        "headquarters": "",
        "country": "",
        "employee_count": ""
    },
    "contact": {
        "official_website": "",
        "email": "",
        "phone": "",
        "security_contact": ""
    },
    "social_media": {
        "linkedin": "",
        "twitter": "",
        "github": ""
    },
    "certifications": {
        "iso_27001": false,
        "iso_27017": false,
        "iso_27018": false,
        "iso_9001": false,
        "iso_14001": false,
        "iso_22301": false,
        "soc2": false,
        "soc2_type": "",
        "pci_dss": false,
        "hipaa": false,
        "gdpr_compliant": false,
        "other_certifications": []
    },
    "security_incidents": {
        "has_breaches": false,
        "breach_summary": "",
        "breach_count": 0,
        "has_cve_vulnerabilities": false,
        "cve_summary": "",
        "ransomware_history": false
    }
}

For is_it_company: Set true if the company is in technology/IT/software/digital services.
For it_classification: Use categories like "Cloud Services", "Software Development", "Cybersecurity", "Data Analytics", "Managed Services", "Consulting", "Networking", "AI/ML", or "Non-IT"."""

    user_prompt = f"""Extract TPRM-relevant information about "{company_name}" from the following text:

{content[:15000]}

Return ONLY valid JSON, no other text."""

    try:
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_prompt),
        ]
        
        response = llm.invoke(messages)
        response_text = response.content
        
        # Parse JSON from response
        import json
        import re
        
        # Try to extract JSON from response
        json_match = re.search(r'\{[\s\S]*\}', response_text)
        if json_match:
            extracted = json.loads(json_match.group())
            return extracted
        
        return {}
        
    except Exception as e:
        logger.error(f"LLM extraction error: {str(e)}")
        return {}


def summarize_content(content: str, max_length: int = 500) -> str:
    """Summarize content using LLM (or truncate if LLM not available)"""
    llm = get_llm()
    
    if llm is None:
        return content[:max_length] + ("..." if len(content) > max_length else "")
    
    prompt = f"""Summarize the following text in {max_length} characters or less. 
Focus on the most important facts and information.

Text:
{content[:10000]}

Summary:"""

    try:
        response = llm.invoke([HumanMessage(content=prompt)])
        return response.content.strip()
    except Exception as e:
        logger.error(f"LLM summarization error: {str(e)}")
        return content[:max_length]


def analyze_company_relevance(content: str, company_name: str) -> float:
    """
    Analyze if content is relevant to the company for TPRM purposes
    Returns score 0.0 to 1.0
    """
    # Simple keyword matching (no LLM needed)
    content_lower = content.lower()
    company_lower = company_name.lower()
    
    # Check for company name
    if company_lower in content_lower:
        base_score = 0.5
    else:
        return 0.1
    
    # Check for TPRM-related keywords (prioritize security/compliance content)
    tprm_keywords = [
        'security', 'compliance', 'iso', 'soc', 'certification', 
        'breach', 'cve', 'vulnerability', 'gdpr', 'hipaa', 'pci',
        'trust', 'privacy', 'data protection'
    ]
    
    general_keywords = ['company', 'about', 'team', 'contact', 
                       'services', 'founded', 'headquarters', 'industry']
    
    tprm_count = sum(1 for kw in tprm_keywords if kw in content_lower)
    general_count = sum(1 for kw in general_keywords if kw in content_lower)
    
    # TPRM keywords get higher weight
    tprm_score = min(tprm_count * 0.15, 0.4)
    general_score = min(general_count * 0.05, 0.1)
    
    return base_score + tprm_score + general_score
