"""
LangGraph nodes for the scraping agent workflow
"""
import logging
from typing import Literal

from .utils.states import AgentState, ScrapedPage
from .utils.search import DuckDuckGoSearcher
from .utils.scraper import WebScraper
from .utils.extractor import CompanyInfoExtractor
from .utils.helpers import sort_urls_by_priority
from .utils.constants import URL_LIMIT, SEARCH_TEMPLATES

logger = logging.getLogger(__name__)


def initialize_node(state: AgentState) -> dict:
    """
    Initialize the agent state and prepare search queries
    """
    company_name = state["company_name"]
    
    logger.info(f"🚀 Starting company research for: {company_name}")
    
    # Generate search queries from templates
    search_queries = [
        template.format(company=company_name)
        for template in SEARCH_TEMPLATES.values()
    ]
    
    return {
        "search_queries": search_queries,
        "current_step": "search",
        "messages": [f"Initialized research for: {company_name}"],
        "iteration_count": 0,
    }


def search_node(state: AgentState) -> dict:
    """
    Search for company information using DuckDuckGo (FREE!)
    """
    company_name = state["company_name"]
    
    logger.info(f"🔍 Searching for: {company_name}")
    
    searcher = DuckDuckGoSearcher()
    
    try:
        # Perform comprehensive search
        search_data = searcher.search_company(company_name)
        
        all_results = []
        for category, results in search_data["results_by_category"].items():
            for result in results:
                result["category"] = category
                all_results.append(result)
        
        # Get unique URLs sorted by priority
        urls = search_data["all_urls"][:URL_LIMIT]
        
        logger.info(f"📊 Found {len(all_results)} results, {len(urls)} unique URLs")
        
        return {
            "search_results": all_results,
            "urls_to_scrape": urls,
            "current_step": "scrape",
            "messages": [f"Found {len(urls)} URLs to scrape"],
        }
        
    except Exception as e:
        error_msg = f"Search error: {str(e)}"
        logger.error(error_msg)
        return {
            "search_results": [],
            "urls_to_scrape": [],
            "current_step": "error",
            "errors": [error_msg],
        }


def scrape_node(state: AgentState) -> dict:
    """
    Scrape URLs to extract content (FREE using requests + BeautifulSoup)
    """
    urls_to_scrape = state["urls_to_scrape"]
    
    if not urls_to_scrape:
        return {
            "current_step": "extract",
            "messages": ["No URLs to scrape"],
        }
    
    logger.info(f"🌐 Scraping {len(urls_to_scrape)} URLs")
    
    scraper = WebScraper()
    scraped_pages = []
    failed_urls = []
    
    for i, url in enumerate(urls_to_scrape):
        logger.info(f"  [{i+1}/{len(urls_to_scrape)}] {url[:60]}...")
        
        try:
            page = scraper.scrape_url(url)
            
            if page.success:
                scraped_pages.append(page.model_dump())
                logger.info(f"    ✅ Success ({len(page.content)} chars)")
            else:
                failed_urls.append(url)
                logger.warning(f"    ❌ Failed: {page.error}")
                
        except Exception as e:
            failed_urls.append(url)
            logger.error(f"    ❌ Error: {str(e)}")
    
    scraper.close()
    
    logger.info(f"📝 Scraped {len(scraped_pages)} pages, {len(failed_urls)} failed")
    
    return {
        "scraped_pages": scraped_pages,
        "failed_urls": failed_urls,
        "current_step": "extract",
        "messages": [f"Scraped {len(scraped_pages)} pages successfully"],
    }


def extract_node(state: AgentState) -> dict:
    """
    Extract structured company information from scraped pages
    Uses LLM (Groq FREE or Ollama FREE) for intelligent extraction
    """
    company_name = state["company_name"]
    scraped_pages_data = state.get("scraped_pages", [])
    
    if not scraped_pages_data:
        return {
            "current_step": "complete",
            "messages": ["No content to extract from"],
        }
    
    logger.info(f"🧠 Extracting company information from {len(scraped_pages_data)} pages")
    
    # Convert to ScrapedPage objects
    scraped_pages = [ScrapedPage(**p) for p in scraped_pages_data]
    
    try:
        # Use extractor with LLM
        extractor = CompanyInfoExtractor(company_name, use_llm=True)
        profile = extractor.extract_from_pages(scraped_pages)
        
        # Set company name if not extracted
        if not profile.basic_info.name:
            profile.basic_info.name = company_name
        
        company_profile = profile.model_dump()
        
        logger.info("✅ Extraction complete")
        
        return {
            "company_profile": company_profile,
            "extracted_info": company_profile,
            "current_step": "complete",
            "messages": ["Extraction complete"],
        }
        
    except Exception as e:
        error_msg = f"Extraction error: {str(e)}"
        logger.error(error_msg)
        return {
            "current_step": "complete",
            "errors": [error_msg],
        }


def should_continue(state: AgentState) -> Literal["search", "scrape", "extract", "complete", "error"]:
    """
    Determine the next step in the workflow
    """
    current_step = state.get("current_step", "search")
    iteration_count = state.get("iteration_count", 0)
    max_iterations = state.get("max_iterations", 5)
    
    # Check for max iterations
    if iteration_count >= max_iterations:
        return "complete"
    
    return current_step


def format_output_node(state: AgentState) -> dict:
    """
    Format the final output
    """
    company_profile = state.get("company_profile", {})
    
    logger.info("📄 Formatting output...")
    
    return {
        "company_profile": company_profile,
        "current_step": "done",
        "messages": ["Output formatted"],
    }
