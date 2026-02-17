"""
DuckDuckGo Search Integration - 100% FREE!
"""
import logging
from typing import Optional

try:
    from ddgs import DDGS
except Exception:
    try:
        from duckduckgo_search import DDGS
    except Exception as e:
        raise ImportError(
            "DuckDuckGo search dependency not found. Install either 'ddgs' or 'duckduckgo-search' (e.g. pip install ddgs duckduckgo-search)"
        ) from e

from .constants import SEARCH_MAX_RESULTS, SEARCH_REGION, SEARCH_SAFESEARCH, SEARCH_TEMPLATES
from .helpers import is_valid_url, should_skip_url, sort_urls_by_priority

logger = logging.getLogger(__name__)


class DuckDuckGoSearcher:
    """DuckDuckGo search wrapper for company research"""
    
    def __init__(
        self,
        max_results: int = SEARCH_MAX_RESULTS,
        region: str = SEARCH_REGION,
        safesearch: str = SEARCH_SAFESEARCH,
    ):
        self.max_results = max_results
        self.region = region
        self.safesearch = safesearch
        self.ddgs = DDGS()
    
    def search(self, query: str, max_results: Optional[int] = None) -> list[dict]:
        """
        Perform a DuckDuckGo search
        
        Args:
            query: Search query string
            max_results: Maximum number of results (overrides default)
            
        Returns:
            List of search results with title, url, snippet
        """
        results = []
        num_results = max_results or self.max_results
        
        try:
            logger.info(f"Searching DuckDuckGo: {query}")
            
            search_results = self.ddgs.text(
                query,
                region=self.region,
                safesearch=self.safesearch,
                max_results=num_results,
            )
            
            for result in search_results:
                url = result.get("href", "") or result.get("url", "")
                
                # Skip invalid or unwanted URLs
                if not is_valid_url(url) or should_skip_url(url):
                    continue
                
                results.append({
                    "title": result.get("title", ""),
                    "url": url,
                    "snippet": result.get("body", "") or result.get("description", ""),
                    "source": "duckduckgo",
                })
            
            logger.info(f"Found {len(results)} results for: {query}")
            
        except Exception as e:
            logger.error(f"Search error for '{query}': {str(e)}")
        
        return results
    
    def search_news(self, query: str, max_results: Optional[int] = None) -> list[dict]:
        """Search DuckDuckGo news"""
        results = []
        num_results = max_results or self.max_results
        
        try:
            logger.info(f"Searching DuckDuckGo News: {query}")
            
            news_results = self.ddgs.news(
                query,
                region=self.region,
                safesearch=self.safesearch,
                max_results=num_results,
            )
            
            for result in news_results:
                url = result.get("url", "") or result.get("href", "")
                if not is_valid_url(url):
                    continue
                
                results.append({
                    "title": result.get("title", ""),
                    "url": url,
                    "snippet": result.get("body", "") or result.get("description", ""),
                    "date": result.get("date", ""),
                    "source": result.get("source", ""),
                    "type": "news",
                })
            
            logger.info(f"Found {len(results)} news results")
            
        except Exception as e:
            logger.error(f"News search error: {str(e)}")
        
        return results
    
    def search_company(self, company_name: str) -> dict:
        """
        Comprehensive company search using multiple query templates
        
        Args:
            company_name: Name of the company to research
            
        Returns:
            Dictionary with categorized search results and URLs
        """
        all_results = {}
        all_urls = set()
        
        for category, template in SEARCH_TEMPLATES.items():
            query = template.format(company=company_name)
            results = self.search(query, max_results=5)
            
            all_results[category] = results
            
            for result in results:
                all_urls.add(result["url"])
        
        # Also get news
        news_query = f"{company_name} news"
        news_results = self.search_news(news_query, max_results=5)
        all_results["news"] = news_results
        
        for result in news_results:
            all_urls.add(result["url"])
        
        # Sort URLs by priority
        sorted_urls = sort_urls_by_priority(list(all_urls))
        
        return {
            "results_by_category": all_results,
            "all_urls": sorted_urls,
            "total_results": sum(len(r) for r in all_results.values()),
        }
    
    def get_instant_answer(self, query: str) -> Optional[dict]:
        """Get instant answer from DuckDuckGo (if available)"""
        try:
            answers = self.ddgs.answers(query)
            if answers:
                return answers[0]
        except Exception as e:
            logger.debug(f"No instant answer for '{query}': {str(e)}")
        return None


def search_company_info(company_name: str) -> dict:
    """
    Convenience function to search for company information
    
    Args:
        company_name: Name of the company
        
    Returns:
        Search results dictionary
    """
    searcher = DuckDuckGoSearcher()
    return searcher.search_company(company_name)
