"""
Web scraping utilities - FREE using requests + BeautifulSoup
"""
import logging
from typing import Optional
from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup

from .constants import REQUEST_TIMEOUT, REQUEST_DELAY, USE_PLAYWRIGHT
from .helpers import (
    get_headers,
    clean_text,
    extract_links,
    extract_social_links,
    extract_emails,
    extract_phones,
    rate_limit_delay,
    truncate_text,
)
from .states import ScrapedPage

logger = logging.getLogger(__name__)


class WebScraper:
    """Web scraper using requests and BeautifulSoup"""
    
    def __init__(
        self,
        timeout: int = REQUEST_TIMEOUT,
        delay: float = REQUEST_DELAY,
        use_playwright: bool = USE_PLAYWRIGHT,
    ):
        self.timeout = timeout
        self.delay = delay
        self.use_playwright = use_playwright
        self.session = requests.Session()
        self.playwright_browser = None
    
    def scrape_url(self, url: str) -> ScrapedPage:
        """
        Scrape a single URL
        
        Args:
            url: URL to scrape
            
        Returns:
            ScrapedPage object with extracted content
        """
        logger.info(f"Scraping: {url}")
        
        try:
            # Try with requests first
            response = self.session.get(
                url,
                headers=get_headers(),
                timeout=self.timeout,
                allow_redirects=True,
            )
            response.raise_for_status()
            
            html = response.text
            
            # Parse with BeautifulSoup
            soup = BeautifulSoup(html, 'lxml')
            
            # Remove script, style, nav, footer elements
            for element in soup(['script', 'style', 'nav', 'footer', 'header', 'aside', 'noscript']):
                element.decompose()
            
            # Extract title
            title = ""
            if soup.title:
                title = soup.title.string or ""
            
            # Extract main content
            content = self._extract_main_content(soup)
            
            # Extract metadata
            metadata = self._extract_metadata(soup)
            
            # Extract links
            links = extract_links(html, url)
            
            # Add delay to be respectful
            rate_limit_delay(self.delay)
            
            return ScrapedPage(
                url=url,
                title=title,
                content=truncate_text(content, 50000),
                html=truncate_text(html, 100000),
                links=links[:50],
                metadata=metadata,
                success=True,
                error="",
            )
            
        except requests.exceptions.Timeout:
            error = f"Timeout scraping {url}"
            logger.warning(error)
            return ScrapedPage(url=url, success=False, error=error)
            
        except requests.exceptions.RequestException as e:
            error = f"Request error for {url}: {str(e)}"
            logger.warning(error)
            
            # Try with Playwright if enabled
            if self.use_playwright:
                return self._scrape_with_playwright(url)
            
            return ScrapedPage(url=url, success=False, error=error)
            
        except Exception as e:
            error = f"Error scraping {url}: {str(e)}"
            logger.error(error)
            return ScrapedPage(url=url, success=False, error=error)
    
    def _extract_main_content(self, soup: BeautifulSoup) -> str:
        """Extract main text content from page"""
        # Try to find main content area
        main_selectors = [
            'main',
            'article',
            '[role="main"]',
            '#content',
            '.content',
            '#main',
            '.main',
            '.post-content',
            '.article-content',
        ]
        
        main_content = None
        for selector in main_selectors:
            main_content = soup.select_one(selector)
            if main_content:
                break
        
        # Fall back to body
        if not main_content:
            main_content = soup.body if soup.body else soup
        
        # Get text
        text = main_content.get_text(separator='\n', strip=True)
        
        # Clean up
        lines = [clean_text(line) for line in text.split('\n') if line.strip()]
        return '\n'.join(lines)
    
    def _extract_metadata(self, soup: BeautifulSoup) -> dict:
        """Extract metadata from page"""
        metadata = {}
        
        # Meta description
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        if meta_desc:
            metadata['description'] = meta_desc.get('content', '')
        
        # Meta keywords
        meta_keywords = soup.find('meta', attrs={'name': 'keywords'})
        if meta_keywords:
            metadata['keywords'] = meta_keywords.get('content', '')
        
        # Open Graph data
        og_tags = ['og:title', 'og:description', 'og:image', 'og:type', 'og:site_name']
        for tag in og_tags:
            og = soup.find('meta', attrs={'property': tag})
            if og:
                metadata[tag.replace('og:', '')] = og.get('content', '')
        
        # Schema.org JSON-LD
        json_ld = soup.find('script', attrs={'type': 'application/ld+json'})
        if json_ld:
            try:
                import json
                metadata['schema'] = json.loads(json_ld.string)
            except:
                pass
        
        # Canonical URL
        canonical = soup.find('link', attrs={'rel': 'canonical'})
        if canonical:
            metadata['canonical'] = canonical.get('href', '')
        
        return metadata
    
    def _scrape_with_playwright(self, url: str) -> ScrapedPage:
        """Scrape with Playwright for JS-heavy sites"""
        try:
            from playwright.sync_api import sync_playwright
            
            logger.info(f"Scraping with Playwright: {url}")
            
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    user_agent=get_headers()['User-Agent']
                )
                page = context.new_page()
                
                page.goto(url, timeout=self.timeout * 1000)
                page.wait_for_load_state('networkidle', timeout=self.timeout * 1000)
                
                html = page.content()
                title = page.title()
                
                browser.close()
                
                # Parse content
                soup = BeautifulSoup(html, 'lxml')
                
                for element in soup(['script', 'style', 'nav', 'footer', 'header', 'aside', 'noscript']):
                    element.decompose()
                
                content = self._extract_main_content(soup)
                metadata = self._extract_metadata(soup)
                links = extract_links(html, url)
                
                rate_limit_delay(self.delay)
                
                return ScrapedPage(
                    url=url,
                    title=title,
                    content=truncate_text(content, 50000),
                    html=truncate_text(html, 100000),
                    links=links[:50],
                    metadata=metadata,
                    success=True,
                    error="",
                )
                
        except Exception as e:
            error = f"Playwright error for {url}: {str(e)}"
            logger.error(error)
            return ScrapedPage(url=url, success=False, error=error)
    
    def scrape_multiple(self, urls: list[str]) -> list[ScrapedPage]:
        """Scrape multiple URLs"""
        results = []
        for url in urls:
            result = self.scrape_url(url)
            results.append(result)
        return results
    
    def close(self):
        """Clean up resources"""
        self.session.close()


def scrape_url(url: str) -> ScrapedPage:
    """Convenience function to scrape a single URL"""
    scraper = WebScraper()
    result = scraper.scrape_url(url)
    scraper.close()
    return result


def scrape_urls(urls: list[str]) -> list[ScrapedPage]:
    """Convenience function to scrape multiple URLs"""
    scraper = WebScraper()
    results = scraper.scrape_multiple(urls)
    scraper.close()
    return results
