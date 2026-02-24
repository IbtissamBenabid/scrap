"""
Web scraping utilities - concurrent scraping with requests + BeautifulSoup
"""
import logging
from typing import Optional
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from bs4 import BeautifulSoup

from .constants import REQUEST_TIMEOUT, REQUEST_DELAY, USE_PLAYWRIGHT, MAX_CONCURRENT_SCRAPES
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
    """Web scraper using requests + BeautifulSoup with concurrency."""

    def __init__(
        self,
        timeout: int = REQUEST_TIMEOUT,
        delay: float = REQUEST_DELAY,
        use_playwright: bool = USE_PLAYWRIGHT,
        max_workers: int = MAX_CONCURRENT_SCRAPES,
    ):
        self.timeout = timeout
        self.delay = delay
        self.use_playwright = use_playwright
        self.max_workers = max_workers
        self.session = requests.Session()
        # Pre-warm session with default headers
        self.session.headers.update(get_headers())

    def scrape_url(self, url: str) -> ScrapedPage:
        """Scrape a single URL."""
        logger.info(f"Scraping: {url}")

        try:
            response = self.session.get(
                url,
                headers=get_headers(),
                timeout=self.timeout,
                allow_redirects=True,
            )
            response.raise_for_status()

            # Skip non-HTML content
            content_type = response.headers.get("Content-Type", "")
            if "text/html" not in content_type and "application/xhtml" not in content_type:
                return ScrapedPage(url=url, success=False, error=f"Non-HTML content: {content_type}")

            html = response.text

            # Parse with BeautifulSoup
            soup = BeautifulSoup(html, 'lxml')

            # Remove noisy elements
            for element in soup(['script', 'style', 'nav', 'footer', 'header', 'aside', 'noscript', 'iframe']):
                element.decompose()

            # Title
            title = ""
            if soup.title:
                title = soup.title.string or ""

            # Content
            content = self._extract_main_content(soup)

            # Metadata
            metadata = self._extract_metadata(soup)

            # Links
            links = extract_links(html, url)

            return ScrapedPage(
                url=url,
                title=title.strip(),
                content=truncate_text(content, 50000),
                html=truncate_text(html, 100000),
                links=links[:50],
                metadata=metadata,
                success=True,
                error="",
            )

        except requests.exceptions.Timeout:
            error = f"Timeout ({self.timeout}s) for {url}"
            logger.warning(error)
            return ScrapedPage(url=url, success=False, error=error)

        except requests.exceptions.RequestException as e:
            error = f"Request error for {url}: {str(e)}"
            logger.warning(error)
            if self.use_playwright:
                return self._scrape_with_playwright(url)
            return ScrapedPage(url=url, success=False, error=error)

        except Exception as e:
            error = f"Error scraping {url}: {str(e)}"
            logger.error(error)
            return ScrapedPage(url=url, success=False, error=error)

    def scrape_multiple(self, urls: list[str]) -> list[ScrapedPage]:
        """Scrape multiple URLs concurrently."""
        results = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_url = {
                executor.submit(self.scrape_url, url): url
                for url in urls
            }

            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    results.append(result)
                    status = "✅" if result.success else "❌"
                    logger.info(f"  {status} {url[:60]}...")
                except Exception as e:
                    logger.error(f"  ❌ Exception for {url}: {e}")
                    results.append(ScrapedPage(url=url, success=False, error=str(e)))

        return results

    def _extract_main_content(self, soup: BeautifulSoup) -> str:
        """Extract main text content from page."""
        main_selectors = [
            'main', 'article', '[role="main"]',
            '#content', '.content', '#main', '.main',
            '.post-content', '.article-content', '.page-content',
        ]

        main_content = None
        for selector in main_selectors:
            main_content = soup.select_one(selector)
            if main_content:
                break

        if not main_content:
            main_content = soup.body if soup.body else soup

        text = main_content.get_text(separator='\n', strip=True)
        lines = [clean_text(line) for line in text.split('\n') if line.strip()]
        return '\n'.join(lines)

    def _extract_metadata(self, soup: BeautifulSoup) -> dict:
        """Extract metadata from page."""
        metadata = {}

        meta_desc = soup.find('meta', attrs={'name': 'description'})
        if meta_desc:
            metadata['description'] = meta_desc.get('content', '')

        meta_keywords = soup.find('meta', attrs={'name': 'keywords'})
        if meta_keywords:
            metadata['keywords'] = meta_keywords.get('content', '')

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
                schema_data = json.loads(json_ld.string)
                metadata['schema'] = schema_data
            except Exception:
                pass

        canonical = soup.find('link', attrs={'rel': 'canonical'})
        if canonical:
            metadata['canonical'] = canonical.get('href', '')

        return metadata

    def _scrape_with_playwright(self, url: str) -> ScrapedPage:
        """Scrape with Playwright for JS-heavy sites."""
        try:
            from playwright.sync_api import sync_playwright

            logger.info(f"Scraping with Playwright: {url}")

            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(user_agent=get_headers()['User-Agent'])
                page = context.new_page()

                page.goto(url, timeout=self.timeout * 1000)
                page.wait_for_load_state('networkidle', timeout=self.timeout * 1000)

                html = page.content()
                title = page.title()
                browser.close()

                soup = BeautifulSoup(html, 'lxml')
                for element in soup(['script', 'style', 'nav', 'footer', 'header', 'aside', 'noscript']):
                    element.decompose()

                content = self._extract_main_content(soup)
                metadata = self._extract_metadata(soup)
                links = extract_links(html, url)

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

    def close(self):
        """Clean up resources."""
        self.session.close()


# Convenience functions
def scrape_url(url: str) -> ScrapedPage:
    scraper = WebScraper()
    result = scraper.scrape_url(url)
    scraper.close()
    return result


def scrape_urls(urls: list[str]) -> list[ScrapedPage]:
    scraper = WebScraper()
    results = scraper.scrape_multiple(urls)
    scraper.close()
    return results
