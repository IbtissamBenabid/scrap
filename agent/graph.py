"""
LangGraph workflow for the company scraping agent
"""
import logging
from typing import Literal

from langgraph.graph import StateGraph, START, END

from .utils.states import AgentState
from .nodes import (
    initialize_node,
    search_node,
    scrape_node,
    extract_node,
    format_output_node,
)

logger = logging.getLogger(__name__)


def create_scraper_graph() -> StateGraph:
    """
    Create the LangGraph workflow for company scraping
    
    Workflow:
    1. Initialize - Set up state and prepare queries
    2. Search - Search DuckDuckGo for company info (FREE)
    3. Scrape - Scrape URLs (FREE with requests/BeautifulSoup)
    4. Extract - Extract structured info (FREE with Groq/Ollama)
    5. Format - Format final output
    """
    
    # Create graph with state schema
    graph = StateGraph(AgentState)
    
    # Add nodes
    graph.add_node("initialize", initialize_node)
    graph.add_node("search", search_node)
    graph.add_node("scrape", scrape_node)
    graph.add_node("extract", extract_node)
    graph.add_node("format", format_output_node)
    
    # Add edges
    graph.add_edge(START, "initialize")
    graph.add_edge("initialize", "search")
    graph.add_edge("search", "scrape")
    graph.add_edge("scrape", "extract")
    graph.add_edge("extract", "format")
    graph.add_edge("format", END)
    
    return graph


def compile_graph():
    """Compile the graph for execution"""
    graph = create_scraper_graph()
    return graph.compile()


# Create compiled graph instance
scraper_graph = compile_graph()


def run_graph(company_name: str, max_iterations: int = 5) -> dict:
    """
    Run the scraping graph for a company
    
    Args:
        company_name: Name of the company to research
        max_iterations: Maximum workflow iterations
        
    Returns:
        Final state with company profile
    """
    initial_state: AgentState = {
        "company_name": company_name,
        "search_queries": [],
        "search_results": [],
        "urls_to_scrape": [],
        "scraped_pages": [],
        "failed_urls": [],
        "extracted_info": {},
        "company_profile": None,
        "current_step": "initialize",
        "errors": [],
        "messages": [],
        "iteration_count": 0,
        "max_iterations": max_iterations,
    }
    
    logger.info(f"🚀 Starting scraper graph for: {company_name}")
    
    # Run the graph
    final_state = scraper_graph.invoke(initial_state)
    
    return final_state
