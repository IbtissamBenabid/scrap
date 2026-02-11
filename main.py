#!/usr/bin/env python3
"""
Company Scraper Agent - Command Line Interface
100% FREE - No paid APIs required!

Usage:
    python main.py "Company Name"
    python main.py "Microsoft" --output json
    python main.py "Apple Inc" --no-save
"""
import argparse
import sys
import json
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from agent import run_scraper_agent


def main():
    parser = argparse.ArgumentParser(
        description="🔍 AI-powered Company Research Agent (100% FREE)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python main.py "Microsoft"
    python main.py "Tesla Inc" --output markdown
    python main.py "OpenAI" --quiet
    python main.py "Google LLC" --no-save --json

FREE tools used:
    - DuckDuckGo Search (no API key needed)
    - BeautifulSoup for web scraping
    - Groq (FREE tier) or Ollama (local) for LLM
        """
    )
    
    parser.add_argument(
        "company",
        type=str,
        help="Name of the company to research"
    )
    
    parser.add_argument(
        "--output", "-o",
        type=str,
        choices=["json", "markdown", "both"],
        default="both",
        help="Output format (default: both)"
    )
    
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Don't save results to file"
    )
    
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Minimal output (no progress display)"
    )
    
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON to stdout"
    )
    
    args = parser.parse_args()
    
    # Set output format in environment
    import os
    os.environ["OUTPUT_FORMAT"] = args.output
    
    # Run the agent
    result = run_scraper_agent(
        company_name=args.company,
        save_results=not args.no_save,
        verbose=not args.quiet and not args.json,
    )
    
    # Output as JSON if requested
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    
    return 0 if result.get("profile") else 1


if __name__ == "__main__":
    sys.exit(main())
