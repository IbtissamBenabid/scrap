"""
Main entry point for the Company Scraper Agent
100% FREE - No paid APIs required!
"""
import logging
import json
from typing import Optional
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from .graph import run_graph
from .utils.helpers import save_output, convert_to_markdown
from .utils.constants import OUTPUT_FORMAT, OUTPUT_DIR, LOG_LEVEL


# Configure logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

console = Console()


class CompanyScraperAgent:
    """
    AI-powered company information scraping agent
    
    100% FREE - Uses:
    - DuckDuckGo for search (no API key needed)
    - BeautifulSoup for scraping (no API key needed)
    - Groq (FREE tier) or Ollama (runs locally) for LLM
    """
    
    def __init__(
        self,
        output_format: str = OUTPUT_FORMAT,
        output_dir: str = OUTPUT_DIR,
    ):
        self.output_format = output_format
        self.output_dir = output_dir
    
    def research_company(
        self,
        company_name: str,
        save_results: bool = True,
        verbose: bool = True,
    ) -> dict:
        """
        Research a company and extract all available information
        
        Args:
            company_name: Name of the company to research
            save_results: Whether to save results to file
            verbose: Whether to show progress in console
            
        Returns:
            Dictionary with company profile and metadata
        """
        if verbose:
            console.print(Panel(
                f"🔍 Researching: [bold cyan]{company_name}[/bold cyan]",
                title="Company Scraper Agent",
                subtitle="100% FREE"
            ))
        
        # Run the scraping workflow
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            disable=not verbose,
        ) as progress:
            task = progress.add_task("Running research workflow...", total=None)
            
            result = run_graph(company_name)
            
            progress.update(task, description="Research complete!")
        
        company_profile = result.get("company_profile", {})
        
        # Save results
        if save_results and company_profile:
            output_path = save_output(company_profile, company_name, self.output_format)
            if verbose:
                console.print(f"\n💾 Results saved to: [green]{output_path}[/green]")
        
        # Display results
        if verbose:
            self._display_results(company_profile)
        
        return {
            "company_name": company_name,
            "profile": company_profile,
            "messages": result.get("messages", []),
            "errors": result.get("errors", []),
        }
    
    def _display_results(self, profile: dict):
        """Display TPRM results in a nice format"""
        if not profile:
            console.print("\n[yellow]No results found[/yellow]")
            return
        
        console.print("\n")
        
        # Basic info table
        basic = profile.get("basic_info", {})
        if any(basic.values()):
            table = Table(title="📋 Basic Information")
            table.add_column("Field", style="cyan")
            table.add_column("Value", style="white")
            
            if basic.get("name"):
                table.add_row("Company Name", basic["name"])
            if basic.get("industry"):
                table.add_row("Industry", basic["industry"])
            if basic.get("sector"):
                table.add_row("Sector", basic["sector"])
            if basic.get("is_it_company") is not None:
                it_status = "✅ Yes" if basic["is_it_company"] else "❌ No"
                table.add_row("IT Company", it_status)
            if basic.get("it_classification"):
                table.add_row("IT Classification", basic["it_classification"])
            if basic.get("sub_services"):
                services = ", ".join(basic["sub_services"][:5])
                table.add_row("Services", services[:100])
            if basic.get("employee_count"):
                table.add_row("Employees", basic["employee_count"])
            if basic.get("headquarters") or basic.get("country"):
                location = f"{basic.get('headquarters', '')} {basic.get('country', '')}".strip()
                table.add_row("Location", location)
            
            console.print(table)
        
        # Contact & Social Media table
        contact = profile.get("contact", {})
        social = profile.get("social_media", {})
        if any(contact.values()) or any(social.values()):
            table = Table(title="🌐 Contact & Online Presence")
            table.add_column("Type", style="cyan")
            table.add_column("Value", style="blue")
            
            if contact.get("official_website"):
                table.add_row("Official Website", contact["official_website"])
            if social.get("linkedin"):
                table.add_row("LinkedIn", social["linkedin"])
            if social.get("twitter"):
                table.add_row("Twitter", social["twitter"])
            if social.get("github"):
                table.add_row("GitHub", social["github"])
            if contact.get("email"):
                table.add_row("Email", contact["email"])
            if contact.get("phone"):
                table.add_row("Phone", contact["phone"])
            if contact.get("security_contact"):
                table.add_row("Security Contact", contact["security_contact"])
            
            console.print(table)
        
        # Security & Compliance - MOST IMPORTANT FOR TPRM
        security = profile.get("security_compliance", {})
        if security:
            table = Table(title="🔒 Security & Compliance (TPRM)")
            table.add_column("Certification/Standard", style="cyan")
            table.add_column("Status", style="white")
            
            # ISO Certifications
            iso_certs = [
                ("iso_27001", "ISO 27001 (Info Security)"),
                ("iso_27017", "ISO 27017 (Cloud Security)"),
                ("iso_27018", "ISO 27018 (Cloud Privacy)"),
                ("iso_9001", "ISO 9001 (Quality)"),
                ("iso_14001", "ISO 14001 (Environmental)"),
                ("iso_22301", "ISO 22301 (Business Continuity)"),
            ]
            
            for key, name in iso_certs:
                cert = security.get(key, {})
                if isinstance(cert, dict) and cert.get("status"):
                    status = cert["status"]
                    color = "green" if status == "Certified" else "yellow"
                    table.add_row(name, f"[{color}]{status}[/{color}]")
            
            # Other certifications
            if security.get("soc2_type2"):
                table.add_row("SOC 2 Type II", "[green]✅ Certified[/green]")
            elif security.get("soc2_type1"):
                table.add_row("SOC 2 Type I", "[green]✅ Certified[/green]")
            
            if security.get("soc1"):
                table.add_row("SOC 1", "[green]✅ Certified[/green]")
            if security.get("pci_dss"):
                table.add_row("PCI-DSS", "[green]✅ Compliant[/green]")
            if security.get("hipaa_compliant"):
                table.add_row("HIPAA", "[green]✅ Compliant[/green]")
            if security.get("gdpr_compliant"):
                table.add_row("GDPR", "[green]✅ Compliant[/green]")
            if security.get("fedramp"):
                table.add_row("FedRAMP", "[green]✅ Authorized[/green]")
            
            # Other certs
            other_certs = security.get("other_certifications", [])
            for cert in other_certs[:5]:
                table.add_row(cert, "[green]✅[/green]")
            
            # Security practices
            if security.get("has_security_page"):
                url = security.get("security_page_url", "Yes")
                table.add_row("Security Page", f"[green]{url}[/green]")
            if security.get("has_trust_center"):
                url = security.get("trust_center_url", "Yes")
                table.add_row("Trust Center", f"[green]{url}[/green]")
            if security.get("has_bug_bounty"):
                table.add_row("Bug Bounty Program", "[green]✅ Yes[/green]")
            
            console.print(table)
        
        # Security Incidents - CRITICAL FOR TPRM
        incidents = profile.get("security_incidents", {})
        if incidents:
            table = Table(title="⚠️ Security Incidents (TPRM Risk)")
            table.add_column("Category", style="cyan")
            table.add_column("Details", style="white")
            
            # Data Breaches
            breach_count = incidents.get("breach_count", 0)
            if breach_count > 0:
                color = "red" if breach_count > 2 else "yellow"
                table.add_row("Data Breaches Found", f"[{color}]{breach_count}[/{color}]")
                
                if incidents.get("last_breach_date"):
                    table.add_row("Last Breach Date", incidents["last_breach_date"])
                
                for breach in incidents.get("data_breaches", [])[:3]:
                    if breach.get("description"):
                        desc = breach["description"][:80] + "..."
                        severity = breach.get("severity", "Unknown")
                        table.add_row(f"  Breach ({severity})", desc)
            else:
                table.add_row("Data Breaches", "[green]None found[/green]")
            
            # CVE Vulnerabilities
            cve_count = incidents.get("cve_count", 0)
            critical_count = incidents.get("critical_cve_count", 0)
            if cve_count > 0:
                color = "red" if critical_count > 0 else "yellow"
                table.add_row("CVE Vulnerabilities", f"[{color}]{cve_count} found ({critical_count} critical)[/{color}]")
                
                for cve in incidents.get("cve_vulnerabilities", [])[:3]:
                    cve_id = cve.get("cve_id", "Unknown")
                    severity = cve.get("severity", "Unknown")
                    patched = "✅ Patched" if cve.get("patched") else "⚠️ Check status"
                    table.add_row(f"  {cve_id}", f"{severity} - {patched}")
            else:
                table.add_row("CVE Vulnerabilities", "[green]None found[/green]")
            
            # Ransomware
            if incidents.get("ransomware_history"):
                table.add_row("Ransomware History", "[red]⚠️ Yes - HIGH RISK[/red]")
            
            console.print(table)
        
        # Data Quality Score
        quality_score = profile.get("data_quality_score", 0)
        if quality_score:
            color = "green" if quality_score >= 60 else "yellow" if quality_score >= 40 else "red"
            console.print(f"\n📊 Data Quality Score: [{color}]{quality_score}%[/{color}]")
        
        # Sources
        sources = profile.get("raw_sources", [])
        if sources:
            console.print(f"\n📚 [dim]Based on {len(sources)} sources[/dim]")


def run_scraper_agent(
    company_name: str,
    save_results: bool = True,
    verbose: bool = True,
) -> dict:
    """
    Convenience function to run the scraper agent
    
    Args:
        company_name: Name of the company to research
        save_results: Whether to save results to file
        verbose: Whether to show progress
        
    Returns:
        Dictionary with company profile
    """
    agent = CompanyScraperAgent()
    return agent.research_company(company_name, save_results, verbose)
