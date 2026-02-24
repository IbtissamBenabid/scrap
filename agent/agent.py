"""
Main entry point for the Company Scraper Agent
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
from .utils.constants import OUTPUT_FORMAT, OUTPUT_DIR


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

console = Console()


class CompanyScraperAgent:
    """
    AI-powered company information scraping agent for TPRM.
    
    Uses:
    - DuckDuckGo for search (no API key needed)
    - BeautifulSoup for scraping (concurrent)
    - Groq (FREE tier) or Ollama (local) for LLM extraction
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
        Research a company and extract TPRM profile.

        Returns:
            Dict with {company_name, profile, messages, errors}
        """
        if verbose:
            console.print(Panel(
                f"🔍 Researching: [bold cyan]{company_name}[/bold cyan]",
                title="TPRM Company Scraper Agent",
                subtitle="Fast & Accurate"
            ))

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            disable=not verbose,
        ) as progress:
            task = progress.add_task("Running research workflow...", total=None)
            result = run_graph(company_name)
            progress.update(task, description="Research complete! ✅")

        company_profile = result.get("company_profile", {})

        if save_results and company_profile:
            output_path = save_output(company_profile, company_name, self.output_format)
            if verbose:
                console.print(f"\n💾 Results saved to: [green]{output_path}[/green]")

        if verbose:
            self._display_results(company_profile)

        return {
            "company_name": company_name,
            "profile": company_profile,
            "messages": result.get("messages", []),
            "errors": result.get("errors", []),
        }

    def _display_results(self, profile: dict):
        """Display TPRM results in a rich console format."""
        if not profile:
            console.print("\n[yellow]No results found[/yellow]")
            return

        console.print("\n")

        # ── Basic Info ──
        basic = profile.get("basic_info", {})
        if basic and any(basic.values()):
            table = Table(title="📋 Basic Information")
            table.add_column("Field", style="cyan")
            table.add_column("Value", style="white")

            display_fields = [
                ("name", "Company Name"),
                ("description", "Description"),
                ("industry", "Industry"),
                ("sector", "Sector"),
                ("founded", "Founded"),
                ("headquarters", "Headquarters"),
                ("country", "Country"),
                ("employees", "Employees"),
                ("it_classification", "IT Classification"),
            ]
            for key, label in display_fields:
                val = basic.get(key)
                if val:
                    # Truncate long descriptions
                    display_val = str(val)[:120] + ("..." if len(str(val)) > 120 else "")
                    table.add_row(label, display_val)

            if basic.get("is_it_company") is not None:
                table.add_row("IT Company", "✅ Yes" if basic["is_it_company"] else "❌ No")

            if basic.get("sub_services"):
                table.add_row("Services", ", ".join(basic["sub_services"][:5]))

            console.print(table)

        # ── Contact & Social ──
        contact = profile.get("contact", {})
        social = profile.get("social_media", {})
        if (contact and any(contact.values())) or (social and any(social.values())):
            table = Table(title="🌐 Contact & Online Presence")
            table.add_column("Type", style="cyan")
            table.add_column("Value", style="blue")

            for key, label in [("official_website", "Website"), ("email", "Email"),
                               ("phone", "Phone"), ("address", "Address"),
                               ("support_email", "Support"), ("security_contact", "Security")]:
                val = contact.get(key)
                if val:
                    table.add_row(label, str(val))

            for key, label in [("linkedin", "LinkedIn"), ("twitter", "Twitter"),
                               ("facebook", "Facebook"), ("github", "GitHub"),
                               ("youtube", "YouTube")]:
                val = social.get(key)
                if val:
                    table.add_row(label, str(val))

            console.print(table)

        # ── Security & Compliance ──
        security = profile.get("security_compliance", {})
        if security:
            table = Table(title="🔒 Security & Compliance (TPRM)")
            table.add_column("Certification/Standard", style="cyan")
            table.add_column("Status", style="white")

            iso_fields = [
                ("iso_27001", "ISO 27001 (Info Security)"),
                ("iso_27017", "ISO 27017 (Cloud Security)"),
                ("iso_27018", "ISO 27018 (Cloud Privacy)"),
                ("iso_9001", "ISO 9001 (Quality)"),
                ("iso_14001", "ISO 14001 (Environmental)"),
                ("iso_22301", "ISO 22301 (Business Continuity)"),
            ]
            for key, name in iso_fields:
                cert = security.get(key)
                if isinstance(cert, dict) and cert.get("status"):
                    status = cert["status"]
                    color = "green" if status == "Certified" else "yellow"
                    extra = ""
                    if cert.get("certification_body"):
                        extra = f" ({cert['certification_body']})"
                    table.add_row(name, f"[{color}]✅ {status}{extra}[/{color}]")

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

            for cert in security.get("other_certifications", [])[:5]:
                table.add_row(cert, "[green]✅[/green]")

            if security.get("has_security_page"):
                url = security.get("security_page_url", "Yes")
                table.add_row("Security Page", f"[green]{url}[/green]")
            if security.get("has_trust_center"):
                url = security.get("trust_center_url", "Yes")
                table.add_row("Trust Center", f"[green]{url}[/green]")
            if security.get("has_bug_bounty"):
                url = security.get("bug_bounty_url", "Yes")
                table.add_row("Bug Bounty", f"[green]{url}[/green]")

            console.print(table)

        # ── Security Incidents ──
        incidents = profile.get("security_incidents", {})
        if incidents:
            table = Table(title="⚠️ Security Incidents (TPRM Risk)")
            table.add_column("Category", style="cyan")
            table.add_column("Details", style="white")

            breach_count = incidents.get("breach_count", 0)
            if breach_count > 0:
                color = "red" if breach_count > 2 else "yellow"
                table.add_row("Data Breaches", f"[{color}]{breach_count} found[/{color}]")
                if incidents.get("last_breach_date"):
                    table.add_row("  Last Breach", incidents["last_breach_date"])
                for breach in incidents.get("data_breaches", [])[:3]:
                    sev = breach.get("severity", "?")
                    desc = (breach.get("description", "")[:80] + "...") if breach.get("description") else ""
                    table.add_row(f"  Breach ({sev})", desc)
            else:
                table.add_row("Data Breaches", "[green]None found[/green]")

            cve_count = incidents.get("cve_count", 0)
            critical = incidents.get("critical_cve_count", 0)
            if cve_count > 0:
                color = "red" if critical > 0 else "yellow"
                table.add_row("CVE Vulnerabilities", f"[{color}]{cve_count} found ({critical} critical)[/{color}]")
            else:
                table.add_row("CVE Vulnerabilities", "[green]None found[/green]")

            if incidents.get("ransomware_history"):
                table.add_row("Ransomware", "[red]⚠️ HISTORY DETECTED[/red]")

            console.print(table)

        # ── Risk Indicators ──
        risk_indicators = profile.get("overall_risk_indicators", [])
        if risk_indicators:
            table = Table(title="🎯 Risk Indicators")
            table.add_column("Category", style="cyan")
            table.add_column("Indicator", style="white")
            table.add_column("Severity", style="white")

            for ri in risk_indicators[:8]:
                sev = ri.get("severity", "")
                sev_color = {"Critical": "red", "High": "red", "Medium": "yellow", "Low": "green"}.get(sev, "white")
                table.add_row(
                    ri.get("category", ""),
                    ri.get("indicator", ""),
                    f"[{sev_color}]{sev}[/{sev_color}]",
                )

            console.print(table)

        # ── Data Quality ──
        quality = profile.get("data_quality_score", 0)
        if quality:
            pct = int(quality * 100) if quality <= 1.0 else int(quality)
            color = "green" if pct >= 70 else "yellow" if pct >= 40 else "red"
            console.print(f"\n📊 Data Quality Score: [{color}]{pct}%[/{color}]")

        sources = profile.get("raw_sources", [])
        if sources:
            console.print(f"📚 [dim]Based on {len(sources)} sources[/dim]")


def run_scraper_agent(
    company_name: str,
    save_results: bool = True,
    verbose: bool = True,
) -> dict:
    """Convenience function to run the scraper agent."""
    agent = CompanyScraperAgent()
    return agent.research_company(company_name, save_results, verbose)
