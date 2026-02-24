"""Quick accuracy test for the scraping agent."""
import json
import logging
logging.disable(logging.CRITICAL)

from agent import run_scraper_agent

r = run_scraper_agent("Cloudflare", save_results=False, verbose=False)

with open("output/cloudflare_test2.json", "w", encoding="utf-8") as f:
    json.dump(r, f, indent=2, default=str, ensure_ascii=False)

p = r["profile"]
bi = p["basic_info"]
ct = p["contact"]
sm = p["social_media"]
sc = p["security_compliance"]
si = p["security_incidents"]

print("=== ACCURACY CHECK ===")
print(f"Name:       {bi['name']}")
print(f"Website:    {ct['official_website']}")
print(f"LinkedIn:   {sm['linkedin']}")
print(f"Country:    {bi['country']}")
print(f"HQ:         {bi['headquarters']}")
print(f"Employees:  {bi['employee_count']}")
print(f"Founded:    {bi['founded']}")
print(f"Industry:   {bi['industry']}")
print(f"Sector:     {bi['sector']}")
print(f"Is IT:      {bi['is_it_company']}")
print(f"IT Class:   {bi['it_classification']}")
print(f"Sub-svc:    {bi['sub_services'][:5]}")
print(f"Twitter:    {sm['twitter']}")
print(f"GitHub:     {sm['github']}")
print(f"Email:      {ct['email']}")
print(f"ISO27001:   {sc['iso_27001']}")
print(f"SOC2 T2:    {sc['soc2_type2']}")
print(f"GDPR:       {sc['gdpr_compliant']}")
print(f"FedRAMP:    {sc['fedramp']}")
print(f"Breaches:   {si['breach_count']}")
print(f"CVEs:       {si['cve_count']}")
print(f"Quality:    {p['data_quality_score']}")
print(f"Sources:    {len(p['raw_sources'])}")
print(f"Risks:      {len(p['overall_risk_indicators'])}")
print("=== DONE ===")
