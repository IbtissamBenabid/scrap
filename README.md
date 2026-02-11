# �️ TPRM Company Research Agent

**AI-powered Third Party Risk Management research tool - 100% FREE!**

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-Web%20App-red.svg)](https://streamlit.io)
[![FREE](https://img.shields.io/badge/Cost-FREE-brightgreen.svg)](.)

An intelligent web scraping agent designed for **Third Party Risk Management (TPRM)** that automatically researches vendors and extracts security-relevant information:

- 📋 **Basic Info** - Name, industry, sector (IT/Non-IT), sub-services
- 📞 **Contact Details** - Headquarters, website, phone, email
- 🌐 **Social Media** - LinkedIn, Twitter, Facebook profiles
- 🏆 **ISO Certifications** - 27001, 9001, 22301, 14001
- ✅ **Compliance** - SOC 2, PCI DSS, HIPAA, GDPR, FedRAMP
- 🔓 **Data Breaches** - Historical security incidents
- ⚠️ **CVE Vulnerabilities** - Known security vulnerabilities
- 📊 **Risk Scoring** - Automated risk assessment (1-10)

## ✨ Key Features

- **100% FREE** - No paid APIs required!
- **TPRM-Focused** - Designed for vendor risk assessment
- **Streamlit Web UI** - Beautiful, easy-to-use interface
- **IT/Non-IT Classification** - Automatic sector detection
- **DuckDuckGo Search** - Free search, no API key needed
- **Groq LLM** - Free AI-powered extraction
- **LangGraph Workflow** - Robust agent architecture

## 🚀 Quick Start

### 1. Setup Environment

```bash
cd scrap
python -m venv venv
.\venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/Mac
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure API Key

Create a `.env` file:

```env
GROQ_API_KEY=your_groq_api_key_here
```

Get a FREE API key at: https://console.groq.com/keys

### 4. Run the App

```bash
streamlit run app.py
```

Open http://localhost:8501 in your browser.

## 📖 Usage

### Web Interface (Recommended)

```bash
streamlit run app.py
```

1. Enter company name in the search bar
2. Click "Search"
3. View results in organized tabs:
   - **Basic Info** - Company details and services
   - **Certifications** - ISO and compliance status
   - **Security Incidents** - Breaches and CVEs
   - **Risk Summary** - Overall risk assessment
4. Download JSON for offline analysis

### Command Line

```bash
python main.py
```

Enter company name when prompted.

## 📂 Project Structure

```
scrap/
├── app.py                    # Streamlit web application
├── main.py                   # CLI entry point
├── requirements.txt          # Python dependencies
├── .env                      # API keys (create this)
├── README.md                 # Documentation
└── agent/
    ├── __init__.py
    ├── agent.py              # LangGraph agent
    ├── nodes.py              # Workflow nodes
    └── utils/
        ├── constants.py      # TPRM search templates
        ├── extractor.py      # Security data extraction
        ├── helpers.py        # Utility functions
        ├── llm.py            # Groq LLM integration
        ├── scraper.py        # Web scraping
        ├── search.py         # DuckDuckGo search
        └── states.py         # TPRM data models
```

## 🔧 Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `GROQ_API_KEY` | Groq API key (FREE) | Required |
| `SEARCH_MAX_RESULTS` | Results per search | 5 |
| `URL_LIMIT` | Max URLs to scrape | 10 |
| `REQUEST_TIMEOUT` | Timeout (seconds) | 30 |
| `REQUEST_DELAY` | Delay between requests | 1.0 |

## 🤖 How It Works

```
┌─────────────────────────────────────────────────────┐
│              TPRM Research Agent                     │
├─────────────────────────────────────────────────────┤
│                                                      │
│  1. Initialize                                       │
│     └─ Prepare TPRM-focused search queries          │
│              │                                       │
│              ▼                                       │
│  2. Search (DuckDuckGo - FREE)                      │
│     └─ Find certification, breach, CVE pages        │
│              │                                       │
│              ▼                                       │
│  3. Scrape (BeautifulSoup - FREE)                   │
│     └─ Extract page content                         │
│              │                                       │
│              ▼                                       │
│  4. Extract (Groq LLM - FREE)                       │
│     └─ AI-powered security data extraction          │
│              │                                       │
│              ▼                                       │
│  5. Display in Streamlit                            │
│     └─ Tabbed interface with risk scoring           │
│                                                      │
└─────────────────────────────────────────────────────┘
```

## 📊 Data Extracted

### Basic Information
| Field | Description |
|-------|-------------|
| Name | Official company name |
| Industry | Business sector |
| Sector | IT or Non-IT classification |
| Sub-Services | Detailed service offerings |
| Founded | Year established |
| Employees | Workforce size |

### Security Certifications
| Certification | Description |
|--------------|-------------|
| ISO 27001 | Information Security Management |
| ISO 9001 | Quality Management |
| ISO 22301 | Business Continuity |
| ISO 14001 | Environmental Management |
| SOC 2 Type II | Service Organization Controls |
| PCI DSS | Payment Card Security |
| HIPAA | Healthcare Data Protection |
| GDPR | EU Data Privacy |
| FedRAMP | US Government Cloud Security |

### Security Incidents
- **Data Breaches**: Date, records affected, breach type
- **CVE Vulnerabilities**: CVE ID, severity (CVSS), description

### Risk Assessment
- **Risk Score**: 1-10 scale (lower is better)
- **Risk Level**: Low / Medium / High / Critical
- **Factors**: Missing certifications, breach history, CVEs

## 📋 Sample Output

```json
{
  "basic_info": {
    "name": "Cloudflare, Inc.",
    "industry": "Cybersecurity & CDN",
    "sector": "IT",
    "sub_services": ["DDoS Protection", "WAF", "CDN", "Zero Trust"],
    "founded": "2009",
    "employees": "3,500+"
  },
  "certifications": [
    {"name": "ISO 27001", "status": "Certified", "scope": "Global Operations"},
    {"name": "SOC 2 Type II", "status": "Compliant"}
  ],
  "security_incidents": {
    "breaches": [],
    "cves": [
      {"cve_id": "CVE-2023-XXXX", "severity": "Medium", "cvss": 5.3}
    ]
  },
  "risk_assessment": {
    "overall_score": 2,
    "risk_level": "Low"
  }
}
```

## 🛡️ Responsible Use

- ⏱️ Adds delays between requests
- 🔄 Rotates user agents
- 📊 Limits request rates
- 🔒 Uses only publicly available information

Use responsibly for legitimate TPRM purposes.

## 📜 License

MIT License - Free for personal and commercial use.

## 🙏 Acknowledgments

- [DuckDuckGo](https://duckduckgo.com) - Free, private search
- [LangGraph](https://langchain-ai.github.io/langgraph/) - Agent orchestration
- [Groq](https://groq.com) - Fast, free LLM inference
- [Streamlit](https://streamlit.io) - Web app framework
- [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/) - HTML parsing

---

**Built for TPRM professionals - 100% FREE!**
