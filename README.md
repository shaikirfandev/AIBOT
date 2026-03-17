# 🎯 BBHunter – Bug Bounty Automation Suite
#s ource venv/bin/activate
> **Professional-grade** bug bounty automation toolkit used by ethical security researchers. Built with Python 3.10+, FastAPI, async I/O, and machine learning.

⚠️ **This tool must ONLY be used on authorized targets. Always obtain written permission before testing.**

---

## 📐 Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        BBHunter Architecture                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐               │
│  │   CLI    │  │ Dashboard│  │  REST    │  │WebSocket │               │
│  │ (Click)  │  │  (HTML)  │  │  API     │  │  (WS)   │               │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘               │
│       │              │              │              │                     │
│  ┌────▼──────────────▼──────────────▼──────────────▼─────┐             │
│  │                  Safety Gate                           │             │
│  │  (Authorization · Scope Check · Rate Limiting)         │             │
│  └────┬──────────────┬──────────────┬──────────────┬─────┘             │
│       │              │              │              │                     │
│  ┌────▼────┐   ┌─────▼────┐   ┌────▼─────┐  ┌────▼─────┐             │
│  │  Recon  │   │ Surface  │   │  Vuln    │  │ Analysis │             │
│  │ Engine  │──▶│ Mapping  │──▶│ Scanner  │──▶│ Engine   │             │
│  │         │   │ Engine   │   │ Engine   │  │          │             │
│  └─────────┘   └──────────┘   └──────────┘  └────┬─────┘             │
│       │                                           │                     │
│  ┌────▼────┐   ┌──────────┐   ┌──────────┐  ┌────▼─────┐             │
│  │ Payload │   │ Manual   │   │ Report   │  │ Learning │             │
│  │ Engine  │   │ Testing  │   │ Engine   │  │ Module   │             │
│  │         │   │ Assist.  │   │          │  │ (ML)     │             │
│  └─────────┘   └──────────┘   └──────────┘  └──────────┘             │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────┐           │
│  │             Shared Infrastructure                        │           │
│  │  Config · Database · Logger · Models · Safety            │           │
│  └─────────────────────────────────────────────────────────┘           │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 🧩 Modules

| # | Module | Description |
|---|--------|-------------|
| 1 | **Recon Engine** | Subdomain enumeration, DNS, CT logs, Wayback, GitHub, Cloud assets, ASN, Reverse IP |
| 2 | **Surface Mapping** | Web crawling, JavaScript analysis, API discovery, tech fingerprinting, WAF detection |
| 3 | **Vulnerability Scanner** | XSS, SQLi, SSRF, IDOR, CORS, Open Redirect, SSTI, Headers, JWT, Auth bypass |
| 4 | **Analysis Engine** | False positive reduction, exploit chain detection, severity recalculation, attack graphs |
| 5 | **Payload Engine** | Context-aware payload generation, WAF bypass mutations, DB-specific payloads |
| 6 | **Manual Testing Assistant** | Attack vector suggestions, response analysis, data decoding, payload recommendations |
| 7 | **Report Engine** | HackerOne / Bugcrowd templates, executive summaries, JSON exports |
| 8 | **Dashboard** | FastAPI REST API + real-time WebSocket + single-page web UI |
| 9 | **Learning Module** | ML-based false positive detection, feedback loop, payload effectiveness tracking |
| 10 | **Safety Rules** | Target authorization, scope enforcement, rate limiting, action audit logging |

---

## 🚀 Installation

### Prerequisites
- Python 3.10+
- Redis (for Celery workers, optional)
- Git

### Quick Start

```bash
# Clone
git clone https://github.com/your-org/bbhunter.git
cd bbhunter

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install
pip install -e ".[dev]"

# Configure authorized targets
cp authorized_targets.yaml.example authorized_targets.yaml
# Edit authorized_targets.yaml with YOUR targets

# Run
bbhunter --help
```

### Docker

```bash
# Build and run with Docker Compose
docker-compose up -d

# Access dashboard
open http://localhost:8000
```

---

## 📖 Usage

### CLI Commands

```bash
# Reconnaissance
bbhunter recon example.com
bbhunter recon example.com --quick         # Passive only
bbhunter recon example.com -o recon.json   # Save to file

# Surface Mapping
bbhunter surface example.com

# Vulnerability Scanning
bbhunter scan example.com
bbhunter scan example.com --scanners xss,sqli,ssrf

# Full Pipeline (recon → surface → scan → analysis → report)
bbhunter full example.com -o full_report.json

# Payload Generation
bbhunter payloads xss --context html
bbhunter payloads sqli --waf cloudflare

# Data Decoding
bbhunter decode "eyJhbGciOiJIUzI1NiJ9..."

# Dashboard
bbhunter dashboard --port 8000

# Learning Module
bbhunter learning stats
bbhunter learning retrain
```

### REST API

When the dashboard is running:

```bash
# Health check
curl http://localhost:8000/api/health

# Start recon
curl -X POST http://localhost:8000/api/recon \
  -H "Content-Type: application/json" \
  -d '{"target_domain": "example.com"}'

# Full scan pipeline
curl -X POST http://localhost:8000/api/scan/full \
  -H "Content-Type: application/json" \
  -d '{"target_domain": "example.com"}'

# Generate payloads
curl -X POST http://localhost:8000/api/payloads \
  -H "Content-Type: application/json" \
  -d '{"category": "xss", "context": "html"}'

# Submit feedback
curl -X POST http://localhost:8000/api/feedback \
  -H "Content-Type: application/json" \
  -d '{"vulnerability_id": "abc123", "is_true_positive": true}'

# Swagger docs
open http://localhost:8000/api/docs
```

### WebSocket (Real-time Updates)

```javascript
const ws = new WebSocket('ws://localhost:8000/ws');
ws.onmessage = (e) => console.log(JSON.parse(e.data));
// Events: recon_complete, surface_complete, scan_complete, phase_change, ...
```

---

## 🔧 Configuration

### `config.yaml`
Main application configuration — scanning limits, timeouts, enabled scanners, API keys (via env vars).

### `authorized_targets.yaml`
**CRITICAL** — Only domains listed here can be scanned. The Safety Gate blocks all unauthorized requests.

```yaml
authorized_targets:
  - domain: "example.com"
    program: "Example Bug Bounty"
    scope:
      - "*.example.com"
    out_of_scope:
      - "admin.example.com"
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` | GitHub API token for code search recon |
| `SHODAN_API_KEY` | Shodan API key |
| `CENSYS_API_KEY` | Censys API key |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key |

---

## 🧪 Vulnerability Scanner Details

### Supported Scanners

| Scanner | Techniques |
|---------|-----------|
| **XSS** | Reflected XSS, 16 payloads, DOM context detection |
| **SQLi** | Error-based (30+ DB patterns), boolean-blind, time-blind |
| **SSRF** | Cloud metadata, internal IP, protocol smuggling |
| **IDOR** | Parameter ID manipulation, path-based IDOR |
| **CORS** | Arbitrary origin, null origin, subdomain reflection |
| **Open Redirect** | 12 bypass payloads, HTTP + DOM redirect |
| **SSTI** | Jinja2, Twig, Freemarker, ERB, Smarty, Mako |
| **Headers** | 7 security headers, info disclosure |
| **JWT** | Algorithm none, weak secrets, missing claims |
| **Auth** | Username enumeration, default credentials |

---

## 🧠 Learning Module

The ML-based learning module continuously improves detection accuracy:

1. **Feedback Loop** — Researchers mark findings as TP/FP
2. **Feature Extraction** — Extracts 12 features from each finding
3. **Model Training** — Random Forest classifier trained on feedback
4. **Confidence Adjustment** — Future findings scored with learned model
5. **Payload Effectiveness** — Tracks which payloads produce true positives

---

## 📊 Dashboard

Access the web dashboard at `http://localhost:8000`:

- **Overview** — Active scans, vulnerability count, learning stats
- **Recon** — Launch and view reconnaissance results
- **Surface Map** — Attack surface visualization
- **Scanner** — Launch vulnerability scans
- **Vulnerabilities** — Triage findings (TP/FP feedback)
- **Payloads** — Generate context-aware payloads
- **Reports** — Generate HackerOne / Bugcrowd reports
- **Learning** — View ML model statistics and feedback

Real-time updates via WebSocket keep the dashboard live during scans.

---

## 🗂️ Project Structure

```
BugbountyHunter/
├── pyproject.toml                 # Dependencies & build config
├── config.yaml                    # Application config
├── authorized_targets.yaml        # REQUIRED: Target whitelist
├── Dockerfile                     # Container build
├── docker-compose.yml             # Full stack deployment
├── README.md
│
├── bbhunter/
│   ├── __init__.py
│   ├── cli.py                     # Click CLI entry point
│   ├── config.py                  # Pydantic config loader
│   ├── models.py                  # Core data models
│   ├── database.py                # SQLAlchemy async ORM
│   ├── logger.py                  # Rich logging + audit trail
│   ├── safety.py                  # Authorization safety gate
│   │
│   └── engines/
│       ├── __init__.py            # All engine exports
│       │
│       ├── recon/                 # Module 1: Reconnaissance
│       │   ├── engine.py          # Orchestrator
│       │   ├── subdomain.py       # Subdomain enumeration
│       │   ├── dns_enum.py        # DNS record enumeration
│       │   ├── wayback.py         # Wayback Machine scraper
│       │   ├── ct_logs.py         # Certificate Transparency
│       │   ├── github_recon.py    # GitHub code search
│       │   ├── cloud_recon.py     # Cloud asset discovery
│       │   ├── asn_lookup.py      # ASN / IP range lookup
│       │   └── reverse_ip.py      # Reverse IP lookup
│       │
│       ├── surface/               # Module 2: Surface Mapping
│       │   └── engine.py          # Crawler, JS analysis, WAF detect
│       │
│       ├── scanner/               # Module 3: Vulnerability Scanner
│       │   ├── engine.py          # Scanner orchestrator
│       │   ├── base_scanner.py    # Abstract base scanner
│       │   ├── xss_scanner.py
│       │   ├── sqli_scanner.py
│       │   ├── ssrf_scanner.py
│       │   ├── idor_scanner.py
│       │   ├── cors_scanner.py
│       │   ├── open_redirect_scanner.py
│       │   ├── ssti_scanner.py
│       │   ├── header_scanner.py
│       │   ├── jwt_scanner.py
│       │   └── auth_scanner.py
│       │
│       ├── analysis/              # Module 4: Intelligent Analysis
│       │   └── engine.py          # FP reduction, chain detection
│       │
│       ├── payloads/              # Module 5: Payload Generation
│       │   └── engine.py          # Context-aware + WAF bypass
│       │
│       ├── assistant/             # Module 6: Manual Testing
│       │   └── engine.py          # Attack vectors, decoder, advisor
│       │
│       ├── reporting/             # Module 7: Report Generation
│       │   └── engine.py          # HackerOne/Bugcrowd templates
│       │
│       ├── dashboard/             # Module 8: Dashboard
│       │   ├── __init__.py
│       │   └── api.py             # FastAPI + WebSocket + SPA
│       │
│       └── learning/              # Module 9: Learning Module
│           ├── __init__.py
│           ├── engine.py          # ML-based FP detection
│           └── module.py          # Feedback & pattern learning
```

---

## ⚖️ Legal & Ethical

- **NEVER** scan targets without explicit written authorization
- **NEVER** use this tool to cause denial of service
- **ALWAYS** follow responsible disclosure practices
- **ALWAYS** comply with the scope defined in the bug bounty program
- The Safety Gate module enforces authorization checks on every action

---

## 📜 License

MIT License — See [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing`)
5. Open a Pull Request

---

**Built for ethical hackers, by ethical hackers.** 🏴‍☠️
