# Beacon — Africa-First Internet Exposure Intelligence

**Open-source, reproducible passive measurement framework for African organizational infrastructure.**

[![Tests](https://github.com/Rayxworld/africa-exposed-enhanced/actions/workflows/tests.yml/badge.svg)](https://github.com/Rayxworld/africa-exposed-enhanced/actions)
[![Docker](https://github.com/Rayxworld/africa-exposed-enhanced/actions/workflows/docker.yml/badge.svg)](https://github.com/Rayxworld/africa-exposed-enhanced/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Study Status: Active](https://img.shields.io/badge/study%20status-active%20analysis-brightgreen.svg)]()

---

## What Beacon Measures

**Public Internet Exposure Intelligence** — without authentication, exploitation, or intrusive scanning.

- **Certificate Transparency**: Historical domain names from crt.sh
- **DNS Infrastructure**: A, AAAA, MX, NS, TXT, CNAME, and SPF/DMARC records
- **Email Security Posture**: SPF adoption, DMARC enforcement policy
- **Subdomain Discovery**: Common subdomains (mail, vpn, admin, etc.) that resolve
- **Public IP Enrichment**: Service metadata via Shodan InternetDB
- **Historical Tracking**: Timestamped reports for time-series analysis

**All data comes from free public sources** — RIPE Stat, crt.sh, public DNS, Shodan InternetDB.  
No paid API keys or credentials required for core functionality.

---

## Quick Start (5 Minutes)

### Option A: Docker (Recommended for Reproducibility)

```bash
# Build image
docker build -t beacon:latest .

# Assess a domain
docker run --rm -v $(pwd)/data:/app/data beacon:latest --domain example.com

# Launch dashboard
docker run -p 8501:8501 -v $(pwd)/data:/app/data beacon:latest \
  streamlit run dashboard/app.py
```

### Option B: Local Python Environment

```bash
# Setup
python -m venv venv
source venv/bin/activate  # or: venv\Scripts\Activate.ps1 on Windows
pip install -r requirements.txt

# Assess organization
python africa_exposed.py --domain example.com

# Launch dashboard
streamlit run dashboard/app.py
```

### Option C: Automated (GitHub Actions)

No setup required. Repository runs Beacon automatically:
- **Weekly scans**: All 15 African countries (Sunday 3 AM UTC)
- **Manual trigger**: Click "Run workflow" in GitHub Actions
- **Results**: Auto-committed to repository

---

## Expanded Study: 15 Countries, 75 Organizations

**Pilot expansion from 6 to 15 countries** for stronger statistical power and regional representation:

| Region | Countries | Sectors | Total |
|--------|-----------|---------|-------|
| West Africa | Nigeria, Ghana, Senegal, Côte d'Ivoire | 5 | 20 |
| East Africa | Kenya, Tanzania, Ethiopia, Rwanda, Uganda | 5 | 25 |
| Southern Africa | South Africa, Zambia, Botswana | 5 | 15 |
| North Africa | Egypt, Morocco | 5 | 10 |
| Central Africa | Cameroon | 5 | 5 |
| **Total** | **15 countries** | **5 sectors** | **75 organizations** |

**Sectors**: Government, Universities, Financial/Business, Healthcare, Telecommunications/Technology

Run the expanded study:

```bash
python africa_exposed.py --study-manifest research/expanded_manifest.csv
```

---

## Key Features

### 🔬 Reproducible Research
- Documented methodology ([research/METHODOLOGY.md](research/METHODOLOGY.md))
- Published findings ([research/PAPER.md](research/PAPER.md))
- Unit tests for domain normalization, CT parsing, SPF/DMARC, statistics
- Multi-resolver DNS validation for independent verification

### 📊 Longitudinal Tracking
- Compare organizational posture across time periods
- Detect security improvements and regressions
- Time-series change detection ([research/time_series_analyzer.py](research/time_series_analyzer.py))

### 🛡️ Policy-Ready Recommendations
- Per-sector guidelines ([research/POLICY_RECOMMENDATIONS.md](research/POLICY_RECOMMENDATIONS.md))
- Implementation roadmaps for government/finance/healthcare/telecom
- Regulatory integration suggestions

### 🐳 Production-Ready Deployment
- Docker containerization for reproducible environments
- GitHub Actions CI/CD for automated scanning and reporting
- Data validation and quality checks

### 📈 Dashboarding & Reporting
- Interactive Streamlit dashboard
- HTML/Markdown exportable reports
- Private remediation drafts for organizations

---

## Research Highlights

**Key Findings from Pilot Study (N=30)**:

- **Email Authentication Crisis in Government**: 0% of government domains enforce DMARC (vs. 100% in financial sector) → **$\chi^2 = 16.20, p < 0.0001$**
- **SPF Adoption**: 86.7% (95% CI: 70.3%–94.7%), but 53.8% use weak softfail policies
- **DMARC Enforcement**: Only 60% of adopting organizations enforce active rejection/quarantine
- **Attack Surface**: Average 13.27 resolvable subdomains per organization (range: 1–70)
- **Certificate Transparency API Degradation**: 96.7% of queries experienced rate-limiting/timeouts

→ **See full paper**: [research/PAPER.md](research/PAPER.md)

---

## Deployment Guides

| Use Case | Guide |
|----------|-------|
| **Academic Research** | One-time study on local machine | [DEPLOYMENT.md](DEPLOYMENT.md#scenario-1-academic-research) |
| **Continuous Monitoring** | Quarterly re-scans (GitHub Actions or self-hosted) | [DEPLOYMENT.md](DEPLOYMENT.md#scenario-2-continuous-monitoring) |
| **Organizational Self-Assessment** | Single domain audit | [DEPLOYMENT.md](DEPLOYMENT.md#scenario-3-organizational-self-assessment) |
| **SOC/CISO Integration** | Send findings to Slack, webhooks, etc. | [DEPLOYMENT.md](DEPLOYMENT.md#scenario-4-integration-with-soc-ciso-tools) |
| **Cloud Deployment** | AWS Lambda, Azure Functions, Google Cloud | [CLOUD_DEPLOYMENT.md](CLOUD_DEPLOYMENT.md) (coming) |

**Full deployment guide**: [DEPLOYMENT.md](DEPLOYMENT.md)

---

## Important Ethical & Legal Notes

- ✅ **Passive observation only** — no port scans, credential testing, or active probing
- ✅ **Domains you own or authorized to assess** — only run on authorized domains
- ✅ **Research-only scope** — DNS and certificate data are public, not proof of compromise
- ✅ **Responsible disclosure** — private remediation drafts available for critical findings
- ✅ **Anonymized research datasets** — domain names hashed for publication

---

## Architecture

```
africa_exposed.py (main orchestrator)
    ├── collectors/
    │   ├── ripe_collector.py          → Regional IP/ASN data
    │   ├── crtsh_collector.py         → Certificate Transparency
    │   ├── dns_security_collector.py  → SPF/DMARC/DNS records
    │   ├── subdomain_enumerator.py    → Wordlist-based discovery
    │   ├── internetdb_collector.py    → Shodan enrichment
    │   ├── findings_engine.py         → Report generation
    │   ├── research_dataset.py        → Anonymization & aggregation
    │   └── error_handling.py          → Structured logging & retry logic
    │
    ├── research/
    │   ├── METHODOLOGY.md             → Study design documentation
    │   ├── PAPER.md                   → Academic manuscript
    │   ├── POLICY_RECOMMENDATIONS.md  → Implementation guidance
    │   ├── analyze_study.py           → Statistical analysis
    │   ├── time_series_analyzer.py    → Longitudinal tracking
    │   ├── data_validator.py          → Quality assurance
    │   └── validate_dns.py            → Multi-resolver verification
    │
    ├── dashboard/
    │   └── app.py                     → Streamlit visualization
    │
    ├── .github/workflows/
    │   ├── tests.yml                  → Unit tests on every commit
    │   ├── scheduled-scans.yml        → Weekly country scans
    │   ├── docker.yml                 → Docker image builds
    │   └── analysis.yml               → Statistical analysis runs
    │
    └── Dockerfile + docker-compose.yml → Container orchestration
```

---

## Contributing & Collaboration

**Want to help?** See [CONTRIBUTING.md](CONTRIBUTING.md)

- Report issues or suggest improvements → GitHub Issues
- Expand to new countries or sectors → Submit PR with updated manifest
- Improve statistical analysis → Add tests, document methodology
- Deploy in your organization → Share learnings

**Citation**:
```bibtex
@misc{beacon2026,
  title={Beacon: Africa-First Passive Internet Exposure Intelligence},
  author={Fafi, Raymond and Contributors},
  year={2026},
  howpublished={\url{https://github.com/Rayxworld/africa-exposed-enhanced}},
  note={Open-source research framework}
}
```

---

## Resources

- 📖 **[METHODOLOGY.md](research/METHODOLOGY.md)** — Study design, sampling, measurement pipeline
- 📄 **[PAPER.md](research/PAPER.md)** — Academic manuscript with findings & analysis
- 🎯 **[POLICY_RECOMMENDATIONS.md](research/POLICY_RECOMMENDATIONS.md)** — Implementation guides for policymakers
- 🚀 **[DEPLOYMENT.md](DEPLOYMENT.md)** — Deployment scenarios & troubleshooting
- 🧪 **[tests/](tests/)** — Unit tests & reproducibility verification
- 📊 **[research/](research/)** — Dataset, analysis code, validation tools

---

## Status

- ✅ Pilot study complete (N=30, 6 countries)
- ✅ Expanded manifest created (N=75, 15 countries)
- ✅ Policy recommendations published
- ✅ Docker containerization & GitHub Actions CI/CD
- ✅ Time-series change detection engine
- ✅ Comprehensive error handling & logging
- ✅ Data quality validation framework
- 🔄 Full expanded study execution (in progress)
- 🔄 Additional African countries (ongoing)

---

**Built with ❤️ for African digital infrastructure research**  
**Raymond Fafi & Contributors**

## Project Outputs

Target reports are saved under `data/targets/<domain>/`. Regional research outputs remain in `data/ripe/`, `data/crtsh/`, `data/dns/`, and `data/subdomains/`.

Each target report contains:

- `report.json`: posture score, findings, evidence, and change counts
- `report.md` and `report.html`: shareable executive and technical reports
- `disclosure_draft.txt`: a reviewable private notification draft
- `history/`: timestamped snapshots for change detection

## Research Paper

The working manuscript is [research/PAPER.md](research/PAPER.md). It defines the Africa-first pilot, measures, validation protocol, analysis plan, ethics, and the boundary between engineering fixtures and publishable study results.
