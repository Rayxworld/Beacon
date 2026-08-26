# Beacon

Beacon is an Africa-first public exposure intelligence platform for organizations. Give it an authorized root domain and it generates a public-internet exposure report that is practical to verify and act on.

## What It Measures

- Certificate-associated domains from crt.sh
- A, AAAA, MX, NS, TXT, and CNAME records
- SPF and DMARC email security posture
- Common subdomains and resolved addresses
- Public IP enrichment through Shodan InternetDB
- Repeatable reports that can be compared over time

All data comes from free public sources: RIPE Stat, crt.sh, DNS, and Shodan InternetDB. No paid subscriptions or API keys are required for core functionality.

## Quick Start

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
python africa_exposed.py --domain example.com
streamlit run dashboard/app.py
```

Only assess domains you own or have explicit permission to assess. DNS and certificate data are public observations, not proof of compromise.

## Africa-first Regional Research

For aggregate infrastructure research, the original country mode remains available:

```powershell
python africa_exposed.py --country ng --collect --dns --subdomains
```

## Reproducible Pilot Study

Edit `research/pilot_manifest.csv` and replace each placeholder with an official domain selected using the criteria in `research/METHODOLOGY.md`. Then run:

```powershell
python africa_exposed.py --study-manifest research/pilot_manifest.csv
```

The run creates an anonymized `research/dataset.json`, analysis-ready `research/dataset.csv`, and `research/summary.json`. Use `research/validate_dns.py` on a saved `dns.json` to independently check DNS presence measurements with a second resolver.

When measurement logic changes, regenerate all study reports with `--refresh`; do not mix reports produced by different collector versions.

```powershell
python africa_exposed.py --study-manifest research/pilot_manifest.csv --refresh
```

## Project Outputs

Target reports are saved under `data/targets/<domain>/`. Regional research outputs remain in `data/ripe/`, `data/crtsh/`, `data/dns/`, and `data/subdomains/`.

Each target report contains:

- `report.json`: posture score, findings, evidence, and change counts
- `report.md` and `report.html`: shareable executive and technical reports
- `disclosure_draft.txt`: a reviewable private notification draft
- `history/`: timestamped snapshots for change detection

## Research Paper

The working manuscript is [research/PAPER.md](research/PAPER.md). It defines the Africa-first pilot, measures, validation protocol, analysis plan, ethics, and the boundary between engineering fixtures and publishable study results.
