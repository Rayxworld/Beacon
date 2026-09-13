# Beacon Deployment & Reproducibility Guide

**For researchers, operators, and organizations wanting to run or extend Beacon research.**

---

## Quick Start (5 minutes)

### Option A: Local Python Environment

```bash
# Clone repository
git clone https://github.com/Rayxworld/africa-exposed-enhanced.git
cd africa-exposed-enhanced

# Create virtual environment
python -m venv venv

# Activate
# On Windows:
venv\Scripts\Activate.ps1
# On Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run a single domain assessment
python africa_exposed.py --domain example.com

# Launch dashboard
streamlit run dashboard/app.py
```

### Option B: Docker (Recommended for Reproducibility)

```bash
# Build image
docker build -t beacon:latest .

# Run collector
docker run --rm -v $(pwd)/data:/app/data beacon:latest --domain example.com

# Run dashboard
docker run -p 8501:8501 -v $(pwd)/data:/app/data beacon:latest streamlit run dashboard/app.py

# Or use docker-compose
docker-compose up dashboard
```

### Option C: GitHub Actions (Automated Cloud Runs)

No setup required. GitHub Actions runs Beacon automatically:
- **Weekly scans**: Every Sunday at 3 AM UTC (all 15 countries)
- **Manual trigger**: Click "Run workflow" in GitHub Actions tab
- **Results**: Automatically committed to repository

---

## Expanding the Study (Adding Countries/Organizations)

### Step 1: Update Manifest

Edit [research/expanded_manifest.csv](research/expanded_manifest.csv):

```csv
country,country_code,region,sector,organization_id,domain,selection_source,selection_date,authorization_status,notes
Yemen,YE,Middle East,government,YE-GOV-001,example.gov.ye,https://example.com,2026-09-13,passive-public-research-only,Description
```

**Requirements**:
- Domain must be official (government/education portals, major banks/telecom)
- Selection source must cite official regulatory directory (central bank website, university commission, etc.)
- Must have authorization status documented (passive-public-research-only)
- For sensitive organizations, coordinate with national CERT/cybersecurity agency first

### Step 2: Validate Manifest

```bash
python -c "
from collectors.research_dataset import read_manifest
manifest = read_manifest('research/expanded_manifest.csv')
print(f'Loaded {len(manifest)} organizations')
print(f'Countries: {len(set(m[\"country\"] for m in manifest))}')
print(f'Sectors: {set(m[\"sector\"] for m in manifest)}')
"
```

### Step 3: Run Study

```bash
# Run full study
python africa_exposed.py --study-manifest research/expanded_manifest.csv

# Or refresh existing data
python africa_exposed.py --study-manifest research/expanded_manifest.csv --refresh

# View progress
streamlit run dashboard/app.py
```

---

## Data Structure & Outputs

### Organization Report Format

Each organization gets a directory: `data/targets/{domain}/`

```
data/targets/example.com/
├── report.json              # Machine-readable findings
├── report.md                # Human-readable markdown
├── report.html              # Shareable HTML report
├── disclosure_draft.txt     # Private remediation email draft
├── dns.json                 # Raw DNS records collected
├── domains.json             # Certificate domains
├── subdomains.json          # Discovered subdomains
├── internetdb.json          # IP enrichment data
└── history/
    ├── report_2026-09-13T123456Z.json
    ├── report_2026-09-20T123456Z.json
    └── ... (timestamped snapshots for time-series analysis)
```

### Research Dataset Format

After running study manifest, generate analysis datasets:

```bash
python -c "
from collectors.research_dataset import build_dataset, save_csv, save_dataset
dataset = build_dataset('research/expanded_manifest.csv', 'research/dataset.json')
save_csv(dataset, 'research/dataset.csv')
"
```

Results in:
- `research/dataset.json` — Machine-readable, anonymized (domain_hash used as ID)
- `research/dataset.csv` — Analysis-ready spreadsheet format
- `research/summary.json` — Aggregate statistics

### Time-Series Change Detection

Compare organizational posture across measurement periods:

```bash
python -c "
from research.time_series_analyzer import TimeSeriesAnalyzer
from pathlib import Path

analyzer = TimeSeriesAnalyzer(Path('data'))
comparison = analyzer.compare_periods('example.com')
print(f'DMARC adoption: {comparison.dmarc_adoption}')
print(f'SPF enforcement improved: {comparison.spf_enforcement_improved}')
print(f'Posture score change: {comparison.posture_improvement}')
print(f'Overall trend: {comparison.overall_trend}')

# Generate full report
analyzer.generate_report(Path('research/timeseries_analysis.json'))
"
```

---

## Deployment Scenarios

### Scenario 1: Academic Research (One-Time Study)

```bash
# Local execution with version control
git clone <repo>
cd africa-exposed-enhanced
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run study
python africa_exposed.py --study-manifest research/expanded_manifest.csv

# Analyze
cd research
python analyze_study.py

# Commit results
git add data/ research/
git commit -m "Study execution - <date>"
git push
```

### Scenario 2: Continuous Monitoring (Quarterly Re-scans)

**Option A: GitHub Actions (Free)**
```
# Workflow runs automatically weekly
# See .github/workflows/scheduled-scans.yml

# Results auto-committed to repository
# Dashboard at: https://github.com/Rayxworld/beacon/actions
```

**Option B: Self-Hosted (Your Server)**
```bash
# Create cron job
crontab -e

# Add:
0 2 * * 0 cd /opt/beacon && python africa_exposed.py --country ng --collect --dns --subdomains

# Or use systemd timer (Linux)
# See SYSTEMD_TIMER.md for configuration
```

**Option C: Cloud (AWS/Azure/GCP)**
```yaml
# Deploy via Lambda/Cloud Functions
# Scheduled trigger: weekly
# Output: S3/Blob Storage
# See CLOUD_DEPLOYMENT.md for cloud provider guides
```

### Scenario 3: Organizational Self-Assessment (Single Domain)

For organizations wanting to audit themselves:

```bash
# Simple one-liner
docker run --rm beacon:latest --domain yourbank.com

# Results saved to container stdout (capture with > output.json)
docker run --rm beacon:latest --domain yourbank.com > yourbank_report.json

# View HTML report
docker run --rm beacon:latest --domain yourbank.com | jq '.report_html' > report.html
# Open report.html in browser
```

### Scenario 4: Integration with SOC/CISO Tools

**Send findings to Slack**:
```bash
# Run collection
python africa_exposed.py --domain example.com

# Post to Slack
python -c "
import json
import requests
findings = json.load(open('data/targets/example.com/report.json'))
slack_msg = f'Security posture: {findings[\"metadata\"][\"posture_score\"]} (findings: {len(findings[\"findings\"][\"all\"])})'
requests.post(os.environ['SLACK_WEBHOOK'], json={'text': slack_msg})
"
```

---

## Validation & Quality Assurance

### Independent DNS Validation

```bash
# Validate DNS records across multiple resolvers
python research/validate_dns.py data/targets/example.com/dns.json

# Output: validation_results.json showing agreement across Google/Cloudflare/Quad9
```

### Run Test Suite

```bash
# Unit tests (zero external network)
pytest tests/ -v

# Coverage report
pytest tests/ --cov=collectors --cov-report=html
# Open htmlcov/index.html
```

### Data Quality Checks

```bash
python -c "
from collectors.research_dataset import validate_dataset
dataset = json.load(open('research/dataset.json'))
issues = validate_dataset(dataset)
print(f'Found {len(issues)} quality issues')
for issue in issues:
  print(f'  - {issue}')
"
```

---

## Extension Points

### Adding a New Data Source

1. Create collector in `collectors/new_source_collector.py`
2. Implement `collect_domain(domain) -> dict` function
3. Register in `africa_exposed.py` main pipeline
4. Add unit tests
5. Document in README

Example:
```python
# collectors/my_collector.py
def collect_domain(domain):
    """Collect additional indicators for domain."""
    return {
        "domain": domain,
        "indicators": [...],
        "collection_date": datetime.utcnow().isoformat(),
    }

# africa_exposed.py - add to analyze_domain():
my_data = my_collector.collect_domain(domain)
report["my_source"] = my_data
```

### Customizing Analysis

Edit `research/analyze_study.py` to:
- Add new statistical tests
- Calculate custom metrics
- Generate additional visualizations
- Export to different formats

---

## Troubleshooting

### DNS Queries Timing Out
```bash
# Increase timeout
python africa_exposed.py --domain example.com --dns-timeout 5.0

# Use different resolver
python -c "
from collectors.dns_security_collector import collect_domain
# Specify custom resolver IP
result = collect_domain('example.com', resolver='8.8.8.8')
"
```

### Certificate Transparency Rate Limits
Beacon automatically detects and flags CT API degradation:
```json
{
  "certificate_data_available": false,
  "certificate_query_status": "rate_limited",
  "fallback_used": true,
  "certificate_result_count": 1
}
```

When this occurs:
- Findings marked with `null` rather than misleading values
- Coverage percentage calculated as `null` (not `1.0`)
- Retry scheduled after 24 hours

### Docker Permission Issues (Linux)
```bash
# Run with sudo or add user to docker group
sudo usermod -aG docker $USER
newgrp docker
docker run beacon:latest --help
```

---

## Contributing & Research Collaboration

### Share Improvements
```bash
git checkout -b feature/my-improvement
# Make changes
git commit -am "Add feature X"
git push origin feature/my-improvement
# Open pull request on GitHub
```

### Report Issues
Use GitHub Issues with template:
- Research question
- Expected vs. actual behavior
- Steps to reproduce
- System info (OS, Python version, etc.)

### Cite This Work

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

## Additional Resources

- **API Documentation**: [API.md](API.md) — Programmatic access to collectors
- **Cloud Deployment**: [CLOUD_DEPLOYMENT.md](CLOUD_DEPLOYMENT.md) — AWS/Azure/GCP setup
- **Dataset Guide**: [DATA_DICTIONARY.md](DATA_DICTIONARY.md) — Field definitions
- **Methodology**: [research/METHODOLOGY.md](research/METHODOLOGY.md) — Research design
- **Policy Guide**: [research/POLICY_RECOMMENDATIONS.md](research/POLICY_RECOMMENDATIONS.md) — Implementation for policymakers
- **Paper**: [research/PAPER.md](research/PAPER.md) — Academic manuscript

---

## Contact & Support

**Questions?** Open an issue on GitHub or contact:
- Research: [research@beacon.example]
- Infrastructure: [ops@beacon.example]

**Want to participate?** See [CONTRIBUTING.md](CONTRIBUTING.md)
