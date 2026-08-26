# Beacon — Quick Start

## Step 1: Setup
```powershell
cd africa-exposed-enhanced
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Step 2: Generate an Organization Report
```powershell
# Replace this with an organization domain you are authorized to assess
python africa_exposed.py --domain example.com
```

The report is saved under `data/targets/example.com/` and covers certificate names, DNS records, email security, common subdomains, and public IP enrichment.
It also creates a posture score, prioritized findings, Markdown/HTML reports, a disclosure draft, and a history snapshot.

## Step 3: Launch Dashboard
```powershell
streamlit run dashboard/app.py
```

## Step 4: Regional Research Mode
```powershell
# Optional aggregate research mode
python africa_exposed.py --country ng --collect --dns --subdomains
python africa_exposed.py --top 5 --collect --dns --subdomains
```

## Step 5: Data sources

All data comes from free public sources: RIPE Stat, crt.sh, DNS, and Shodan InternetDB.
No paid subscriptions or API keys are required for core functionality.
