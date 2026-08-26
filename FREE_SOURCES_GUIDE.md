# Beacon - Free Public Sources

All data comes from free public sources: RIPE Stat, crt.sh, DNS, and Shodan InternetDB.
No paid subscriptions or API keys are required for core functionality.

## Collect Nigeria

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
python africa_exposed.py --country ng --collect --dns --subdomains
streamlit run dashboard/app.py
```

## Collect Other Countries

```powershell
python africa_exposed.py --country ke --collect --dns --subdomains
python africa_exposed.py --top 5 --collect --dns
python africa_exposed.py --all --collect --dns --subdomains
```

## Outputs

- `data/ripe/`: country IP prefixes and ASNs from RIPE Stat
- `data/crtsh/`: certificate domains from crt.sh
- `data/dns/`: A, AAAA, MX, NS, TXT, CNAME records and SPF/DMARC findings
- `data/subdomains/`: resolved common subdomains and wildcard results
- `data/free_sources/`: optional Shodan InternetDB enrichment for discovered DNS addresses

DNS requests use public resolvers `8.8.8.8` and `1.1.1.1`, with timeouts and a 0.5-second delay between lookups. Results are public observations and should be validated privately before remediation or publication.
