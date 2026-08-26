# Beacon Research Data Sources

This registry separates direct Beacon measurements from contextual research data. It prevents the study from treating a public website list as a representative population.

## Direct measurement sources

| Source | Variables | Access | Role |
|---|---|---|---|
| Official organization directories | country, sector, organization, official domain | public web pages or downloadable registries | sampling frame |
| crt.sh | certificate-associated names | `https://crt.sh/?q=%25.example.org&output=json` | certificate discovery |
| RIPE Stat | prefixes and ASNs | `https://stat.ripe.net/data/country-resource-list/data.json?resource=NG` | country infrastructure context |
| Public DNS | A, AAAA, MX, NS, TXT, CNAME, SPF, DMARC | `8.8.8.8` and `1.1.1.1` | Beacon measurements |
| Shodan InternetDB | previously observed public IP ports and services | `https://internetdb.shodan.io/<ip>` | IP enrichment only |
| RDAP bootstrap | registration and registrar metadata | `https://data.iana.org/rdap/dns.json` | domain attribution support |
| Common Crawl Index | publicly crawled hostnames and pages | `https://index.commoncrawl.org/` | independent discovery/validation |

## Sampling-frame sources

Use official sources to identify organizations and verify their domains. Save the source URL and selection date in the manifest.

### Confirmed official starting points

- Nigeria: [National Universities Commission](https://www.nuc.edu.ng/) - official university regulator; the homepage publishes current university totals and links to statistical digests.
- Ghana: [Ghana Tertiary Education Commission](https://www.gtec.edu.gh/) - official tertiary regulator; use its accreditation and publications sections.
- Ghana: [Ghana government portal](https://www.ghana.gov.gh/) - official agency and service directory.
- Kenya: [Commission for University Education](https://www.che.ac.ke/) - official higher-education regulator; use its accredited institutions resources.
- South Africa: [Department of Higher Education and Training](https://www.dhet.gov.za/) - official department with university and research resources.
- Egypt: [Supreme Council of Universities](https://scu.eg/) - official higher-education council; the homepage publishes institutional categories and links.
- Tanzania: [Tanzania Commission for Universities](https://www.tcu.go.tz/) - official university regulator; use its institutional resources.

These are source portals, not automatically clean CSV datasets. For every selected organization, open its official website, confirm that the domain belongs to that organization, and record the source page in the sampling log.

| Country | Government | Universities | Financial/business | Healthcare | Telecom/technology |
|---|---|---|---|---|---|
| Nigeria | official ministry/agency directories | National Universities Commission | SEC/NGX public issuer lists | Federal Ministry of Health registries | NCC licensee lists |
| Ghana | Ghana government portal | Ghana Tertiary Education Commission | Bank of Ghana/SEC Ghana lists | Ghana Health Service | NCA licensee lists |
| Kenya | Kenya government portal | Commission for University Education | CMA/NSE issuer lists | Ministry of Health registries | Communications Authority licensee lists |
| South Africa | gov.za directory | Department of Higher Education lists | JSE/FSCA lists | National Department of Health | ICASA licensee lists |
| Egypt | Egyptian government portal | Supreme Council of Universities | FRA/EGX public issuer lists | Ministry of Health registries | NTRA licensee lists |
| Tanzania | Tanzania government portal | Tanzania Commission for Universities | CMSA/DSE issuer lists | Ministry of Health registries | TCRA licensee lists |

## Contextual datasets

These should explain differences in the environment, not be used as direct security labels:

- ITU ICT indicators
- World Bank development indicators
- Internet Society Pulse
- Cloudflare Radar
- Ookla Open Data
- AfriNIC statistics

## Current local inventory

The repository currently contains:

- Nigeria regional RIPE snapshot: 416 IPv4 prefixes, 136 IPv6 prefixes
- Target reports for `example.com`, `scanme.nmap.org`, `wfp.org`, and `fbi.gov`
- Target reports include DNS, certificate, subdomain, and InternetDB artifacts
- Nigeria's latest country certificate/DNS/subdomain files are empty because crt.sh returned an outage response during collection

The target reports are engineering fixtures and must not be presented as the African study sample. Replace the pilot manifest placeholders with organizations selected from official sources before collecting research observations.

## Acquisition rule

For every sampled organization, preserve:

```text
country
sector
organization_id
official_domain
selection_source
selection_date
authorization_status
```

For publication, release only aggregate statistics and anonymized observations. Keep raw domains and detailed target reports private unless the organization has agreed to publication.
