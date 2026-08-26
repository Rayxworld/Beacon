# Beacon: Measuring Observable Internet Exposure Across African Organizations Using Publicly Available Internet Data

**Working Manuscript**  
**Version:** 1.0 (Empirical Pilot Evaluation)  
**Date:** 26 August 2026  
**Status:** Pilot execution complete ($N=30$ organizations across 6 nations and 5 sectors); empirical analysis and multi-resolver validation completed.

## Abstract

Organizations expose digital infrastructure through ordinary Internet operations before any active security assessment begins. Public Certificate Transparency (CT) logs, Domain Name System (DNS) configurations, resolvable hostnames, and historically observed IP-service metadata provide an external perspective on organizational exposure without authentication or intrusive probing. This paper presents **Beacon**, an open-source, reproducible passive measurement framework designed for rigorous attack-surface intelligence, and evaluates it on an Africa-first stratified sampling frame.

The pilot study investigates 30 critical organizations across six African economies (Nigeria, Ghana, Kenya, South Africa, Egypt, and Tanzania) spanning five foundational sectors: Government, Higher Education, Financial/Business, Healthcare, and Telecommunications/Technology. Beacon collects certificate-associated names, DNS security records (SPF, DMARC, MX, NS), active common subdomain resolutions, and IP metadata from Shodan InternetDB, while generating anonymized research datasets.

Our empirical findings reveal substantial baseline security protocol adoption alongside acute sectoral vulnerabilities:
1. **Email Authentication Prevalence:** Overall SPF adoption reached 86.7% ($n=26/30$, 95% CI: [70.3%, 94.7%]), though 53.8% ($n=14/26$) of adopting domains employed weak softfail mechanisms (`~all` or `?all`). DMARC adoption reached 73.3% ($n=22/30$, 95% CI: [55.6%, 85.8%]), with 60.0% ($n=18/30$, 95% CI: [42.3%, 75.4%]) enforcing active policy protection (`p=reject` or `p=quarantine`).
2. **Critical Sector Disparity:** A pronounced and statistically significant divergence emerged in the Government sector, where **0.0%** of sampled government domains published DMARC records ($n=0/6$), compared to 91.7% ($n=22/24$) across non-governmental sectors ($\chi^2 = 16.20, p < 0.0001$). Consequently, 100% of sampled government portals triggered high-priority security findings for email spoofing vulnerability. In contrast, 100% of financial/business and university domains published DMARC records, with financial institutions achieving 100% strict enforcement (`p=reject` or `p=quarantine`).
3. **Attack Surface Visibility & Measurement Challenges:** Subdomain brute-forcing revealed an average of 13.27 resolvable hostnames per organization (range: 1–70) and 10.27 discovered public IP addresses (range: 1–51). Crucially, we document upstream Certificate Transparency API degradation (where crt.sh rate-limiting and timeouts caused fallback to root domains in 96.7% of targets), demonstrating why passive measurement frameworks must explicitly differentiate upstream source availability from true organizational asset coverage.

**Keywords:** passive network measurement, Internet exposure, DNS security, Certificate Transparency, DMARC, SPF, African digital infrastructure, reproducibility, attack surface intelligence

---

## 1. Introduction

Internet-facing infrastructure is observable through public routing, naming, and cryptographic logging systems without authentication, exploitation, or intrusive scanning. Organizations routinely publish DNS records to route traffic and authenticate mail, obtain TLS certificates recorded in append-only Certificate Transparency (CT) logs, and operate services indexed by internet-wide observational platforms. While these telemetry sources provide valuable attack-surface visibility for defensive operators, empirical measurement in academic literature has frequently suffered from methodological shortcomings—including conflating passive visibility with security compromise, failing to document upstream data source limitations, and neglecting emerging Internet regions.

This work introduces **Beacon** as both a lightweight, dependency-minimal software framework and a formalized research instrument. Beacon applies a standardized, non-intrusive collection pipeline to organization domains, structures findings with explainable deduction rules, and outputs anonymized, reproducible datasets. To demonstrate the framework's utility, we conduct an Africa-first empirical pilot evaluation across six African nations: Nigeria, Ghana, Kenya, South Africa, Egypt, and Tanzania.

The contributions of this paper are fourfold:
1. **Reproducible Passive Pipeline:** We specify and release an open-source measurement architecture that combines public DNS resolvers, CT logs, wordlist-based subdomain resolution, and passive IP enrichment (Shodan InternetDB) without conducting active vulnerability scans or port scans.
2. **Empirical African Pilot Findings:** We provide the first multi-national, cross-sector empirical measurement of email authentication (SPF/DMARC) and public asset exposure across 30 major African institutions.
3. **Methodological Rigor on Upstream API Failure:** We identify and address critical measurement artifacts in public CT data sources (specifically crt.sh query timeouts and rate-limits), demonstrating how failure to flag upstream source unavailability leads to severe coverage miscalculations.
4. **Responsible Disclosure and Ethical Protocol:** We articulate an operational model that bridges academic measurement and responsible remediation without exposing raw identifying vulnerability data publicly.

---

## 2. Research Questions

This study evaluates five specific research questions:

- **RQ1 (Exposure Indicator Prevalence):** Which observable exposure indicators (subdomains, public IPs, external service observations) are most prevalent across sampled African organizations?
- **RQ2 (Email Security Baseline):** What proportion of sampled domains publish SPF and DMARC signals, and what fraction actively enforce spoofing prevention (`p=reject` or `p=quarantine`) versus passive monitoring (`p=none`)?
- **RQ3 (Sectoral and Geographic Variation):** How do observable exposure indicators and security configurations vary across the selected countries and sectors?
- **RQ4 (Sectoral Disparity Analysis):** Is organizational sector significantly associated with email security adoption and overall posture after accounting for geographic distribution?
- **RQ5 (Measurement Reliability & Upstream Stability):** How consistent are passive DNS measurements across independent public resolvers, and how do upstream API constraints affect measurement integrity?

---

## 3. Scope and Ethical Framework

### 3.1 Definition of Observable Exposure
We define **observable Internet exposure** strictly as information retrievable through benign public queries to authoritative or public recursive DNS resolvers, public Certificate Transparency repositories, and pre-indexed public databases (such as Shodan InternetDB) without authentication, vulnerability exploitation, payload injection, or port scanning.

An observed indicator is **not** inherently a vulnerability. For example:
- A resolvable hostname such as `vpn.target.org` or `test.target.org` demonstrates external namespace presence and requires administrative verification, but does not indicate that the underlying service is compromised or misconfigured.
- An InternetDB port record indicates that a third-party observational scanner previously indexed an open port at that IP address; it does not constitute current proof of accessibility or exploitability.

### 3.2 Ethical Boundary and Responsible Disclosure
Beacon strictly adheres to passive observation principles:
- **No Active Probing:** Beacon sends no TCP SYN packets, HTTP requests, or credential attempts to target hostnames or IP addresses.
- **Privacy and Anonymization:** Raw target domains and identifiable entity names are restricted to local operational logs. All published research datasets utilize a salted SHA-256 pseudonymized hash (`domain_hash`).
- **Private Remediation:** For critical exposures, Beacon provides private, formatted disclosure draft artifacts for verified administrative contacts, preventing public exposure of unpatched configurations.

---

## 4. Study Design and Methodology

### 4.1 Sampling Frame and Stratification
The study population comprises six economically and technologically prominent African countries representing Western, Eastern, Southern, and Northern Africa:
1. **Nigeria (NG)** — West Africa
2. **Ghana (GH)** — West Africa
3. **Kenya (KE)** — East Africa
4. **South Africa (ZA)** — Southern Africa
5. **Egypt (EG)** — North Africa
6. **Tanzania (TZ)** — East Africa

Within each country, the sampling frame is stratified across five critical societal and economic sectors:
1. **Government (`government`):** Official national and ministerial web portals.
2. **Higher Education (`universities`):** Leading national universities and accredited tertiary institutions.
3. **Financial / Business (`business`):** Major commercial banks and publicly listed financial institutions.
4. **Healthcare (`healthcare`):** National health authorities, referral hospital networks, and health insurance regulators.
5. **Telecommunications / Technology (`telecom-tech`):** Major licensed national telecommunications operators and digital service providers.

The resulting pilot sample consists of $N = 30$ organizations ($6 \times 5$ balanced matrix), as specified in `research/pilot_manifest.csv`. Organizations were identified through official regulatory directories (such as national university commissions, central banks, and telecommunications regulatory authorities).

### 4.2 Collection Pipeline

```
[Official Domain]
       │
       ├─► 1. Certificate Transparency Discovery (crt.sh)
       │         └── Extracts historical Subject Alternative Names (SANs)
       │
       ├─► 2. Public DNS Security & Infrastructure Collection
       │         └── Queries A, AAAA, MX, NS, TXT, CNAME, DMARC records
       │
       ├─► 3. Common Subdomain Enumeration
       │         └── Probes high-frequency wordlist (admin, mail, vpn, dev, etc.)
       │
       ├─► 4. Discovered IP Address Aggregation
       │         └── Resolves unique IPv4/IPv6 addresses across DNS and subdomains
       │
       ├─► 5. Passive IP Enrichment (Shodan InternetDB)
       │         └── Queries passive open-port and CVE metadata for discovered IPs
       │
       └─► 6. Findings & Anonymization Engine
                 └── Evaluates explainable heuristics and generates research dataset
```

---

## 5. Measures and Operational Definitions

Each observation record in `research/dataset.json` contains the following formalized measures:

| Variable | Type | Operational Definition |
|---|---|---|
| `country` | Nominal | Country stratum (`nigeria`, `ghana`, `kenya`, `south-africa`, `egypt`, `tanzania`) |
| `sector` | Nominal | Sector stratum (`government`, `universities`, `business`, `healthcare`, `telecom-tech`) |
| `organization_id` | String | Stratum-specific identifier (e.g., `NG-GOV-001`, `ZA-BUS-001`) |
| `domain_hash` | String | Truncated 16-hex-character SHA-256 hash using a study-local salt |
| `certificate_domain_count` | Integer | Count of unique FQDNs returned by Certificate Transparency |
| `certificate_data_available` | Boolean | `True` if CT returned active multi-name SANs; `False` if CT timed out/fell back |
| `dns_domain_count` | Integer | Count of unique hostnames queried during DNS collection |
| `observed_asset_coverage` | Float/Null | Ratio of DNS-checked names to CT names ($D_i / T_i$) when CT data is available; `null` otherwise |
| `subdomain_count` | Integer | Count of successfully resolved hostnames from the common wordlist |
| `total_observed_hostnames` | Integer | Total observable namespace surface ($D_i + \text{subdomain\_count}$) |
| `discovered_ip_count` | Integer | Count of unique public IPv4 and IPv6 addresses resolved |
| `has_spf` | Boolean | `True` if root domain publishes a valid `v=spf1` TXT record |
| `weak_spf` | Boolean/Null | `True` if SPF uses softfail (`~all`) or neutral (`?all`); `False` if strict hardfail (`-all`) |
| `has_dmarc` | Boolean | `True` if `_dmarc.{domain}` publishes a valid `v=DMARC1` TXT record |
| `dmarc_policy` | Categorical | Policy attribute: `reject`, `quarantine`, `none`, or `absent` |
| `dmarc_enforced` | Boolean | `True` if `dmarc_policy` is `reject` or `quarantine`; `False` if `none` or `absent` |
| `finding_count` | Integer | Count of explainable findings generated by Beacon rules |
| `high_priority_finding_count` | Integer | Count of findings classified with `high` or `critical` severity |
| `posture_score` | Integer | Composite hygiene score (0–100) based on severity deductions |

---

## 6. Methodological Analysis of Upstream Data Sources

A pivotal finding of our study pertains to upstream API behavior in passive security measurement:

### 6.1 Certificate Transparency Upstream Degradation
When querying `crt.sh` via `q=%.{domain}`, public research requests frequently encounter HTTP 504 Gateway Timeouts, 502 Bad Gateway responses, or HTTP 429 rate limits due to high upstream database loads. When an automated pipeline catches these exceptions and returns the requested root domain as a baseline fallback, naive counting produces `certificate_domain_count = 1`.

Interpreting `certificate_domain_count = 1` as "the organization only owns one certificate name" introduces severe measurement bias. In our pilot:
- 29 of 30 targets returned `certificate_domain_count = 1` due to upstream query timeouts.
- Exactly 1 target (`kenya.go.ke`) completed a full CT query, returning 14 certificate-associated hostnames.

**Methodological Resolution:** Beacon incorporates an explicit `certificate_data_available` boolean. When CT discovery falls back to the root domain, `observed_asset_coverage` is assigned `null` rather than a spurious `1.0` (100% coverage). This separation ensures that upstream data availability is never conflated with organizational exposure posture.

---

## 7. Multi-Resolver Validation and Empirical Agreement

To evaluate measurement consistency and account for potential resolver caching or transport anomalies, we executed independent DNS presence checks across public resolvers (Google DNS `8.8.8.8`, Cloudflare `1.1.1.1`, and Quad9 `9.9.9.9`) across all 258 record sets (A, AAAA, MX, NS, TXT, CNAME).

Empirical agreement was evaluated using exact presence agreement ($A$) and Jaccard set similarity ($J$):

$$
A = \frac{\sum_{i=1}^{M} \mathbb{I}(\text{Expected}_i \iff \text{Observed}_i)}{M}, \quad J(X, Y) = \frac{|X \cap Y|}{|X \cup Y|}
$$

### Validation Insights:
- In environments where standard UDP port 53 traffic is filtered or subjected to middlebox packet loss by regional ISPs, recursive resolvers may experience transient transport timeouts.
- When querying authoritative nameservers, Google DNS (`8.8.8.8`) exhibited consistent resolution for active records, with perfect record-set fidelity ($J = 1.0$) for all responsive endpoints.
- The validation protocol demonstrates that multi-vantage point DNS queries are required in distributed Internet measurements to separate network transport artifacts from actual DNS misconfigurations.

---

## 8. Empirical Results

The Africa pilot completed collection for all $N = 30$ organizations across the six countries and five sectors with **zero missing reports** ($100\%$ sample completion).

### 8.1 Overall Exposure Indicator Prevalence (RQ1 & RQ2)

Table 1 summarizes the primary exposure indicators across the full sample ($N = 30$).

**Table 1: Overall Exposure & Email Security Prevalence ($N = 30$)**

| Metric | Count ($k$) | Proportion ($\hat{p}$) | 95% Confidence Interval (Wilson) |
|---|---|---|---|
| **SPF Adoption (`has_spf`)** | 26 | 86.7% | [70.3%, 94.7%] |
| — Strict Policy (`-all`) | 12 | 40.0% | [24.6%, 57.7%] |
| — Weak Policy (`~all` / `?all`) | 14 | 46.7% | [30.2%, 63.9%] |
| **DMARC Adoption (`has_dmarc`)** | 22 | 73.3% | [55.6%, 85.8%] |
| — Policy: `reject` | 12 | 40.0% | [24.6%, 57.7%] |
| — Policy: `quarantine` | 6 | 20.0% | [9.5%, 37.3%] |
| — Policy: `none` (Monitoring only) | 4 | 13.3% | [5.3%, 29.7%] |
| — Policy: `absent` (No record) | 8 | 26.7% | [14.2%, 44.4%] |
| **DMARC Enforced (`reject` or `quarantine`)** | 18 | 60.0% | [42.3%, 75.4%] |
| **High-Priority Findings Triggered** | 8 | 26.7% | [14.2%, 44.4%] |
| **Metric** | **Mean ($\pm$ SD)** | **Median [IQR]** | **Observed Range** |
| Resolved Subdomains | $13.27 \pm 15.34$ | 12.00 [5.25, 15.00] | 1 – 70 |
| Discovered Public IPs | $10.27 \pm 9.42$ | 9.50 [5.00, 12.75] | 1 – 51 |
| Composite Posture Score | $79.57 \pm 14.88$ | 84.00 [72.25, 92.00] | 44 – 100 |

```
Email Security Policy Breakdown (N=30)
=======================================
SPF Present (Strict -all):    [████████████░░░░░░░░░░░░░░░░░░] 40.0% (12/30)
SPF Present (Weak ~all/?all): [██████████████░░░░░░░░░░░░░░░░] 46.7% (14/30)
SPF Absent:                   [████░░░░░░░░░░░░░░░░░░░░░░░░░░] 13.3% (4/30)

DMARC p=reject (Strict):      [████████████░░░░░░░░░░░░░░░░░░] 40.0% (12/30)
DMARC p=quarantine (Moderate):[██████░░░░░░░░░░░░░░░░░░░░░░░░] 20.0% (6/30)
DMARC p=none (Monitoring):    [████░░░░░░░░░░░░░░░░░░░░░░░░░░] 13.3% (4/30)
DMARC Absent:                 [████████░░░░░░░░░░░░░░░░░░░░░░] 26.7% (8/30)
```

---

### 8.2 Cross-Sector Comparative Analysis (RQ3 & RQ4)

A central finding of this study is the substantial disparity in email security hygiene and attack surface exposure across economic sectors. Table 2 details the sectoral distribution.

**Table 2: Comparative Exposure and Security Posture Across Sectors ($n=6$ per sector)**

| Sector | SPF Rate | DMARC Rate | DMARC Enforced | Mean Subdomains | Mean IPs | High Priority % | Mean Posture |
|---|---|---|---|---|---|---|---|
| **Business / Banking** | **100.0%** (6/6) | **100.0%** (6/6) | **100.0%** (6/6) | 11.50 | 10.50 | **0.0%** (0/6) | **90.00** |
| **Universities** | **100.0%** (6/6) | **100.0%** (6/6) | 50.0% (3/6) | 14.00 | 13.83 | **0.0%** (0/6) | 88.33 |
| **Telecom / Tech** | 83.3% (5/6) | 83.3% (5/6) | 83.3% (5/6) | 9.67 | 9.50 | 16.7% (1/6) | 82.50 |
| **Healthcare** | 83.3% (5/6) | 83.3% (5/6) | 66.7% (4/6) | **19.33** | 5.67 | 16.7% (1/6) | 78.00 |
| **Government** | 66.7% (4/6) | **0.0%** (0/6) | **0.0%** (0/6) | 11.83 | 11.83 | **100.0%** (6/6) | **59.00** |

```
DMARC Enforcement by Sector (n=6 per sector)
=============================================
Business:      [████████████████████████████████████████] 100.0% (6/6)
Telecom/Tech:  [█████████████████████████████████░░░░░░░]  83.3% (5/6)
Healthcare:    [███████████████████████████░░░░░░░░░░░░░]  66.7% (4/6)
Universities:  [████████████████████░░░░░░░░░░░░░░░░░░░░]  50.0% (3/6)
Government:    [░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░]   0.0% (0/6)
```

#### Statistical Significance of the Government Security Deficit
A $2 \times 2$ contingency test comparing Government domains against all Non-Government domains for DMARC adoption yields:

$$
\text{Contingency Table:} \quad
\begin{pmatrix}
\text{Government} & 0 & 6 \\
\text{Non-Government} & 22 & 2
\end{pmatrix}
$$

- **Pearson Chi-Square with Yates Correction:** $\chi^2 = 16.2038, p = 0.000057$ ($p < 0.0001$).
- **Odds Ratio:** $\text{OR} = 0.000$ (Fisher's exact $p < 0.0001$).

This confirms a statistically significant systemic deficit: sampled national government portals in Africa systematically lag behind private enterprise and academia in adopting spoofing defenses.

---

### 8.3 Geographic Distribution (RQ3)

Table 3 summarizes the observations stratified across the six participating countries ($n=5$ organizations per country).

**Table 3: Country-Level Distribution ($n=5$ per country)**

| Country | SPF Rate | DMARC Rate | DMARC Enforced | Mean Subdomains | Mean IPs | High Priority % |
|---|---|---|---|---|---|---|
| **Nigeria (NG)** | 100.0% (5/5) | 80.0% (4/5) | 60.0% (3/5) | 9.00 | 6.80 | 20.0% (1/5) |
| **South Africa (ZA)** | 100.0% (5/5) | 80.0% (4/5) | 80.0% (4/5) | 11.20 | 11.00 | 20.0% (1/5) |
| **Kenya (KE)** | 100.0% (5/5) | 80.0% (4/5) | 40.0% (2/5) | 11.80 | 10.00 | 20.0% (1/5) |
| **Tanzania (TZ)** | 80.0% (4/5) | 80.0% (4/5) | 80.0% (4/5) | 9.20 | 9.60 | 20.0% (1/5) |
| **Egypt (EG)** | 80.0% (4/5) | 80.0% (4/5) | 80.0% (4/5) | 5.60 | 5.60 | 20.0% (1/5) |
| **Ghana (GH)** | 60.0% (3/5) | 40.0% (2/5) | 20.0% (1/5) | 32.80 | 18.60 | 60.0% (3/5) |

Nonparametric testing across geographic strata confirms that observable attack surface size does not exhibit statistically significant divergence between countries:
- Kruskal-Wallis across Countries for Subdomain Counts: $H = 2.454, p = 0.653$ (no significant country effect).
- Kruskal-Wallis across Sectors for Posture Scores: $H = 8.786, p = 0.066$ (marginal sectoral effect driven by government vs business).

---

## 9. Discussion

### 9.1 The Email Authentication Adoption vs. Enforcement Gap
While headline SPF adoption is high ($86.7\%$), over half of adopting domains ($53.8\%$) employ softfail mechanisms (`~all` or `?all`). In modern mail processing, softfail instructs receiving mail transfer agents (MTAs) to accept non-conforming messages and merely apply spam scoring increments. Without strict DMARC alignment, attackers can easily forge sender addresses.

Furthermore, among the 22 domains publishing DMARC records, 4 domains (18.2% of adopters) remain in monitoring mode (`p=none`). While `p=none` is the recommended initial deployment stage for telemetry collection, organizations frequently abandon DMARC implementations at this stage, leaving domains vulnerable to direct identity spoofing.

### 9.2 The Government Exposure Paradox
Our empirical finding that 0.0% of sampled government portals enforce DMARC (compared to 100% of commercial banks) underscores a critical public-sector cyber hygiene challenge. Government domains (`.gov.ng`, `.gov.gh`, `.go.ke`, `.gov.za`, `.gov.eg`, `.go.tz`) are prime targets for state-sponsored phishing, tax scams, and executive impersonation. Implementing `p=quarantine` and `p=reject` policies on apex government domains represents an immediate, cost-effective defense with substantial societal impact.

### 9.3 Cloudflare and CDN Intermediation
In several cases (such as `nigeria.gov.ng` and `kcbgroup.com`), DNS records resolve to Cloudflare CDN anycast IP ranges (`104.21.x.x`, `172.67.x.x`). While CDN intermediation provides DDoS mitigation and web application firewalling, it can mask origin mail infrastructure and DNS complexity. Researchers must recognize that public IP counts in CDN-fronted domains reflect edge POP distributions rather than single hosting servers.

---

## 10. Threats to Validity and Limitations

1. **Pilot Sample Size:** The stratified sample of 30 organizations is designed to validate methodology and establish initial baseline metrics; while balanced across 6 nations and 5 sectors, it should not be extrapolated as a census of all African web assets.
2. **Third-Party Upstream Reliance:** As demonstrated in Section 6, public CT sources like crt.sh are subject to load-induced rate limits. Large-scale longitudinal studies must incorporate private CT mirrors or alternate logs (e.g., Google Argon/Oak).
3. **Wordlist Scope in Subdomain Discovery:** Wordlist-based resolution is bounded by dictionary size. Domain-specific naming conventions may remain unobserved without active recursive brute-forcing or reverse DNS crawling.

---

## 11. Conclusion and Future Work

Beacon provides an open-source, reproducible, and ethically bounded framework for measuring observable organizational Internet exposure. The Africa pilot evaluation demonstrates that while core commercial and academic sectors have achieved high rates of email authentication adoption, severe structural vulnerabilities persist in public-sector apex domains.

Future extensions of Beacon will scale the sample size across 54 African economies, incorporate DNS-over-HTTPS (DoH) multi-vantage point collectors to eliminate local network transport filtering, and deploy automated longitudinal change tracking.

---

## Reproducibility Artifacts

All dataset files, manifest specifications, and analysis scripts are released for independent replication:
- Dataset (JSON): `research/dataset.json`
- Dataset (CSV): `research/dataset.csv`
- Statistical Analysis Engine: `research/analyze_study.py`
- Statistical Results (JSON): `research/statistical_analysis.json`
- Multi-Resolver Validation Engine: `research/validate_dns.py`
- Validation Output: `research/validation_results.json`
- Sampling Manifest: `research/pilot_manifest.csv`
- Methodology Specification: `research/METHODOLOGY.md`
- Data Source Registry: `research/DATA_SOURCES.md`

