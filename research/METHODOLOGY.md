# Beacon Africa-First Study

## Research objective

Measure observable Internet exposure among organizations in selected African countries using reproducible, passive public-data collection.

Beacon is the measurement framework. Africa is the bounded study population, not a technical limitation of the framework.

## Pilot design

The pilot uses six countries: Nigeria, Ghana, Kenya, South Africa, Egypt, and Tanzania. It samples one organization per country in each of five sectors: government, universities, business, healthcare, and telecom-tech. The pilot therefore contains 30 organizations.

The full study can expand to a fixed number per stratum after the pilot validates the collection and normalization process. Organization selection must be documented before collection using these criteria:

- The organization is publicly identifiable and has an official domain.
- The domain can be attributed to the organization from an official source.
- The organization belongs to exactly one declared study sector.
- The selected domain is in scope for passive public observation.
- The selection date and source are recorded in the manifest.

Do not replace unavailable organizations after seeing their results without recording the replacement and reason. This protects against outcome-driven sampling.

## Measurement pipeline

`official domain -> certificate names -> DNS records -> common subdomains -> resolved IPs -> InternetDB metadata -> anonymized dataset`

Beacon does not authenticate, exploit, brute-force credentials, send packets to services, or attempt access. DNS and certificate collection are public observations. InternetDB is enrichment of already discovered public IPs.

## Variables

Each dataset row contains:
- Stratum indicators: `country`, `sector`, `organization_id`
- Pseudonymized ID: `domain_hash` (salted truncated SHA-256)
- Metadata: `collection_date`
- Certificate measurements: `certificate_domain_count`, `certificate_data_available`
- Namespace visibility: `dns_domain_count`, `subdomain_count`, `total_observed_hostnames`
- Sample coverage: `observed_asset_coverage` ($D_i / T_i$, computed only when `certificate_data_available` is true, otherwise `null`)
- Infrastructure & addressing: `ipv4_count`, `ipv6_count`, `discovered_ip_count`, `internetdb_record_count`, `mx_count`, `ns_count`
- Email security controls: `has_spf`, `weak_spf`, `has_dmarc`, `dmarc_policy` (`reject`, `quarantine`, `none`, `absent`), `dmarc_enforced` (boolean)
- Security indicators & posture: `finding_count`, `high_priority_finding_count`, `posture_score`

Raw target reports remain local and should not be published with the study dataset. The hash is an identifier for longitudinal comparison, not proof of anonymity against an outside party with auxiliary information.

## Analysis plan

Primary questions:

1. Which observable exposure indicators are most prevalent?
2. How prevalent are SPF and DMARC configurations, and what proportion enforce active rejection/quarantine?
3. How do indicators vary across countries and sectors?
4. Is sector associated with exposure after accounting for country?
5. How stable are measurements across repeated collection dates?

Use descriptive statistics first. Report sample counts, medians, IQRs, means, proportions, and Wilson score 95% confidence intervals. Use Kruskal-Wallis for skewed count comparisons and chi-square / Fisher's exact tests for categorical proportions. Treat p-values as supporting evidence alongside effect sizes and confidence intervals.

## Validation and Upstream Data Source Rigor

1. **Independent DNS Multi-Resolver Validation:** Independently repeat DNS measurements across distinct recursive resolvers (Google DNS, Cloudflare, Quad9) for record-presence agreement ($A$) and Jaccard set overlap ($J$).
2. **Upstream CT API Degradation Handling:** When Certificate Transparency queries (e.g. crt.sh) encounter upstream timeouts or rate limits and return single-name fallbacks, flag `certificate_data_available = False` and record coverage as `null` rather than a misleading `1.0`.

## Ethics and limitations

The study reports visibility, not compromise or vulnerability. CDN ownership, shared hosting, wildcard DNS, stale certificates, domain aliases, and multinational infrastructure can make attribution difficult. Country and sector comparisons describe this sample and must not be generalized to all African organizations without qualification.

For research-only passive observations, publish only aggregated results and remove direct identifiers. Ensure private remediation drafts are available for critical configuration issues without public disclosure.
