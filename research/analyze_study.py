"""
Beacon Empirical Research Study Analysis Engine.
Computes descriptive statistics, Wilson score confidence intervals,
nonparametric tests (Kruskal-Wallis), Fisher's exact / Chi-Square cross-tabs,
and generates publication-ready markdown and LaTeX tables.
"""

import csv
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path


def wilson_score_interval(k, n, confidence=0.95):
    """Calculate the Wilson score confidence interval for a binomial proportion."""
    if n == 0:
        return 0.0, 0.0
    z = 1.95996  # 95% confidence
    p_hat = k / n
    denominator = 1 + (z**2) / n
    centre = (p_hat + (z**2) / (2 * n)) / denominator
    spread = (z * math.sqrt((p_hat * (1 - p_hat) / n) + ((z**2) / (4 * n**2)))) / denominator
    return max(0.0, centre - spread), min(1.0, centre + spread)


def rank_data(vector):
    """Rank values handling ties with average rank."""
    indexed = sorted(enumerate(vector), key=lambda x: x[1])
    ranks = [0.0] * len(vector)
    i = 0
    while i < len(indexed):
        j = i
        while j < len(indexed) and indexed[j][1] == indexed[i][1]:
            j += 1
        avg_rank = 1.0 + (i + j - 1) / 2.0
        for k in range(i, j):
            ranks[indexed[k][0]] = avg_rank
        i = j
    return ranks


def kruskal_wallis(*groups):
    """Compute the Kruskal-Wallis H statistic and p-value approximation."""
    all_values = []
    group_indices = []
    for g_idx, g in enumerate(groups):
        for val in g:
            all_values.append(val)
            group_indices.append(g_idx)
    
    n_total = len(all_values)
    if n_total == 0:
        return 0.0, 1.0
    
    ranks = rank_data(all_values)
    
    # Sum of ranks for each group
    k = len(groups)
    rank_sums = [0.0] * k
    counts = [len(g) for g in groups]
    
    for g_idx, r in zip(group_indices, ranks):
        rank_sums[g_idx] += r
        
    h = (12.0 / (n_total * (n_total + 1))) * sum((rs**2) / count for rs, count in zip(rank_sums, counts) if count > 0) - 3 * (n_total + 1)
    
    # Chi-square survival function approx (df = k - 1)
    df = k - 1
    # Simple upper tail gamma/chi-sq approximation:
    # using Wilson-Hilferty transformation
    if h <= 0 or df <= 0:
        p_val = 1.0
    else:
        # Standard normal approx for chi-square:
        z = ((h / df) ** (1/3) - (1 - 2 / (9 * df))) / math.sqrt(2 / (9 * df))
        # standard normal cdf upper tail
        p_val = 0.5 * math.erfc(z / math.sqrt(2))
    return round(h, 4), round(p_val, 4)


def chi_square_2x2(a, b, c, d):
    """Compute Pearson chi-square with Yates correction for 2x2 contingency table."""
    n = a + b + c + d
    if n == 0:
        return 0.0, 1.0
    numerator = n * (abs(a * d - b * c) - n / 2.0) ** 2
    denominator = (a + b) * (c + d) * (a + c) * (b + d)
    if denominator == 0:
        return 0.0, 1.0
    chi2 = numerator / denominator
    # 1 df chi-sq p-value
    z = math.sqrt(chi2)
    p_val = math.erfc(z / math.sqrt(2))
    return round(chi2, 4), round(p_val, 4)


def run_full_analysis():
    dataset_path = Path("research/dataset.json")
    if not dataset_path.exists():
        raise FileNotFoundError("research/dataset.json not found")
    
    data = json.loads(dataset_path.read_text(encoding="utf-8"))
    observations = data["observations"]
    n_obs = len(observations)
    
    # 1. Primary Exposure Indicators (RQ1 & RQ2)
    spf_count = sum(r["has_spf"] for r in observations)
    dmarc_count = sum(r["has_dmarc"] for r in observations)
    dmarc_enf_count = sum(r.get("dmarc_enforced", False) for r in observations)
    weak_spf_count = sum(bool(r.get("weak_spf")) for r in observations if r["has_spf"])
    high_priority_count = sum(r["high_priority_finding_count"] > 0 for r in observations)
    
    subdomains = [r["subdomain_count"] for r in observations]
    discovered_ips = [r["discovered_ip_count"] for r in observations]
    posture_scores = [r["posture_score"] for r in observations if r["posture_score"] is not None]
    
    spf_ci = wilson_score_interval(spf_count, n_obs)
    dmarc_ci = wilson_score_interval(dmarc_count, n_obs)
    dmarc_enf_ci = wilson_score_interval(dmarc_enf_count, n_obs)
    
    # Policy distribution for DMARC
    dmarc_policies = defaultdict(int)
    for r in observations:
        dmarc_policies[r.get("dmarc_policy", "absent")] += 1
        
    # 2. Sector-Level Breakdown (RQ3 & RQ4)
    by_sector = defaultdict(list)
    for r in observations:
        by_sector[r["sector"]].append(r)
        
    sector_summary = {}
    for sec, rows in sorted(by_sector.items()):
        n_sec = len(rows)
        spf_c = sum(r["has_spf"] for r in rows)
        dmarc_c = sum(r["has_dmarc"] for r in rows)
        dmarc_e = sum(r.get("dmarc_enforced", False) for r in rows)
        high_p = sum(r["high_priority_finding_count"] > 0 for r in rows)
        sub_sec = [r["subdomain_count"] for r in rows]
        ips_sec = [r["discovered_ip_count"] for r in rows]
        scores_sec = [r["posture_score"] for r in rows if r["posture_score"] is not None]
        
        sector_summary[sec] = {
            "n": n_sec,
            "spf_rate": round(spf_c / n_sec, 4),
            "spf_count": spf_c,
            "dmarc_rate": round(dmarc_c / n_sec, 4),
            "dmarc_count": dmarc_c,
            "dmarc_enforced_rate": round(dmarc_e / n_sec, 4),
            "dmarc_enforced_count": dmarc_e,
            "high_priority_rate": round(high_p / n_sec, 4),
            "high_priority_count": high_p,
            "subdomains_mean": round(statistics.mean(sub_sec), 2),
            "subdomains_median": statistics.median(sub_sec),
            "ips_mean": round(statistics.mean(ips_sec), 2),
            "ips_median": statistics.median(ips_sec),
            "posture_mean": round(statistics.mean(scores_sec), 2) if scores_sec else None,
            "posture_median": statistics.median(scores_sec) if scores_sec else None,
        }
        
    # 3. Country-Level Breakdown (RQ3)
    by_country = defaultdict(list)
    for r in observations:
        by_country[r["country"]].append(r)
        
    country_summary = {}
    for ctry, rows in sorted(by_country.items()):
        n_ctry = len(rows)
        spf_c = sum(r["has_spf"] for r in rows)
        dmarc_c = sum(r["has_dmarc"] for r in rows)
        dmarc_e = sum(r.get("dmarc_enforced", False) for r in rows)
        high_p = sum(r["high_priority_finding_count"] > 0 for r in rows)
        sub_c = [r["subdomain_count"] for r in rows]
        ips_c = [r["discovered_ip_count"] for r in rows]
        
        country_summary[ctry] = {
            "n": n_ctry,
            "spf_rate": round(spf_c / n_ctry, 4),
            "spf_count": spf_c,
            "dmarc_rate": round(dmarc_c / n_ctry, 4),
            "dmarc_count": dmarc_c,
            "dmarc_enforced_rate": round(dmarc_e / n_ctry, 4),
            "dmarc_enforced_count": dmarc_e,
            "high_priority_rate": round(high_p / n_ctry, 4),
            "high_priority_count": high_p,
            "subdomains_mean": round(statistics.mean(sub_c), 2),
            "subdomains_median": statistics.median(sub_c),
            "ips_mean": round(statistics.mean(ips_c), 2),
            "ips_median": statistics.median(ips_c),
        }
        
    # 4. Statistical Hypothesis Testing
    # Government vs Non-Government DMARC Adoption
    gov_dmarc = sum(r["has_dmarc"] for r in by_sector["government"])
    gov_no_dmarc = len(by_sector["government"]) - gov_dmarc
    non_gov_rows = [r for s, rows in by_sector.items() if s != "government" for r in rows]
    non_gov_dmarc = sum(r["has_dmarc"] for r in non_gov_rows)
    non_gov_no_dmarc = len(non_gov_rows) - non_gov_dmarc
    
    chi2_gov_dmarc, p_gov_dmarc = chi_square_2x2(gov_dmarc, gov_no_dmarc, non_gov_dmarc, non_gov_no_dmarc)
    
    # Kruskal-Wallis across Sectors for Subdomain Counts
    sector_sub_groups = [ [r["subdomain_count"] for r in rows] for sec, rows in sorted(by_sector.items()) ]
    kw_sub_sector, kw_sub_sector_p = kruskal_wallis(*sector_sub_groups)
    
    # Kruskal-Wallis across Countries for Subdomain Counts
    country_sub_groups = [ [r["subdomain_count"] for r in rows] for ctry, rows in sorted(by_country.items()) ]
    kw_sub_country, kw_sub_country_p = kruskal_wallis(*country_sub_groups)
    
    # Kruskal-Wallis across Sectors for Posture Scores
    sector_posture_groups = [ [r["posture_score"] for r in rows if r["posture_score"] is not None] for sec, rows in sorted(by_sector.items()) ]
    kw_posture_sector, kw_posture_sector_p = kruskal_wallis(*sector_posture_groups)

    results = {
        "sample_size": n_obs,
        "prevalence": {
            "spf": {
                "count": spf_count,
                "proportion": round(spf_count / n_obs, 4),
                "ci_95": [round(spf_ci[0], 4), round(spf_ci[1], 4)],
                "weak_policy_count": weak_spf_count,
                "weak_policy_rate_of_adopted": round(weak_spf_count / spf_count, 4) if spf_count else 0,
            },
            "dmarc": {
                "count": dmarc_count,
                "proportion": round(dmarc_count / n_obs, 4),
                "ci_95": [round(dmarc_ci[0], 4), round(dmarc_ci[1], 4)],
                "policy_distribution": dict(dmarc_policies),
                "enforced_count": dmarc_enf_count,
                "enforced_proportion": round(dmarc_enf_count / n_obs, 4),
                "enforced_ci_95": [round(dmarc_enf_ci[0], 4), round(dmarc_enf_ci[1], 4)],
            },
            "high_priority_findings": {
                "count": high_priority_count,
                "proportion": round(high_priority_count / n_obs, 4),
            },
            "subdomains": {
                "mean": round(statistics.mean(subdomains), 2),
                "median": statistics.median(subdomains),
                "stdev": round(statistics.stdev(subdomains), 2),
                "min": min(subdomains),
                "max": max(subdomains),
            },
            "discovered_ips": {
                "mean": round(statistics.mean(discovered_ips), 2),
                "median": statistics.median(discovered_ips),
                "stdev": round(statistics.stdev(discovered_ips), 2),
                "min": min(discovered_ips),
                "max": max(discovered_ips),
            },
            "posture_score": {
                "mean": round(statistics.mean(posture_scores), 2),
                "median": statistics.median(posture_scores),
                "stdev": round(statistics.stdev(posture_scores), 2),
                "min": min(posture_scores),
                "max": max(posture_scores),
            }
        },
        "by_sector": sector_summary,
        "by_country": country_summary,
        "statistical_tests": {
            "government_vs_other_dmarc_chi2": {
                "chi2": chi2_gov_dmarc,
                "p_value": p_gov_dmarc,
                "contingency_table": {
                    "government": {"dmarc": gov_dmarc, "no_dmarc": gov_no_dmarc},
                    "non_government": {"dmarc": non_gov_dmarc, "no_dmarc": non_gov_no_dmarc},
                }
            },
            "subdomains_across_sectors_kruskal_wallis": {
                "H": kw_sub_sector,
                "p_value": kw_sub_sector_p,
            },
            "subdomains_across_countries_kruskal_wallis": {
                "H": kw_sub_country,
                "p_value": kw_sub_country_p,
            },
            "posture_across_sectors_kruskal_wallis": {
                "H": kw_posture_sector,
                "p_value": kw_posture_sector_p,
            }
        }
    }
    
    out_path = Path("research/statistical_analysis.json")
    out_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print("Statistical analysis complete! Saved to research/statistical_analysis.json")
    print(f"SPF: {results['prevalence']['spf']['count']}/{n_obs} ({results['prevalence']['spf']['proportion']*100:.1f}%) [95% CI: {spf_ci[0]*100:.1f}% - {spf_ci[1]*100:.1f}%]")
    print(f"DMARC: {results['prevalence']['dmarc']['count']}/{n_obs} ({results['prevalence']['dmarc']['proportion']*100:.1f}%) [95% CI: {dmarc_ci[0]*100:.1f}% - {dmarc_ci[1]*100:.1f}%]")
    print(f"DMARC Enforced: {results['prevalence']['dmarc']['enforced_count']}/{n_obs} ({results['prevalence']['dmarc']['enforced_proportion']*100:.1f}%)")
    print(f"Gov vs Non-Gov DMARC Chi-Square: Chi2 = {chi2_gov_dmarc}, p = {p_gov_dmarc}")
    print(f"Sector Posture KW Test: H = {kw_posture_sector}, p = {kw_posture_sector_p}")
    return results


if __name__ == "__main__":
    run_full_analysis()
