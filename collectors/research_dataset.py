"""
Build an anonymized, reproducible research dataset from Beacon observation reports.
Separates Organization metadata, Collection metadata, Measurement observations,
Source provenance, and Derived analytical variables.
"""

import csv
import hashlib
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from collectors.domain_utils import normalize_domain
from collectors.dns_security_collector import parse_spf, parse_dmarc

REQUIRED_COLUMNS = ("country", "sector", "organization_id", "domain")


def read_manifest(path):
    """Read and validate the frozen organization sampling frame."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Manifest file not found: {path}")
    with path.open(newline="", encoding="utf-8-sig") as stream:
        rows = list(csv.DictReader(stream))
    if not rows:
        raise ValueError("Manifest is empty")
    missing = set(REQUIRED_COLUMNS) - set(rows[0])
    if missing:
        raise ValueError(f"Manifest is missing columns: {', '.join(sorted(missing))}")
    for row in rows:
        if not all(row.get(column, "").strip() for column in REQUIRED_COLUMNS):
            raise ValueError("Every manifest row requires country, sector, organization_id, and domain")
    return rows


def domain_hash(domain, salt="beacon-study"):
    """Create a stable non-reversible identifier within one study."""
    normalized = normalize_domain(domain)
    return hashlib.sha256(f"{salt}:{normalized}".encode("utf-8")).hexdigest()[:16]


def _load_report(target_root, domain):
    path = Path(target_root) / domain / "report.json"
    try:
        with path.open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError):
        return None


def _load_dns(target_root, domain):
    path = Path(target_root) / domain / "dns.json"
    try:
        with path.open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError):
        return []


def _measure(row, report, salt, collection_date, dns_data=None):
    """
    Extract measurement variables separated into:
    A. Organization Metadata
    B. Collection Metadata
    C. Source Provenance
    D. Measurement Observations
    E. Derived Analytical Variables
    """
    metrics = report.get("metrics", {})
    provenance = report.get("provenance", {})
    findings = report.get("findings", [])
    domain = normalize_domain(row["domain"])

    # CT Provenance & Measures
    crt_prov = provenance.get("certificate_transparency", {})
    cert_count = metrics.get("certificate_domains", crt_prov.get("certificate_result_count", 0))
    cert_status = crt_prov.get("certificate_query_status", "success" if cert_count > 1 else "fallback")
    cert_available = crt_prov.get("certificate_source_available", cert_count > 1 or cert_status == "success")
    cert_fallback = crt_prov.get("fallback_used", not cert_available)

    # DNS Measures & Security Parsing
    root_dns = next((item for item in (dns_data or []) if item.get("domain") == domain), (dns_data or [None])[0])
    sec = root_dns.get("security", {}) if root_dns else {}
    records = root_dns.get("records", {}) if root_dns else {}

    # Parse SPF if not already pre-parsed
    if "spf_policy" in sec:
        has_spf = sec.get("has_spf", False)
        spf_status = sec.get("spf_status", "valid" if has_spf else "absent")
        spf_policy = sec.get("spf_policy", "absent")
        weak_spf = sec.get("weak_spf") if has_spf else None
    else:
        spf_parsed = parse_spf(records.get("TXT", []), "NOERROR")
        has_spf = spf_parsed["has_spf"]
        spf_status = spf_parsed["spf_status"]
        spf_policy = spf_parsed["spf_policy"]
        weak_spf = spf_parsed["weak_spf"]

    # Parse DMARC if not already pre-parsed
    if "dmarc_policy" in sec:
        has_dmarc = sec.get("has_dmarc", False)
        dmarc_status = sec.get("dmarc_status", "valid" if has_dmarc else "absent")
        dmarc_policy = sec.get("dmarc_policy", "absent")
        dmarc_enforced = sec.get("dmarc_enforced", dmarc_policy in ("quarantine", "reject"))
    else:
        dmarc_parsed = parse_dmarc(records.get("DMARC", []), "NOERROR")
        has_dmarc = dmarc_parsed["has_dmarc"]
        dmarc_status = dmarc_parsed["dmarc_status"]
        dmarc_policy = dmarc_parsed["dmarc_policy"]
        dmarc_enforced = dmarc_parsed["dmarc_enforced"]

    self_hosted_mail = sec.get("self_hosted_mail", False)

    dns_count = metrics.get("dns_domains", 0)
    subdomain_count = metrics.get("resolved_subdomains", 0)

    # Sample coverage is only valid if CT source succeeded and denominator > 0
    sample_coverage = round(dns_count / cert_count, 4) if (cert_available and cert_count > 0 and not cert_fallback) else None

    return {
        # A. Organization Metadata
        "country": row["country"].strip().lower(),
        "sector": row["sector"].strip().lower(),
        "organization_id": row["organization_id"].strip(),
        "domain_hash": domain_hash(domain, salt),

        # B. Collection Metadata
        "collection_date": collection_date,

        # C. Source Provenance
        "certificate_query_status": cert_status,
        "certificate_source_available": cert_available,
        "certificate_fallback_used": cert_fallback,

        # D. Measurement Observations
        "certificate_domain_count": cert_count,
        "dns_domain_count": dns_count,
        "subdomain_count": subdomain_count,
        "total_observed_hostnames": dns_count + subdomain_count,
        "ipv4_count": metrics.get("ipv4_count", 0),
        "ipv6_count": metrics.get("ipv6_count", 0),
        "discovered_ip_count": metrics.get("discovered_ips", 0),
        "internetdb_record_count": metrics.get("internetdb_records", 0),
        "mx_count": metrics.get("mx_count", 0),
        "ns_count": metrics.get("ns_count", 0),
        "has_spf": has_spf,
        "spf_status": spf_status,
        "spf_policy": spf_policy,
        "weak_spf": weak_spf,
        "has_dmarc": has_dmarc,
        "dmarc_status": dmarc_status,
        "dmarc_policy": dmarc_policy,
        "dmarc_enforced": dmarc_enforced,
        "self_hosted_mail": self_hosted_mail,

        # E. Derived Analytical Variables
        "observed_asset_coverage": sample_coverage,
        "finding_count": len(findings),
        "high_priority_finding_count": sum(item.get("severity") in {"critical", "high"} for item in findings),
        "posture_score": report.get("posture", {}).get("score"),
    }


def build_dataset(manifest_path, target_root="data/targets", salt="beacon-study", collection_date=None):
    rows = read_manifest(manifest_path)
    date = collection_date or datetime.now(timezone.utc).date().isoformat()
    dataset = []
    missing = []
    for row in rows:
        domain = normalize_domain(row["domain"])
        report = _load_report(target_root, domain)
        if report is None:
            missing.append(row["organization_id"])
            continue
        dns_data = _load_dns(target_root, domain)
        dataset.append(_measure(row, report, salt, date, dns_data=dns_data))
    return {
        "metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "collection_date": date,
            "manifest": str(manifest_path),
            "anonymization": "domain_hash is SHA-256 truncated to 16 hex characters with a study-local salt",
            "missing_reports": missing,
        },
        "observations": dataset,
    }


def summarize(dataset):
    observations = dataset.get("observations", [])
    n = len(observations)
    summary = {
        "n": n,
        "overall": {
            "spf_adoption_rate": round(sum(r["has_spf"] for r in observations) / n, 4) if n else 0,
            "dmarc_adoption_rate": round(sum(r["has_dmarc"] for r in observations) / n, 4) if n else 0,
            "dmarc_enforcement_rate": round(sum(r.get("dmarc_enforced", False) for r in observations) / n, 4) if n else 0,
            "high_priority_rate": round(sum(r["high_priority_finding_count"] > 0 for r in observations) / n, 4) if n else 0,
            "mean_subdomains": round(sum(r["subdomain_count"] for r in observations) / n, 2) if n else 0,
            "mean_discovered_ips": round(sum(r["discovered_ip_count"] for r in observations) / n, 2) if n else 0,
        },
        "by_country": {},
        "by_sector": {},
    }
    for group_key in ("country", "sector"):
        groups = defaultdict(list)
        for row in observations:
            groups[row[group_key]].append(row)
        target = summary[f"by_{group_key}"]
        for name, rows in sorted(groups.items()):
            n_grp = len(rows)
            with_coverage = [r for r in rows if r["observed_asset_coverage"] is not None]
            target[name] = {
                "n": n_grp,
                "mean_subdomains": round(sum(row["subdomain_count"] for row in rows) / n_grp, 2),
                "mean_discovered_ips": round(sum(row["discovered_ip_count"] for row in rows) / n_grp, 2),
                "spf_rate": round(sum(row["has_spf"] for row in rows) / n_grp, 4),
                "dmarc_rate": round(sum(row["has_dmarc"] for row in rows) / n_grp, 4),
                "dmarc_enforcement_rate": round(sum(row.get("dmarc_enforced", False) for row in rows) / n_grp, 4),
                "high_priority_rate": round(sum(row["high_priority_finding_count"] > 0 for row in rows) / n_grp, 4),
                "mean_asset_coverage": round(sum(r["observed_asset_coverage"] for r in with_coverage) / len(with_coverage), 4) if with_coverage else None,
            }
    return summary


def save_dataset(dataset, output_path):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(dataset, indent=2), encoding="utf-8")
    return output_path


def save_csv(dataset, output_path):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    rows = dataset.get("observations", [])
    if rows:
        with output_path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
    return output_path
