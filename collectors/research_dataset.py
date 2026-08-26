"""Build an anonymized, reproducible research dataset from Beacon reports."""

import csv
import hashlib
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


REQUIRED_COLUMNS = ("country", "sector", "organization_id", "domain")


def read_manifest(path):
    """Read and validate the frozen organization sampling frame."""
    path = Path(path)
    with path.open(newline="", encoding="utf-8-sig") as stream:
        rows = list(csv.DictReader(stream))
    missing = set(REQUIRED_COLUMNS) - set(rows[0]) if rows else set(REQUIRED_COLUMNS)
    if missing:
        raise ValueError(f"Manifest is missing columns: {', '.join(sorted(missing))}")
    for row in rows:
        if not all(row.get(column, "").strip() for column in REQUIRED_COLUMNS):
            raise ValueError("Every manifest row needs country, sector, organization_id, and domain")
    return rows


def domain_hash(domain, salt):
    """Create a stable non-reversible identifier within one study."""
    return hashlib.sha256(f"{salt}:{domain.lower().strip()}".encode("utf-8")).hexdigest()[:16]


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


def _extract_dmarc_policy(dns_data, root_domain):
    root_entry = next((item for item in dns_data if item.get("domain") == root_domain), dns_data[0] if dns_data else None)
    if not root_entry:
        return "absent"
    dmarc_records = root_entry.get("records", {}).get("DMARC", [])
    if not dmarc_records:
        return "absent"
    combined = " ".join(dmarc_records).lower()
    if "p=reject" in combined:
        return "reject"
    if "p=quarantine" in combined:
        return "quarantine"
    if "p=none" in combined:
        return "none"
    return "present_unspecified"


def _measure(row, report, salt, collection_date, dns_data=None):
    metrics = report.get("metrics", {})
    findings = report.get("findings", [])
    cert_count = metrics.get("certificate_domains", 0)
    dns_count = metrics.get("dns_domains", 0)
    subdomain_count = metrics.get("resolved_subdomains", 0)
    
    # Certificate Transparency source availability:
    # crt.sh returns >1 when subdomain/SAN discovery succeeds; 1 indicates single-name fallback or solitary cert
    cert_source_available = cert_count > 1
    sample_coverage = round(dns_count / cert_count, 4) if cert_source_available and cert_count > 0 else None
    
    # Email security policy details from DNS
    dmarc_policy = _extract_dmarc_policy(dns_data or [], row["domain"].strip().lower())
    has_dmarc = dmarc_policy != "absent"
    dmarc_enforced = dmarc_policy in ("quarantine", "reject")
    
    root_dns = next((item for item in (dns_data or []) if item.get("domain") == row["domain"].strip().lower()), (dns_data or [None])[0])
    weak_spf = root_dns.get("security", {}).get("weak_spf") if root_dns else None
    has_spf = metrics.get("spf_domains", 0) > 0

    return {
        "country": row["country"].strip().lower(),
        "sector": row["sector"].strip().lower(),
        "organization_id": row["organization_id"].strip(),
        "collection_date": collection_date,
        "domain_hash": domain_hash(row["domain"], salt),
        "certificate_domain_count": cert_count,
        "certificate_data_available": cert_source_available,
        "dns_domain_count": dns_count,
        "subdomain_count": subdomain_count,
        "total_observed_hostnames": dns_count + subdomain_count,
        "ipv4_count": metrics.get("ipv4_count", 0),
        "ipv6_count": metrics.get("ipv6_count", 0),
        "discovered_ip_count": metrics.get("discovered_ips", 0),
        "internetdb_record_count": metrics.get("internetdb_records", 0),
        "finding_count": len(findings),
        "high_priority_finding_count": sum(item.get("severity") in {"critical", "high"} for item in findings),
        "posture_score": report.get("posture", {}).get("score"),
        "observed_asset_coverage": sample_coverage,
        "has_spf": has_spf,
        "weak_spf": weak_spf if has_spf else None,
        "has_dmarc": has_dmarc,
        "dmarc_policy": dmarc_policy,
        "dmarc_enforced": dmarc_enforced,
        "mx_count": metrics.get("mx_count", 0),
        "ns_count": metrics.get("ns_count", 0),
    }


def build_dataset(manifest_path, target_root="data/targets", salt="beacon-study", collection_date=None):
    """Create one anonymized row per manifest organization with available data."""
    rows = read_manifest(manifest_path)
    date = collection_date or datetime.now(timezone.utc).date().isoformat()
    dataset = []
    missing = []
    for row in rows:
        domain = row["domain"].strip().lower()
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
    summary = {
        "n": len(observations),
        "overall": {
            "spf_adoption_rate": round(sum(r["has_spf"] for r in observations) / len(observations), 4) if observations else 0,
            "dmarc_adoption_rate": round(sum(r["has_dmarc"] for r in observations) / len(observations), 4) if observations else 0,
            "dmarc_enforcement_rate": round(sum(r.get("dmarc_enforced", False) for r in observations) / len(observations), 4) if observations else 0,
            "high_priority_rate": round(sum(r["high_priority_finding_count"] > 0 for r in observations) / len(observations), 4) if observations else 0,
            "mean_subdomains": round(sum(r["subdomain_count"] for r in observations) / len(observations), 2) if observations else 0,
            "mean_discovered_ips": round(sum(r["discovered_ip_count"] for r in observations) / len(observations), 2) if observations else 0,
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
            with_coverage = [r for r in rows if r["observed_asset_coverage"] is not None]
            target[name] = {
                "n": len(rows),
                "mean_subdomains": round(sum(row["subdomain_count"] for row in rows) / len(rows), 2),
                "mean_discovered_ips": round(sum(row["discovered_ip_count"] for row in rows) / len(rows), 2),
                "spf_rate": round(sum(row["has_spf"] for row in rows) / len(rows), 4),
                "dmarc_rate": round(sum(row["has_dmarc"] for row in rows) / len(rows), 4),
                "dmarc_enforcement_rate": round(sum(row.get("dmarc_enforced", False) for row in rows) / len(rows), 4),
                "high_priority_rate": round(sum(row["high_priority_finding_count"] > 0 for row in rows) / len(rows), 4),
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
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
    return output_path
