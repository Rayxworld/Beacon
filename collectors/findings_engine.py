"""Turn passive public observations into explainable Beacon indicators and findings."""

import html
import json
from datetime import datetime, timezone
from pathlib import Path

from collectors.domain_utils import normalize_domain

SEVERITY_DEDUCTIONS = {"critical": 25, "high": 15, "medium": 8, "low": 3}


def _finding(finding_id, severity, title, description, evidence, recommendation, category="exposure_indicator"):
    return {
        "id": finding_id,
        "severity": severity,
        "category": category,
        "title": title,
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
        "confidence": "high" if evidence else "medium",
    }


def build_findings(domain, dns_data, subdomain_data, internetdb_data):
    """
    Build explainable indicators from passive observations without conflating
    exposure with confirmed vulnerability or attributing query failures as missing records.
    """
    findings = []
    domain = normalize_domain(domain)

    for item in dns_data:
        security = item.get("security", {})
        subject = item.get("domain", domain)
        spf_status = security.get("spf_status", "absent")
        dmarc_status = security.get("dmarc_status", "absent")

        # Only report missing SPF if query actually succeeded and record was absent
        if not security.get("has_spf"):
            if spf_status == "absent":
                findings.append(_finding(
                    f"missing-spf:{subject}", "high", f"SPF record absent on {subject}",
                    "No SPF configuration observed. Receiver validation cannot verify authorized sending hosts via SPF.",
                    subject, "Publish an SPF record specifying authorized mail sources.",
                    category="configuration_state"
                ))
            elif spf_status == "malformed":
                findings.append(_finding(
                    f"malformed-spf:{subject}", "high", f"Malformed SPF record on {subject}",
                    security.get("error", "Multiple or invalid SPF records published."),
                    security.get("spf_record", subject), "Ensure only a single, syntactically valid SPF record is published.",
                    category="configuration_state"
                ))

        if not security.get("has_dmarc"):
            if dmarc_status == "absent":
                findings.append(_finding(
                    f"missing-dmarc:{subject}", "high", f"DMARC policy absent on {subject}",
                    "No DMARC policy published. Receiving mail transfer agents will not enforce alignment or send feedback reports.",
                    subject, "Publish a DMARC policy starting with p=none for telemetry, advancing to p=quarantine/p=reject.",
                    category="configuration_state"
                ))
            elif dmarc_status == "malformed":
                findings.append(_finding(
                    f"malformed-dmarc:{subject}", "high", f"Malformed DMARC record on {subject}",
                    security.get("error", "Multiple or invalid DMARC records published."),
                    security.get("dmarc_record", subject), "Ensure exactly one valid DMARC record with a valid p= policy tag is published.",
                    category="configuration_state"
                ))

        if security.get("weak_spf"):
            findings.append(_finding(
                f"weak-spf:{subject}", "medium", f"Weak SPF policy mechanism on {subject}",
                f"The SPF policy uses {security.get('spf_policy', 'softfail')} (~all/?all), which allows unauthorized mail to be received with spam scoring increments.",
                security.get("spf_record", subject), "Review authorized sending IP ranges and upgrade final mechanism to -all when verified.",
                category="configuration_state"
            ))

        if security.get("self_hosted_mail"):
            findings.append(_finding(
                f"self-hosted-mail:{subject}", "medium", f"Self-hosted mail infrastructure on {subject}",
                "MX records resolve under the same organizational registrable domain.",
                ", ".join(item.get("records", {}).get("MX", [])), "Ensure mail server interfaces are monitored, patched, and secured against relaying.",
                category="exposure_indicator"
            ))

    risky_labels = {"admin", "dev", "test", "staging", "api", "vpn", "remote", "internal"}
    risky_records = [
        record for group in subdomain_data for record in group.get("records", [])
        if record.get("subdomain", "").split(".")[0] in risky_labels
    ]
    if risky_records:
        findings.append(_finding(
            f"sensitive-subdomains:{domain}", "medium", f"{len(risky_records)} sensitive hostnames resolve under {domain}",
            "Administrative, development, or remote access hostnames resolve to public IP addresses.",
            ", ".join(record.get("subdomain", "") for record in risky_records[:20]),
            "Confirm each hostname is necessary, enforce multi-factor authentication, and decommission stale environments.",
            category="exposure_indicator"
        ))

    wildcard_domains = [group.get("domain") for group in subdomain_data if group.get("wildcard_enabled")]
    if wildcard_domains:
        findings.append(_finding(
            f"wildcard-dns:{domain}", "low", "Wildcard DNS resolution enabled",
            "Non-existent subdomain queries resolve to active IP addresses, which can obscure stale asset inventories.",
            ", ".join(wildcard_domains), "Confirm wildcard DNS resolution is intentional.",
            category="configuration_state"
        ))

    exposed_services = sum(bool(item.get("ports")) for item in internetdb_data if item.get("found"))
    if exposed_services:
        findings.append(_finding(
            f"public-ip-services:{domain}", "medium", f"{exposed_services} public IPs have historical InternetDB service observations",
            "Previously observed public network services are indexed for IP addresses associated with this organization.",
            ", ".join(item.get("ip", "") for item in internetdb_data if item.get("found")),
            "Review public service necessity and restrict management ports to internal or VPN access.",
            category="exposure_indicator"
        ))

    return findings


def posture(findings):
    score = 100 - sum(SEVERITY_DEDUCTIONS.get(item["severity"], 0) for item in findings)
    score = max(0, score)
    if score >= 85:
        label = "Healthy"
    elif score >= 65:
        label = "Needs attention"
    elif score >= 40:
        label = "Elevated risk"
    else:
        label = "High priority"
    return {"score": score, "label": label, "finding_count": len(findings)}


def category_scores(domains, dns_data, subdomain_data, internetdb_data):
    checked = len(dns_data)
    spf = sum(item.get("security", {}).get("has_spf", False) for item in dns_data)
    dmarc = sum(item.get("security", {}).get("has_dmarc", False) for item in dns_data)
    email_score = round(((spf / checked) + (dmarc / checked)) * 50) if checked else None
    asset_count = len(domains) + sum(len(item.get("records", [])) for item in subdomain_data)
    asset_score = min(100, asset_count * 10) if asset_count else 0
    observed_ips = sum(bool(item.get("ports")) for item in internetdb_data if item.get("found"))
    service_score = min(100, observed_ips * 10)
    quality_parts = [bool(domains), bool(dns_data), bool(subdomain_data), bool(internetdb_data) if observed_ips else True]
    quality_score = round(sum(quality_parts) / len(quality_parts) * 100)

    return {
        "email_security": {"score": email_score, "spf_coverage": round(spf / checked, 4) if checked else None, "dmarc_coverage": round(dmarc / checked, 4) if checked else None, "domains_checked": checked},
        "asset_visibility": {"score": asset_score, "certificate_domains": len(domains), "resolved_subdomains": sum(len(item.get("records", [])) for item in subdomain_data)},
        "public_service_observations": {"score": service_score, "ips_with_observations": observed_ips, "ips_checked": len(internetdb_data)},
        "measurement_quality": {"score": quality_score, "certificate_data": bool(domains), "dns_data": bool(dns_data), "subdomain_data": bool(subdomain_data), "internetdb_data": bool(internetdb_data)},
    }


def make_report(domain, domains, dns_data, subdomain_data, internetdb_data, crt_metadata=None):
    domain = normalize_domain(domain)
    findings = build_findings(domain, dns_data, subdomain_data, internetdb_data)
    crt_meta = crt_metadata or {}
    
    unique_discovered_ips = {
        record.get("ip") for group in subdomain_data for record in group.get("records", []) if record.get("ip")
    } | {
        address for item in dns_data for address in item.get("records", {}).get("A", []) + item.get("records", {}).get("AAAA", [])
    }
    unique_discovered_ips.discard(None)

    report = {
        "domain": domain,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": "passive public observations",
        "provenance": {
            "certificate_transparency": crt_meta,
            "dns_collector": {
                "records_collected": len(dns_data),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        },
        "metrics": {
            "certificate_domains": len(domains),
            "certificate_source_available": crt_meta.get("certificate_source_available", len(domains) > 1 or crt_meta.get("certificate_query_status") == "success"),
            "dns_domains": len(dns_data),
            "resolved_subdomains": sum(len(item.get("records", [])) for item in subdomain_data),
            "discovered_ips": len(unique_discovered_ips),
            "internetdb_records": len(internetdb_data),
            "ipv4_count": sum(len(item.get("records", {}).get("A", [])) for item in dns_data),
            "ipv6_count": sum(len(item.get("records", {}).get("AAAA", [])) for item in dns_data),
            "spf_domains": sum(item.get("security", {}).get("has_spf", False) for item in dns_data),
            "dmarc_domains": sum(item.get("security", {}).get("has_dmarc", False) for item in dns_data),
            "mx_count": sum(len(item.get("records", {}).get("MX", [])) for item in dns_data),
            "ns_count": sum(len(item.get("records", {}).get("NS", [])) for item in dns_data),
        },
        "posture": posture(findings),
        "categories": category_scores(domains, dns_data, subdomain_data, internetdb_data),
        "findings": findings,
    }
    return report


def save_report(report, target_dir):
    target_dir = Path(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    path = target_dir / "report.json"
    with path.open("w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
    return path


def save_history_snapshot(report, target_dir):
    history_dir = Path(target_dir) / "history"
    history_dir.mkdir(parents=True, exist_ok=True)
    stamp = report["generated_at"].replace(":", "").replace("-", "").replace("+0000", "+00:00")
    snapshot_path = history_dir / f"{stamp}.json"
    with snapshot_path.open("w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
    return snapshot_path


def compare_previous(current_report, target_dir):
    history_dir = Path(target_dir) / "history"
    if not history_dir.exists():
        return {"new_findings": current_report.get("findings", []), "resolved_findings": [], "previous": None}
    snapshots = sorted(history_dir.glob("*.json"))
    if not snapshots:
        return {"new_findings": current_report.get("findings", []), "resolved_findings": [], "previous": None}
    previous_path = snapshots[-1]
    try:
        with previous_path.open(encoding="utf-8") as stream:
            previous_report = json.load(stream)
    except (OSError, json.JSONDecodeError):
        return {"new_findings": current_report.get("findings", []), "resolved_findings": [], "previous": None}
    current_ids = {item["id"]: item for item in current_report.get("findings", [])}
    previous_ids = {item["id"]: item for item in previous_report.get("findings", [])}
    new_findings = [current_ids[k] for k in current_ids if k not in previous_ids]
    resolved_findings = [previous_ids[k] for k in previous_ids if k not in current_ids]
    return {
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "previous": previous_report.get("generated_at"),
    }


def save_artifacts(report, target_dir):
    target_dir = Path(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    # Save report.md
    md_lines = [
        f"# Exposure Report: {report['domain']}",
        f"Generated: {report['generated_at']}",
        f"Posture Score: {report['posture']['score']}/100 ({report['posture']['label']})",
        "",
        "## Summary Metrics",
        f"- Certificate Names: {report['metrics']['certificate_domains']}",
        f"- Resolved Subdomains: {report['metrics']['resolved_subdomains']}",
        f"- Discovered Public IPs: {report['metrics']['discovered_ips']}",
        f"- Total Findings: {len(report['findings'])}",
        "",
        "## Observable Exposure Findings",
    ]
    for f in report.get("findings", []):
        md_lines.extend([
            f"### [{f['severity'].upper()}] {f['title']}",
            f"**Description:** {f['description']}",
            f"**Evidence:** `{f['evidence']}`",
            f"**Recommendation:** {f['recommendation']}",
            "",
        ])
    (target_dir / "report.md").write_text("\n".join(md_lines), encoding="utf-8")
    
    # Save disclosure draft
    disclosure = [
        f"SUBJECT: Security Observability Notice for {report['domain']}",
        "",
        f"Dear Security Team at {report['domain']},",
        "",
        "During passive public measurements conducted for academic research, the following observable configuration indicators were noted:",
        "",
    ]
    for f in report.get("findings", []):
        disclosure.append(f"- {f['title']}: {f['description']}")
    disclosure.extend([
        "",
        "This notice is provided for defensive awareness. No active probing or exploitation was performed.",
        "Regards,",
        "Beacon Research Team",
    ])
    (target_dir / "disclosure_draft.txt").write_text(disclosure_draft(report), encoding="utf-8")


def disclosure_draft(report):
    disclosure = [
        f"SUBJECT: Security Observability Notice for {report.get('domain', 'Target')}",
        "",
        f"Dear Security Team at {report.get('domain', 'Target')},",
        "",
        "During passive public measurements conducted for academic research, the following observable configuration indicators were noted:",
        "",
    ]
    for f in report.get("findings", []):
        disclosure.append(f"- [{f.get('severity', 'info').upper()}] {f.get('title', '')}: {f.get('description', '')}")
    disclosure.extend([
        "",
        "This notice is provided for defensive awareness. No active probing or exploitation was performed.",
        "Regards,",
        "Beacon Research Team",
    ])
    return "\n".join(disclosure)
