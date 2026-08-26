"""Turn passive public observations into explainable Beacon findings."""

import json
import html
from datetime import datetime, timezone
from pathlib import Path


SEVERITY_DEDUCTIONS = {"critical": 25, "high": 15, "medium": 8, "low": 3}


def _finding(finding_id, severity, title, description, evidence, recommendation):
    return {
        "id": finding_id,
        "severity": severity,
        "title": title,
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
        "confidence": "high" if evidence else "medium",
    }


def build_findings(domain, dns_data, subdomain_data, internetdb_data):
    findings = []
    for item in dns_data:
        security = item.get("security", {})
        subject = item.get("domain", domain)
        if not security.get("has_spf"):
            findings.append(_finding(
                f"missing-spf:{subject}", "high", f"SPF missing on {subject}",
                "This domain publishes no SPF policy, making sender impersonation easier.",
                subject, "Publish an SPF record with an explicit sender policy and review it before enforcement.",
            ))
        if not security.get("has_dmarc"):
            findings.append(_finding(
                f"missing-dmarc:{subject}", "high", f"DMARC missing on {subject}",
                "This domain publishes no DMARC policy, reducing protection against phishing and spoofed mail.",
                subject, "Publish a DMARC record, begin with monitoring, then move toward quarantine or reject.",
            ))
        if security.get("weak_spf"):
            findings.append(_finding(
                f"weak-spf:{subject}", "medium", f"Weak SPF policy on {subject}",
                "The SPF policy uses a soft or neutral final mechanism rather than rejecting unauthorized senders.",
                subject, "Review authorized senders and replace the final mechanism with -all when safe.",
            ))
        if security.get("self_hosted_mail"):
            findings.append(_finding(
                f"self-hosted-mail:{subject}", "medium", f"Self-hosted mail infrastructure on {subject}",
                "MX records point to infrastructure under the same registrable domain.",
                ", ".join(item.get("records", {}).get("MX", [])), "Confirm the mail host is patched, monitored, and intentionally internet-facing.",
            ))

    risky_labels = {"admin", "dev", "test", "staging", "api", "vpn", "remote", "internal"}
    risky_records = [
        record for group in subdomain_data for record in group.get("records", [])
        if record.get("subdomain", "").split(".")[0] in risky_labels
    ]
    if risky_records:
        findings.append(_finding(
            f"sensitive-subdomains:{domain}", "medium", f"{len(risky_records)} sensitive subdomains resolve",
            "Administrative, development, testing, or internal-looking names are publicly resolvable.",
            ", ".join(record.get("subdomain", "") for record in risky_records[:20]),
            "Confirm each hostname is required, restrict administrative services, and remove abandoned records.",
        ))
    wildcard_domains = [group.get("domain") for group in subdomain_data if group.get("wildcard_enabled")]
    if wildcard_domains:
        findings.append(_finding(
            f"wildcard-dns:{domain}", "low", "Wildcard DNS is enabled",
            "Randomly generated hostnames resolve under the domain, which can obscure stale or mistyped subdomains.",
            ", ".join(wildcard_domains), "Confirm wildcard DNS is intentional and does not route unexpected hosts to production.",
        ))

    exposed_services = sum(bool(item.get("ports")) for item in internetdb_data if item.get("found"))
    if exposed_services:
        findings.append(_finding(
            f"public-ip-services:{domain}", "medium", f"{exposed_services} public IPs have InternetDB observations",
            "Previously observed public services are associated with IP addresses discovered from DNS.",
            ", ".join(item.get("ip", "") for item in internetdb_data if item.get("found")),
            "Verify ownership and necessity of each service, then restrict management interfaces and unused ports.",
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
    """Return transparent category metrics instead of one blended risk claim."""
    checked = len(dns_data)
    spf = sum(item.get("security", {}).get("has_spf", False) for item in dns_data)
    dmarc = sum(item.get("security", {}).get("has_dmarc", False) for item in dns_data)
    email_score = round(((spf / checked) + (dmarc / checked)) * 50) if checked else None
    asset_count = len(domains) + sum(len(item.get("records", [])) for item in subdomain_data)
    asset_score = min(100, asset_count * 10) if asset_count else 0
    observed_ips = sum(bool(item.get("ports")) for item in internetdb_data if item.get("found"))
    service_score = min(100, observed_ips * 10)
    quality_parts = [bool(domains), bool(dns_data)]
    quality_parts.append(bool(subdomain_data))
    quality_parts.append(bool(internetdb_data) if observed_ips else True)
    quality_score = round(sum(quality_parts) / len(quality_parts) * 100)
    return {
        "email_security": {"score": email_score, "spf_coverage": round(spf / checked, 4) if checked else None, "dmarc_coverage": round(dmarc / checked, 4) if checked else None, "domains_checked": checked},
        "asset_visibility": {"score": asset_score, "certificate_domains": len(domains), "resolved_subdomains": sum(len(item.get("records", [])) for item in subdomain_data)},
        "public_service_observations": {"score": service_score, "ips_with_observations": observed_ips, "ips_checked": len(internetdb_data)},
        "measurement_quality": {"score": quality_score, "certificate_data": bool(domains), "dns_data": bool(dns_data), "subdomain_data": bool(subdomain_data), "internetdb_data": bool(internetdb_data)},
    }


def make_report(domain, domains, dns_data, subdomain_data, internetdb_data):
    findings = build_findings(domain, dns_data, subdomain_data, internetdb_data)
    report = {
        "domain": domain,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": "passive public observations",
        "metrics": {
            "certificate_domains": len(domains),
            "dns_domains": len(dns_data),
            "resolved_subdomains": sum(len(item.get("records", [])) for item in subdomain_data),
            "discovered_ips": len({record.get("ip") for group in subdomain_data for record in group.get("records", [])} | {address for item in dns_data for address in item.get("records", {}).get("A", []) + item.get("records", {}).get("AAAA", [])}),
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
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return path


def markdown_report(report):
    posture_data = report["posture"]
    lines = [
        f"# Beacon exposure report: {report['domain']}",
        "",
        f"Generated: {report['generated_at']}",
        "Scope: passive public observations only.",
        "",
        f"## Overall posture: {posture_data['label']} ({posture_data['score']}/100)",
        "",
        "## Measurement categories",
        "",
        "| Category | Score |",
        "|---|---:|",
        *[f"| {key.replace('_', ' ').title()} | {value.get('score', 'n/a')} |" for key, value in report.get("categories", {}).items()],
        "",
        "| Metric | Count |",
        "|---|---:|",
    ]
    for key, value in report["metrics"].items():
        lines.append(f"| {key.replace('_', ' ').title()} | {value:,} |" if isinstance(value, int) else f"| {key.replace('_', ' ').title()} | {value} |")
    lines.extend(["", f"## Findings ({len(report['findings'])})", ""])
    if not report["findings"]:
        lines.append("No actionable findings were generated from the available observations.")
    for finding in sorted(report["findings"], key=lambda item: (SEVERITY_DEDUCTIONS.get(item["severity"], 0) * -1, item["title"])):
        lines.extend([
            f"### {finding['severity'].upper()}: {finding['title']}",
            finding["description"],
            f"- Evidence: `{finding['evidence']}`",
            f"- Recommended action: {finding['recommendation']}",
            "",
        ])
    return "\n".join(lines)


def html_report(report):
    """Render a standalone report that can be opened in any browser."""
    posture_data = report["posture"]
    findings = []
    for item in report["findings"]:
        findings.append(
            f"<article><h3>{html.escape(item['severity'].upper())} · {html.escape(item['title'])}</h3>"
            f"<p>{html.escape(item['description'])}</p>"
            f"<p><strong>Evidence:</strong> <code>{html.escape(str(item['evidence']))}</code></p>"
            f"<p><strong>Recommended action:</strong> {html.escape(item['recommendation'])}</p></article>"
        )
    cards = "".join(f"<li><strong>{html.escape(key.replace('_', ' ').title())}</strong><span>{value}</span></li>" for key, value in report["metrics"].items())
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Beacon report - {html.escape(report['domain'])}</title>
<style>body{{font:16px system-ui,sans-serif;max-width:900px;margin:40px auto;padding:0 20px;color:#18222d}}h1{{margin-bottom:4px}}.posture{{font-size:28px;padding:18px;background:#e8f4f1;border-left:6px solid #168277}}ul{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;padding:0;list-style:none}}li,article{{padding:16px;border:1px solid #d8e0e5;border-radius:6px}}li span{{display:block;font-size:25px;margin-top:6px}}article{{margin:14px 0}}code{{overflow-wrap:anywhere}}</style></head>
<body><h1>Beacon exposure report</h1><p>{html.escape(report['domain'])} · {html.escape(report['generated_at'])}</p>
<div class="posture"><strong>{html.escape(posture_data['label'])}</strong> · {posture_data['score']}/100 · {posture_data['finding_count']} findings</div>
<h2>Observed footprint</h2><ul>{cards}</ul><h2>Findings</h2>{''.join(findings) or '<p>No actionable findings were generated.</p>'}</body></html>"""


def disclosure_draft(report, recipient="security@company.com"):
    high = [item for item in report["findings"] if item["severity"] in {"critical", "high"}]
    summary = "\n".join(f"- {item['title']}: {item['recommendation']}" for item in high) or "- No high-priority findings were identified in the available public observations."
    return f"""To: {recipient}
Subject: Private public-exposure observations for {report['domain']}

Hello security team,

I am sharing a private, non-intrusive report about publicly observable configuration for {report['domain']}. These observations do not indicate compromise or unauthorized access.

Priority observations:
{summary}

The observations were collected from public certificate, DNS, and InternetDB data on {report['generated_at']}. Please verify them through your normal security process. I have not attempted authentication, exploitation, or access to private systems.

Beacon
Africa-first public exposure intelligence
"""


def save_artifacts(report, target_dir):
    target_dir = Path(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / "report.md").write_text(markdown_report(report), encoding="utf-8")
    (target_dir / "report.html").write_text(html_report(report), encoding="utf-8")
    (target_dir / "disclosure_draft.txt").write_text(disclosure_draft(report), encoding="utf-8")


def save_history_snapshot(report, target_dir):
    history_dir = Path(target_dir) / "history"
    history_dir.mkdir(parents=True, exist_ok=True)
    stamp = report["generated_at"].replace(":", "").replace("+00:00", "Z")
    path = history_dir / f"{stamp}.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return path


def compare_previous(report, target_dir):
    paths = sorted((Path(target_dir) / "history").glob("*.json"))
    if not paths:
        return {"new_findings": report["findings"], "resolved_findings": [], "previous": None}
    previous = json.loads(paths[-1].read_text(encoding="utf-8"))
    current_ids = {item["id"] for item in report["findings"]}
    previous_ids = {item["id"] for item in previous.get("findings", [])}
    return {
        "new_findings": [item for item in report["findings"] if item["id"] not in previous_ids],
        "resolved_findings": [item for item in previous.get("findings", []) if item["id"] not in current_ids],
        "previous": previous.get("generated_at"),
    }
