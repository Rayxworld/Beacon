#!/usr/bin/env python3
"""
BEACON — Africa-first public exposure intelligence
Collect, analyze, and visualize Africa's digital infrastructure.
All free data sources. No unauthorized scanning.

Data sources: RIPE Stat, crt.sh, DNS, subdomain lookups, and Shodan InternetDB.
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).parent))

from collectors.ripe_collector import collect_country as ripe_collect, save_ripe_data, AFRICAN_COUNTRIES
from collectors.crtsh_collector import collect_country_domains, collect_domain_domains, save_crtsh_data
from collectors.dns_security_collector import collect_domains, save_dns_data, save_target_dns_data
from collectors.subdomain_enumerator import enumerate_domains, save_subdomain_data, save_target_subdomain_data
from collectors.internetdb_collector import enrich_ips, save_internetdb_data, save_target_internetdb_data
from collectors.findings_engine import compare_previous, make_report, save_artifacts, save_history_snapshot, save_report
from collectors.research_dataset import build_dataset, read_manifest, save_csv, save_dataset, summarize


MAX_DNS_DOMAINS_PER_TARGET = 25


def print_banner():
    print(r"""
    ___    __    _____ __________ _    ____________ 
   /   |  / /   / ___// ____/ __ \ |  / / ____/ __ \
  / /| | / /    \__ \/ __/ / /_/ / | / / /   / /_/ /
 / ___ |/ /______/ / / / /___/ _, _/| |/ / /___/ _, _/ 
/_/  |_/_____/____/ /_____/_/ |_| |___/\____/_/ |_|  

    Beacon — Africa-first public exposure intelligence
Built by Raymond Fafi | github.com/Rayxworld
""")


def normalize_domain(value):
    """Convert a hostname or URL into a safe lowercase hostname."""
    value = value.strip()
    parsed = urlsplit(value if "://" in value else f"//{value}")
    domain = (parsed.hostname or "").lower().removeprefix("www.").rstrip(".")
    if not domain or any(character in domain for character in ("/", "\\", " ")):
        raise ValueError("enter a valid domain such as example.com or https://www.example.com")
    return domain


def analyze_country(country_code, do_dns=False, do_subdomains=False):
    """Run full collection pipeline for a country."""
    country_name = AFRICAN_COUNTRIES.get(country_code, country_code.upper())
    print(f"\n{'='*60}")
    print(f"🌍 ANALYZING: {country_name} ({country_code.upper()})")
    print(f"{'='*60}\n")

    # 1. RIPE (free, no key)
    ripe_data = ripe_collect(country_code)
    save_ripe_data(ripe_data, country_code)

    # 2. crt.sh (free, no key)
    crt_data = collect_country_domains(country_code)
    save_crtsh_data(crt_data, country_code)

    dns_data = []
    subdomain_data = []
    if do_dns:
        print("\n🔎 Collecting DNS security and infrastructure records")
        dns_data = collect_domains(crt_data, delay=0.5)
        save_dns_data(dns_data, country_code)

    if do_subdomains:
        print("\n🔎 Enumerating common subdomains")
        subdomain_data = enumerate_domains(crt_data, delay=0.5)
        save_subdomain_data(subdomain_data, country_code)

    discovered_ips = set()
    for domain in dns_data:
        for address in domain.get("records", {}).get("A", []) + domain.get("records", {}).get("AAAA", []):
            discovered_ips.add(address)
    for domain in subdomain_data:
        for record in domain.get("records", []):
            discovered_ips.add(record.get("ip"))
    internetdb_data = enrich_ips(discovered_ips, delay=1.0) if discovered_ips else []
    if internetdb_data:
        save_internetdb_data(internetdb_data, country_code)

    # Summary
    print(f"\n📊 SUMMARY FOR {country_name}")
    print(f"   IP ranges (RIPE): {ripe_data['stats']['ipv4_count']} IPv4, {ripe_data['stats']['ipv6_count']} IPv6")
    print(f"   Domains (crt.sh): {len(crt_data)}")
    print(f"   DNS records: {sum(len(item.get('records', {})) for item in dns_data)} domains")
    print(f"   Resolved subdomains: {sum(len(item.get('records', [])) for item in subdomain_data)}")
    print()

    return {
        "country": country_name,
        "code": country_code.upper(),
        "timestamp": datetime.utcnow().isoformat(),
        "ripe": ripe_data["stats"],
        "domains_count": len(crt_data),
        "dns_domains": len(dns_data),
        "subdomains": sum(len(item.get("records", [])) for item in subdomain_data),
        "internetdb_findings": len(internetdb_data),
    }


def analyze_domain(domain, do_dns=True, do_subdomains=True):
    """Generate a public exposure report for one authorized root domain."""
    domain = normalize_domain(domain)
    print(f"\n{'='*60}")
    print(f"🎯 ORGANIZATION DOMAIN: {domain}")
    print(f"{'='*60}\n")

    crt_data = collect_domain_domains(domain)
    print(f"   Certificate names: {len(crt_data)}")
    dns_targets = [domain] + [name for name in crt_data if name != domain]
    dns_targets = dns_targets[:MAX_DNS_DOMAINS_PER_TARGET]
    dns_data = collect_domains(dns_targets, delay=0.5) if do_dns else []
    subdomain_data = enumerate_domains([domain], delay=0.5) if do_subdomains else []

    discovered_ips = set()
    for item in dns_data:
        discovered_ips.update(item.get("records", {}).get("A", []))
        discovered_ips.update(item.get("records", {}).get("AAAA", []))
    for item in subdomain_data:
        discovered_ips.update(record.get("ip") for record in item.get("records", []))
    discovered_ips.discard(None)
    internetdb_data = enrich_ips(discovered_ips, delay=1.0) if discovered_ips else []

    target_dir = Path("data/targets") / domain
    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / "domains.json").write_text(json.dumps(crt_data, indent=2), encoding="utf-8")
    save_target_dns_data(dns_data, domain)
    save_target_subdomain_data(subdomain_data, domain)
    save_target_internetdb_data(internetdb_data, domain)
    report = make_report(domain, crt_data, dns_data, subdomain_data, internetdb_data)
    changes = compare_previous(report, target_dir)
    report["changes"] = {
        "new_findings": len(changes["new_findings"]),
        "resolved_findings": len(changes["resolved_findings"]),
        "previous": changes["previous"],
    }
    save_report(report, target_dir)
    save_history_snapshot(report, target_dir)
    save_artifacts(report, target_dir)
    print(f"\n📊 REPORT FOR {domain}")
    print(f"   Posture: {report['posture']['label']} ({report['posture']['score']}/100)")
    print(f"   Findings: {report['posture']['finding_count']} ({report['changes']['new_findings']} new)")
    print(f"   Resolved subdomains: {report['metrics']['resolved_subdomains']}")
    print(f"   Discovered IPs: {report['metrics']['discovered_ips']}")
    print(f"   Saved: {target_dir}")
    return report


def generate_summary_report(results):
    """Generate a summary JSON of all analyzed countries."""
    report = {
        "generated_at": datetime.utcnow().isoformat(),
        "total_countries": len(results),
        "countries": results,
    }

    output_path = Path("output/africa_summary.json")
    output_path.parent.mkdir(exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"💾 Summary report saved: {output_path}")
    return report


def run_study(manifest_path, salt, resume=False):
    """Run the same passive measurement for every row in a study manifest."""
    rows = read_manifest(manifest_path)
    results = []
    for index, row in enumerate(rows, start=1):
        target_dir = Path("data/targets") / normalize_domain(row["domain"])
        report_path = target_dir / "report.json"
        if resume and report_path.exists():
            print(f"\n[{index}/{len(rows)}] {row['organization_id']} - already complete, skipping")
            results.append(json.loads(report_path.read_text(encoding="utf-8")))
            continue
        print(f"\n[{index}/{len(rows)}] {row['country']} / {row['sector']} / {row['organization_id']}")
        try:
            results.append(analyze_domain(row["domain"], do_dns=True, do_subdomains=True))
        except KeyboardInterrupt:
            print("\nInterrupted. Re-run with --study-manifest ... --resume to continue.")
            raise
        except Exception as error:
            print(f"   Failed, continuing to next organization: {error}")
    dataset = build_dataset(manifest_path, salt=salt)
    save_dataset(dataset, "research/dataset.json")
    save_csv(dataset, "research/dataset.csv")
    Path("research/summary.json").write_text(json.dumps(summarize(dataset), indent=2), encoding="utf-8")
    print(f"\n📚 STUDY COMPLETE: {len(dataset['observations'])} observations")
    print("   Dataset: research/dataset.json and research/dataset.csv")
    return results


def main():
    parser = argparse.ArgumentParser(
        description="BEACON — Africa-first public exposure intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python africa_exposed.py --domain example.com
    python africa_exposed.py --country ng --collect --dns --subdomains
    python africa_exposed.py --top 5 --collect --dns
    python africa_exposed.py --all --collect --dns --subdomains
        """
    )
    parser.add_argument("--domain", help="Authorized organization root domain (recommended)")
    parser.add_argument("--country", help="Country code for regional research mode (e.g., ng, ke, za)")
    parser.add_argument("--collect", action="store_true", help="Run full data collection")
    parser.add_argument("--dns", action="store_true", help="Collect DNS records and email security indicators")
    parser.add_argument("--subdomains", action="store_true", help="Enumerate common subdomains with DNS lookups")
    parser.add_argument("--top", type=int, help="Analyze top N countries by internet penetration")
    parser.add_argument("--all", action="store_true", help="Analyze all African countries")
    parser.add_argument("--report", action="store_true", help="Generate summary report")
    parser.add_argument("--study-manifest", help="CSV manifest for a reproducible passive organization study")
    parser.add_argument("--study-salt", default="beacon-study", help="Study-local salt for anonymized domain hashes")
    parser.add_argument("--resume", action="store_true", help="Skip study targets that already have report.json")
    parser.add_argument("--refresh", action="store_true", help="Re-collect study targets even when report.json exists")
    args = parser.parse_args()

    if args.domain:
        try:
            args.domain = normalize_domain(args.domain)
        except ValueError as error:
            parser.error(str(error))
    if not args.domain and not args.country and not args.all and not args.top and not args.study_manifest:
        parser.error("provide --domain example.com, or choose --country/--top/--all research mode")

    print_banner()

    if args.study_manifest:
        run_study(args.study_manifest, args.study_salt, resume=args.resume and not args.refresh)
        return
    if args.domain:
        analyze_domain(args.domain, do_dns=True, do_subdomains=True)
        return
    if args.all:
        countries = list(AFRICAN_COUNTRIES.keys())
    elif args.top:
        top_countries = ["ng", "eg", "za", "ke", "gh", "tz", "dz", "ug", "ma", "et"]
        countries = top_countries[:args.top]
    else:
        countries = [args.country]

    results = []
    for code in countries:
        if args.collect:
            result = analyze_country(code, do_dns=args.dns, do_subdomains=args.subdomains)
        else:
            print(f"\n📂 Checking existing data for {code.upper()}...")
            result = {
                "country": AFRICAN_COUNTRIES.get(code, code.upper()),
                "code": code.upper(),
                "note": "Use --collect to fetch new data",
            }
        results.append(result)

    if args.report or args.collect:
        generate_summary_report(results)

    print("\n✅ Done.")
    print("   Launch dashboard: streamlit run dashboard/app.py")
    print("   Built by Raymond Fafi | github.com/Rayxworld")


if __name__ == "__main__":
    main()
