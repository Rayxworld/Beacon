"""
AFRICA EXPOSED — Rapid7 Project Sonar Processor
Download free internet scan data from Rapid7 and filter for African IPs.

Project Sonar publishes FREE datasets at:
https://opendata.rapid7.com/

No API key. No signup. Just download and analyze.
Datasets are large (GBs) but you can download specific studies.

This script:
1. Loads your RIPE IP ranges for a country
2. Downloads a Sonar study file (or uses an already-downloaded one)
3. Filters for IPs that fall within African ranges
4. Extracts ports, banners, and services
5. Saves structured findings

LEGAL: Project Sonar data is collected by Rapid7 legally and published
for research. Using their published data is 100% legal.
"""

import gzip
import json
import ipaddress
from pathlib import Path
from datetime import datetime, timezone


def load_ripe_networks(country_code):
    """Load RIPE IP ranges as ipaddress network objects."""
    ripe_file = Path(f"data/ripe/{country_code.lower()}_ripe.json")
    if not ripe_file.exists():
        print(f"❌ No RIPE data for {country_code}. Run: python africa_exposed.py --country {country_code} --collect")
        return []

    with open(ripe_file) as f:
        data = json.load(f)

    networks = []
    for prefix in data.get("ipv4_prefixes", []):
        try:
            networks.append(ipaddress.ip_network(prefix, strict=False))
        except ValueError:
            continue
    return networks


def is_in_african_ranges(ip_str, networks):
    """Check if an IP falls within any of the African networks."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for net in networks:
            if ip in net:
                return True
    except ValueError:
        pass
    return False


def process_sonar_file(sonar_path, country_code, max_lines=500000):
    """
    Process a Project Sonar study file and extract African IPs.

    Sonar files are .json.gz with one JSON object per line:
    {"timestamp":"...","ip":"102.130.x.x","port":443,"data":{"banner":"..."}}
    """
    networks = load_ripe_networks(country_code)
    if not networks:
        return []

    print(f"🗂️  Processing {sonar_path}")
    print(f"   Filtering for {country_code.upper()} ({len(networks)} IP ranges)")
    print(f"   Max lines to scan: {max_lines:,}")

    findings = []
    line_count = 0
    match_count = 0

    try:
        opener = gzip.open if str(sonar_path).endswith('.gz') else open
        with opener(sonar_path, 'rt', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line_count += 1
                if line_count > max_lines:
                    break

                try:
                    record = json.loads(line.strip())
                except json.JSONDecodeError:
                    continue

                ip_str = record.get("ip")
                if not ip_str:
                    continue

                if is_in_african_ranges(ip_str, networks):
                    match_count += 1
                    finding = {
                        "ip": ip_str,
                        "port": record.get("port"),
                        "timestamp": record.get("timestamp"),
                        "banner": record.get("data", {}).get("banner", "")[:200],
                        "source": "rapid7_sonar",
                        "country": country_code.upper(),
                        "collected_at": datetime.now(timezone.utc).isoformat(),
                    }
                    findings.append(finding)

                    if match_count % 100 == 0:
                        print(f"   Found {match_count} matches...")

    except Exception as e:
        print(f"   Error processing file: {e}")

    print(f"\n📊 Scanned {line_count:,} lines | Found {match_count} matches for {country_code.upper()}")
    return findings


def save_sonar_findings(findings, country_code):
    """Save filtered Sonar findings."""
    out_dir = Path("data/sonar")
    out_dir.mkdir(parents=True, exist_ok=True)

    filepath = out_dir / f"{country_code.lower()}_sonar.json"
    with open(filepath, "w") as f:
        json.dump(findings, f, indent=2)

    print(f"💾 Saved {len(findings)} findings to {filepath}")
    return filepath


def summarize_findings(findings):
    """Print a summary of what was found."""
    if not findings:
        print("   No findings.")
        return

    ports = {}
    for f in findings:
        p = f.get("port", "unknown")
        ports[p] = ports.get(p, 0) + 1

    print("\n📈 Port distribution:")
    for port, count in sorted(ports.items(), key=lambda x: -x[1])[:10]:
        print(f"   Port {port}: {count} hosts")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Process Rapid7 Project Sonar data for African countries")
    parser.add_argument("--country", default="ng", help="Country code")
    parser.add_argument("--file", required=True, help="Path to Sonar .json.gz file")
    parser.add_argument("--max-lines", type=int, default=500000, help="Max lines to scan")
    args = parser.parse_args()

    findings = process_sonar_file(args.file, args.country, args.max_lines)
    if findings:
        save_sonar_findings(findings, args.country)
        summarize_findings(findings)
    else:
        print("\n⚠️  No findings. Either the file has no matches, or RIPE data is missing.")
        print("   Download Sonar data from: https://opendata.rapid7.com/")
