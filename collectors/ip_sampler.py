"""
AFRICA EXPOSED — IP Sampler
Generate representative IP samples from RIPE ranges for free enrichment.
"""

import json
import random
import ipaddress
from pathlib import Path


def parse_ripe_ranges(country_code):
    """Load RIPE data and extract all IPv4 prefixes."""
    ripe_file = Path(f"data/ripe/{country_code.lower()}_ripe.json")
    if not ripe_file.exists():
        return []

    with open(ripe_file) as f:
        data = json.load(f)

    prefixes = data.get("ipv4_prefixes", [])
    networks = []
    for p in prefixes:
        try:
            networks.append(ipaddress.ip_network(p, strict=False))
        except ValueError:
            continue
    return networks


def sample_from_network(network, count=5):
    """Sample N host IPs from a network, avoiding network/broadcast addresses."""
    hosts = list(network.hosts())
    if len(hosts) <= count:
        return [str(h) for h in hosts]
    # Pick evenly distributed samples
    step = max(1, len(hosts) // count)
    return [str(hosts[i]) for i in range(0, len(hosts), step)[:count]]


def generate_country_samples(country_code, samples_per_prefix=3, max_total=500):
    """Generate IP samples for a country."""
    networks = parse_ripe_ranges(country_code)
    if not networks:
        print(f"   No RIPE data for {country_code}")
        return []

    all_samples = []
    for net in networks:
        samples = sample_from_network(net, samples_per_prefix)
        all_samples.extend(samples)

    # Deduplicate and shuffle
    all_samples = list(set(all_samples))
    random.shuffle(all_samples)

    result = all_samples[:max_total]
    print(f"   Generated {len(result)} sample IPs from {len(networks)} prefixes")
    return result


def save_samples(ips, country_code):
    """Save sampled IPs to JSON."""
    out_dir = Path("data/samples")
    out_dir.mkdir(parents=True, exist_ok=True)

    filepath = out_dir / f"{country_code.lower()}_samples.json"
    with open(filepath, "w") as f:
        json.dump(ips, f, indent=2)

    print(f"💾 Saved {len(ips)} samples to {filepath}")
    return filepath


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--country", default="ng")
    parser.add_argument("--per-prefix", type=int, default=3)
    parser.add_argument("--max", type=int, default=500)
    args = parser.parse_args()

    samples = generate_country_samples(args.country, args.per_prefix, args.max)
    if samples:
        save_samples(samples, args.country)
