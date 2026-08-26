"""Enumerate common subdomains with DNS-only lookups."""

import json
import secrets
import time
from pathlib import Path

import dns.exception
import dns.resolver


WORDLIST = (
    "www mail ftp admin api dev test staging portal vpn remote git jenkins wp blog shop app dashboard cpanel webmail mx ns smtp pop imap webdisk whm cpcalendars cpcontacts autodiscover autoconfig m mobile old new beta alpha demo sandbox internal intranet secure private public files docs drive cloud storage backup db database sql mongo redis elastic kafka rabbitmq graphql rest soap ws websocket socket io wss mqtt coap grpc thrift"
).split()
PUBLIC_RESOLVERS = ("8.8.8.8", "1.1.1.1")


def _resolver():
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = list(PUBLIC_RESOLVERS)
    resolver.timeout = 1.5
    resolver.lifetime = 3.0
    return resolver


def _lookup(resolver, name, record_type):
    try:
        answer = resolver.resolve(name, record_type, raise_on_no_answer=False)
        if answer.rrset:
            return [str(value).strip().rstrip(".") for value in answer]
    except (dns.exception.DNSException, OSError):
        pass
    return []


def enumerate_domain(domain, delay=0.5):
    domain = str(domain).strip().lower().removeprefix("*.").rstrip(".")
    resolver = _resolver()
    wildcard_name = f"wildcard-{secrets.token_hex(8)}.{domain}"
    wildcard_addresses = _lookup(resolver, wildcard_name, "A") + _lookup(resolver, wildcard_name, "AAAA")
    time.sleep(delay)
    records = []
    for label in WORDLIST:
        subdomain = f"{label}.{domain}"
        for record_type in ("A", "AAAA"):
            addresses = _lookup(resolver, subdomain, record_type)
            if addresses:
                records.extend({
                    "subdomain": subdomain,
                    "ip": address,
                    "record_type": record_type,
                    "wildcard": address in wildcard_addresses,
                } for address in addresses)
            time.sleep(delay)
    return {
        "domain": domain,
        "wildcard_enabled": bool(wildcard_addresses),
        "wildcard_addresses": wildcard_addresses,
        "records": records,
    }


def enumerate_domains(domains, delay=0.5):
    unique_domains = sorted({str(domain).strip().lower().removeprefix("*.").rstrip(".") for domain in domains or [] if domain})
    return [enumerate_domain(domain, delay=delay) for domain in unique_domains]


def save_subdomain_data(results, country_code, output_dir="data/subdomains"):
    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)
    output_path = path / f"{country_code.lower()}_subdomains.json"
    with output_path.open("w", encoding="utf-8") as stream:
        json.dump(results, stream, indent=2)
    return output_path


def save_target_subdomain_data(results, domain, output_dir="data/targets"):
    path = Path(output_dir) / domain
    path.mkdir(parents=True, exist_ok=True)
    output_path = path / "subdomains.json"
    with output_path.open("w", encoding="utf-8") as stream:
        json.dump(results, stream, indent=2)
    return output_path


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--country", required=True)
    args = parser.parse_args()
    source = Path("data/crtsh") / f"{args.country.lower()}_domains.json"
    with source.open(encoding="utf-8") as stream:
        domains = json.load(stream)
    save_subdomain_data(enumerate_domains(domains), args.country)
