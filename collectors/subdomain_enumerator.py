"""Enumerate common subdomains with DNS-only lookups and wildcard detection."""

import json
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path

import dns.exception
import dns.resolver

from collectors.domain_utils import normalize_domain

WORDLIST = (
    "www mail ftp admin api dev test staging portal vpn remote git jenkins wp blog shop app dashboard cpanel webmail mx ns smtp pop imap webdisk whm cpcalendars cpcontacts autodiscover autoconfig m mobile old new beta alpha demo sandbox internal intranet secure private public files docs drive cloud storage backup db database sql mongo redis elastic kafka rabbitmq graphql rest soap ws websocket socket io wss mqtt coap grpc thrift"
).split()
PUBLIC_RESOLVERS = ("8.8.8.8", "1.1.1.1")


def _resolver(resolver_ip=None):
    res = dns.resolver.Resolver(configure=False)
    res.nameservers = [resolver_ip] if resolver_ip else list(PUBLIC_RESOLVERS)
    res.timeout = 1.5
    res.lifetime = 3.0
    return res


def _lookup(resolver, name, record_type):
    try:
        answer = resolver.resolve(name, record_type, raise_on_no_answer=False)
        if answer.rrset:
            return [str(value).strip().rstrip(".") for value in answer]
    except (dns.exception.DNSException, OSError):
        pass
    return []


def enumerate_domain(domain, delay=0.2, resolver_instance=None):
    domain = normalize_domain(domain)
    res = resolver_instance or _resolver()
    wildcard_name = f"wildcard-{secrets.token_hex(8)}.{domain}"
    wildcard_addresses = _lookup(res, wildcard_name, "A") + _lookup(res, wildcard_name, "AAAA")
    time.sleep(delay)
    records = []
    for label in WORDLIST:
        subdomain = f"{label}.{domain}"
        for record_type in ("A", "AAAA"):
            addresses = _lookup(res, subdomain, record_type)
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
        "enumerated_at": datetime.now(timezone.utc).isoformat(),
    }


def enumerate_domains(domains, delay=0.2, resolver_instance=None):
    results = []
    seen = set()
    for item in domains or []:
        try:
            d = normalize_domain(item)
            if d not in seen:
                seen.add(d)
                results.append(enumerate_domain(d, delay=delay, resolver_instance=resolver_instance))
        except ValueError:
            continue
    return results


def save_subdomain_data(results, country_code, output_dir="data/subdomains"):
    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)
    output_path = path / f"{country_code.lower()}_subdomains.json"
    with output_path.open("w", encoding="utf-8") as stream:
        json.dump(results, stream, indent=2)
    return output_path


def save_target_subdomain_data(results, domain, output_dir="data/targets"):
    path = Path(output_dir) / normalize_domain(domain)
    path.mkdir(parents=True, exist_ok=True)
    output_path = path / "subdomains.json"
    with output_path.open("w", encoding="utf-8") as stream:
        json.dump(results, stream, indent=2)
    return output_path
