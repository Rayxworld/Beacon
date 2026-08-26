"""Independently validate saved DNS presence observations."""

import argparse
import json
from pathlib import Path

import dns.exception
import dns.resolver


RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")


def resolver(nameserver):
    instance = dns.resolver.Resolver(configure=False)
    instance.nameservers = [nameserver]
    instance.timeout = 3
    instance.lifetime = 5
    return instance


def observed(resolver_instance, domain, record_type):
    try:
        answer = resolver_instance.resolve(domain, record_type, raise_on_no_answer=False)
        return {str(value).strip().rstrip(".") for value in answer} if answer.rrset else set()
    except (dns.exception.DNSException, OSError):
        return set()


def validate(path, nameserver="1.1.1.1"):
    saved = json.loads(Path(path).read_text(encoding="utf-8"))
    instance = resolver(nameserver)
    checks = []
    for item in saved:
        domain = item.get("domain", "")
        for record_type in RECORD_TYPES:
            expected = set(item.get("records", {}).get(record_type, []))
            actual = observed(instance, domain, record_type)
            checks.append({
                "domain": domain,
                "record_type": record_type,
                "expected_present": bool(expected),
                "actual_present": bool(actual),
                "presence_agreement": bool(expected) == bool(actual),
                "jaccard": round(len(expected & actual) / len(expected | actual), 4) if expected | actual else 1.0,
            })
    agreement = sum(item["presence_agreement"] for item in checks) / len(checks) if checks else 1.0
    return {"resolver": nameserver, "checks": len(checks), "presence_agreement": round(agreement, 4), "results": checks}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("dns_json", help="Saved target dns.json")
    parser.add_argument("--resolver", default="1.1.1.1")
    args = parser.parse_args()
    print(json.dumps(validate(args.dns_json, args.resolver), indent=2))
