"""DNS security and infrastructure collection using public DNS resolvers."""

import json
import time
from datetime import datetime, timezone
from pathlib import Path

import dns.exception
import dns.resolver


DNS_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")
PUBLIC_RESOLVERS = ("8.8.8.8", "1.1.1.1")


def _domain_from_item(item):
    if isinstance(item, str):
        return item.strip().lower().rstrip(".")
    if isinstance(item, dict):
        for key in ("name_value", "domain", "name"):
            value = item.get(key)
            if value:
                return str(value).strip().lower().rstrip(".")
    return ""


def normalise_domains(domains):
    result = set()
    for item in domains or []:
        for value in _domain_from_item(item).splitlines():
            value = value.removeprefix("*.")
            if value and " " not in value:
                result.add(value)
    return sorted(result)


def _resolver():
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = list(PUBLIC_RESOLVERS)
    resolver.timeout = 1.5
    resolver.lifetime = 3.0
    return resolver


def query_records(domain, delay=0.5):
    resolver = _resolver()
    records = {record_type: [] for record_type in DNS_RECORD_TYPES}
    for record_type in DNS_RECORD_TYPES:
        try:
            answer = resolver.resolve(domain, record_type, raise_on_no_answer=False)
            if answer.rrset:
                records[record_type] = [str(value).strip().rstrip(".") for value in answer]
        except (dns.exception.DNSException, OSError):
            pass
        time.sleep(delay)
    try:
        answer = resolver.resolve(f"_dmarc.{domain}", "TXT", raise_on_no_answer=False)
        if answer.rrset:
            records["DMARC"] = [str(value).strip().strip('"').replace('" "', "") for value in answer]
    except (dns.exception.DNSException, OSError):
        records["DMARC"] = []
    time.sleep(delay)
    return records


def _txt_values(records):
    return [value.strip().strip('"').replace('" "', "") for value in records.get("TXT", [])]


def analyse_security(domain, records):
    txt_records = _txt_values(records)
    spf = [value for value in txt_records if value.lower().startswith("v=spf1")]
    dmarc = [value for value in records.get("DMARC", []) if value.lower().startswith("v=dmarc1")]
    weak_spf = any("~all" in value.lower() or "?all" in value.lower() for value in spf)
    mail_servers = records.get("MX", [])
    domain_labels = domain.split(".")[-2:]
    registrable = ".".join(domain_labels)
    self_hosted_mail = any(registrable in server.lower() for server in mail_servers)
    issues = []
    if not spf:
        issues.append("missing_spf")
    if not dmarc:
        issues.append("missing_dmarc")
    if weak_spf:
        issues.append("weak_spf")
    if self_hosted_mail:
        issues.append("self_hosted_mail")
    return {
        "has_spf": bool(spf),
        "has_dmarc": bool(dmarc),
        "weak_spf": weak_spf,
        "self_hosted_mail": self_hosted_mail,
        "issues": issues,
    }


def collect_domains(domains, delay=0.5):
    results = []
    for domain in normalise_domains(domains):
        records = query_records(domain, delay=delay)
        results.append({
            "domain": domain,
            "records": records,
            "security": analyse_security(domain, records),
            "collected_at": datetime.now(timezone.utc).isoformat(),
        })
    return results


def save_dns_data(results, country_code, output_dir="data/dns"):
    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)
    output_path = path / f"{country_code.lower()}_dns.json"
    with output_path.open("w", encoding="utf-8") as stream:
        json.dump(results, stream, indent=2)
    return output_path


def save_target_dns_data(results, domain, output_dir="data/targets"):
    path = Path(output_dir) / domain
    path.mkdir(parents=True, exist_ok=True)
    output_path = path / "dns.json"
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
    save_dns_data(collect_domains(domains), args.country)
