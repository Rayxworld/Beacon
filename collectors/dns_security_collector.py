"""DNS security and infrastructure collection using public DNS resolvers with full provenance."""

import json
import time
from datetime import datetime, timezone
from pathlib import Path

import dns.exception
import dns.resolver
import dns.rcode

from collectors.domain_utils import normalize_domain, is_same_registrable_domain

DNS_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")
PUBLIC_RESOLVERS = ("8.8.8.8", "1.1.1.1")


def _resolver(resolver_ip=None):
    res = dns.resolver.Resolver(configure=False)
    res.nameservers = [resolver_ip] if resolver_ip else list(PUBLIC_RESOLVERS)
    res.timeout = 2.0
    res.lifetime = 3.5
    return res


def query_record_type(domain, record_type, resolver_instance=None):
    """
    Query a single DNS record type with complete execution provenance:
    - queried_at
    - resolver
    - status ('NOERROR', 'NXDOMAIN', 'SERVFAIL', 'TIMEOUT', 'ERROR')
    - rcode
    - error
    - ttl
    - records (list of strings)
    """
    res = resolver_instance or _resolver()
    queried_at = datetime.now(timezone.utc).isoformat()
    resolver_ip = res.nameservers[0] if res.nameservers else "system"

    try:
        ans = res.resolve(domain, record_type, raise_on_no_answer=False)
        ttl = ans.rrset.ttl if ans.rrset else None
        rcode_name = dns.rcode.to_text(ans.response.rcode()) if ans.response else "NOERROR"
        records = [str(v).strip().rstrip(".") for v in ans] if ans.rrset else []
        return {
            "record_type": record_type,
            "status": "NOERROR",
            "rcode": rcode_name,
            "queried_at": queried_at,
            "resolver": resolver_ip,
            "ttl": ttl,
            "records": records,
            "error": None,
        }
    except dns.resolver.NXDOMAIN:
        return {
            "record_type": record_type,
            "status": "NXDOMAIN",
            "rcode": "NXDOMAIN",
            "queried_at": queried_at,
            "resolver": resolver_ip,
            "ttl": None,
            "records": [],
            "error": None,
        }
    except dns.resolver.NoAnswer:
        return {
            "record_type": record_type,
            "status": "NOERROR",
            "rcode": "NOERROR",
            "queried_at": queried_at,
            "resolver": resolver_ip,
            "ttl": None,
            "records": [],
            "error": None,
        }
    except dns.resolver.LifetimeTimeout:
        return {
            "record_type": record_type,
            "status": "TIMEOUT",
            "rcode": "TIMEOUT",
            "queried_at": queried_at,
            "resolver": resolver_ip,
            "ttl": None,
            "records": [],
            "error": "Query resolution lifetime expired",
        }
    except (dns.exception.DNSException, OSError) as exc:
        return {
            "record_type": record_type,
            "status": "ERROR",
            "rcode": "ERROR",
            "queried_at": queried_at,
            "resolver": resolver_ip,
            "ttl": None,
            "records": [],
            "error": f"{type(exc).__name__}: {exc}",
        }


def parse_spf(txt_records, txt_status):
    """
    Parse and validate SPF records according to RFC 7208:
    - Checks for multiple SPF records (RFC 7208 Section 3.2 violation)
    - Validates mechanism structure
    - Distinguishes absent, malformed, query_failed, strict, weak
    """
    if txt_status in ("TIMEOUT", "ERROR"):
        return {
            "has_spf": False,
            "spf_status": "query_failed",
            "spf_policy": None,
            "weak_spf": None,
            "spf_record": None,
            "error": "TXT query failed",
        }

    spf_records = [
        r.strip().strip('"').replace('" "', "")
        for r in txt_records
        if r.strip().strip('"').lower().startswith("v=spf1")
    ]
    if not spf_records:
        return {
            "has_spf": False,
            "spf_status": "absent",
            "spf_policy": "absent",
            "weak_spf": None,
            "spf_record": None,
            "error": None,
        }
    if len(spf_records) > 1:
        return {
            "has_spf": False,
            "spf_status": "malformed",
            "spf_policy": "multiple_records_prohibited",
            "weak_spf": None,
            "spf_record": spf_records[0],
            "error": f"Multiple SPF records found ({len(spf_records)}), violating RFC 7208 Section 3.2",
        }

    rec = spf_records[0]
    rec_lower = rec.lower()
    terms = rec_lower.split()
    all_mechanisms = [t for t in terms if t.endswith("all")]
    final_mech = all_mechanisms[-1] if all_mechanisms else ""

    if final_mech in ("-all",):
        weak_spf = False
        policy = "strict_hardfail"
    elif final_mech in ("~all",):
        weak_spf = True
        policy = "weak_softfail"
    elif final_mech in ("?all",):
        weak_spf = True
        policy = "weak_neutral"
    elif final_mech in ("+all", "all"):
        weak_spf = True
        policy = "permissive_all"
    else:
        weak_spf = True
        policy = "unspecified_all"

    return {
        "has_spf": True,
        "spf_status": "valid",
        "spf_policy": policy,
        "weak_spf": weak_spf,
        "spf_record": rec,
        "error": None,
    }


def parse_dmarc(dmarc_records, dmarc_status):
    """
    Parse and validate DMARC records according to RFC 7489:
    - Checks for multiple DMARC records (RFC 7489 Section 6.6.3 violation)
    - Validates p= tag (reject, quarantine, none)
    - Distinguishes absent, malformed, query_failed
    """
    if dmarc_status in ("TIMEOUT", "ERROR"):
        return {
            "has_dmarc": False,
            "dmarc_status": "query_failed",
            "dmarc_policy": "query_failed",
            "dmarc_enforced": False,
            "dmarc_record": None,
            "error": "DMARC TXT query failed",
        }

    valid_dmarcs = [
        r.strip().strip('"').replace('" "', "")
        for r in dmarc_records
        if r.strip().strip('"').lower().startswith("v=dmarc1")
    ]
    if not valid_dmarcs:
        return {
            "has_dmarc": False,
            "dmarc_status": "absent",
            "dmarc_policy": "absent",
            "dmarc_enforced": False,
            "dmarc_record": None,
            "error": None,
        }
    if len(valid_dmarcs) > 1:
        return {
            "has_dmarc": False,
            "dmarc_status": "malformed",
            "dmarc_policy": "multiple_records_prohibited",
            "dmarc_enforced": False,
            "dmarc_record": valid_dmarcs[0],
            "error": f"Multiple DMARC records found ({len(valid_dmarcs)}), violating RFC 7489 Section 6.6.3",
        }

    rec = valid_dmarcs[0]
    tags = {}
    for part in rec.split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            tags[k.strip().lower()] = v.strip().lower()

    p_policy = tags.get("p", "")
    if p_policy == "reject":
        policy = "reject"
        enforced = True
    elif p_policy == "quarantine":
        policy = "quarantine"
        enforced = True
    elif p_policy == "none":
        policy = "none"
        enforced = False
    else:
        policy = "malformed_missing_p_tag"
        enforced = False

    return {
        "has_dmarc": policy in ("reject", "quarantine", "none"),
        "dmarc_status": "valid" if policy in ("reject", "quarantine", "none") else "malformed",
        "dmarc_policy": policy,
        "dmarc_enforced": enforced,
        "dmarc_record": rec,
        "tags": tags,
        "error": None,
    }


def query_records_with_provenance(domain, delay=0.2, resolver_instance=None):
    domain = normalize_domain(domain)
    res = resolver_instance or _resolver()
    provenance = {}
    record_map = {}

    for rt in DNS_RECORD_TYPES:
        info = query_record_type(domain, rt, resolver_instance=res)
        provenance[rt] = info
        record_map[rt] = info["records"]
        time.sleep(delay)

    dmarc_info = query_record_type(f"_dmarc.{domain}", "TXT", resolver_instance=res)
    provenance["DMARC"] = dmarc_info
    record_map["DMARC"] = dmarc_info["records"]

    # Security Analysis
    spf_parsed = parse_spf(record_map.get("TXT", []), provenance["TXT"]["status"])
    dmarc_parsed = parse_dmarc(record_map.get("DMARC", []), dmarc_info["status"])

    mail_servers = record_map.get("MX", [])
    self_hosted_mail = any(is_same_registrable_domain(domain, server) for server in mail_servers)

    issues = []
    if not spf_parsed["has_spf"]:
        if spf_parsed["spf_status"] != "query_failed":
            issues.append("missing_spf" if spf_parsed["spf_status"] == "absent" else "malformed_spf")
    elif spf_parsed["weak_spf"]:
        issues.append("weak_spf")

    if not dmarc_parsed["has_dmarc"]:
        if dmarc_parsed["dmarc_status"] != "query_failed":
            issues.append("missing_dmarc" if dmarc_parsed["dmarc_status"] == "absent" else "malformed_dmarc")

    if self_hosted_mail:
        issues.append("self_hosted_mail")

    security = {
        "has_spf": spf_parsed["has_spf"],
        "spf_status": spf_parsed["spf_status"],
        "spf_policy": spf_parsed["spf_policy"],
        "weak_spf": spf_parsed["weak_spf"],
        "spf_record": spf_parsed["spf_record"],
        "has_dmarc": dmarc_parsed["has_dmarc"],
        "dmarc_status": dmarc_parsed["dmarc_status"],
        "dmarc_policy": dmarc_parsed["dmarc_policy"],
        "dmarc_enforced": dmarc_parsed["dmarc_enforced"],
        "dmarc_record": dmarc_parsed["dmarc_record"],
        "self_hosted_mail": self_hosted_mail,
        "issues": issues,
    }

    return {
        "domain": domain,
        "records": record_map,
        "provenance": provenance,
        "security": security,
        "collected_at": datetime.now(timezone.utc).isoformat(),
    }


def collect_domains(domains, delay=0.2, resolver_instance=None):
    results = []
    seen = set()
    for item in domains or []:
        try:
            d = normalize_domain(item)
            if d not in seen:
                seen.add(d)
                results.append(query_records_with_provenance(d, delay=delay, resolver_instance=resolver_instance))
        except ValueError:
            continue
    return results


def save_dns_data(results, country_code, output_dir="data/dns"):
    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)
    output_path = path / f"{country_code.lower()}_dns.json"
    with output_path.open("w", encoding="utf-8") as stream:
        json.dump(results, stream, indent=2)
    return output_path


def save_target_dns_data(results, domain, output_dir="data/targets"):
    path = Path(output_dir) / normalize_domain(domain)
    path.mkdir(parents=True, exist_ok=True)
    output_path = path / "dns.json"
    with output_path.open("w", encoding="utf-8") as stream:
        json.dump(results, stream, indent=2)
    return output_path
