"""
Independently validate saved DNS presence and record sets across multiple recursive resolvers.
Records timestamp-aware provenance, query status, TTLs, presence agreement, and Jaccard similarity.
"""

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path

import dns.exception
import dns.resolver
import dns.rcode

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")
DEFAULT_RESOLVERS = {
    "google": "8.8.8.8",
    "cloudflare": "1.1.1.1",
    "quad9": "9.9.9.9",
}


def _get_resolver(nameserver_ip, timeout=2.0, lifetime=3.5):
    res = dns.resolver.Resolver(configure=False)
    res.nameservers = [nameserver_ip]
    res.timeout = timeout
    res.lifetime = lifetime
    return res


def query_single_record(resolver_instance, domain, record_type):
    queried_at = datetime.now(timezone.utc).isoformat()
    resolver_ip = resolver_instance.nameservers[0] if resolver_instance.nameservers else "unknown"
    try:
        ans = resolver_instance.resolve(domain, record_type, raise_on_no_answer=False)
        ttl = ans.rrset.ttl if ans.rrset else None
        rcode = dns.rcode.to_text(ans.response.rcode()) if ans.response else "NOERROR"
        records = {str(v).strip().rstrip(".") for v in ans} if ans.rrset else set()
        return {
            "status": "NOERROR",
            "rcode": rcode,
            "queried_at": queried_at,
            "resolver": resolver_ip,
            "ttl": ttl,
            "records": sorted(records),
            "error": None,
        }
    except dns.resolver.NXDOMAIN:
        return {
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
            "status": "TIMEOUT",
            "rcode": "TIMEOUT",
            "queried_at": queried_at,
            "resolver": resolver_ip,
            "ttl": None,
            "records": [],
            "error": "Resolution lifetime expired",
        }
    except (dns.exception.DNSException, OSError) as exc:
        return {
            "status": "ERROR",
            "rcode": "ERROR",
            "queried_at": queried_at,
            "resolver": resolver_ip,
            "ttl": None,
            "records": [],
            "error": f"{type(exc).__name__}: {exc}",
        }


def validate_dns_file(dns_json_path, resolvers=None):
    path = Path(dns_json_path)
    if not path.exists():
        raise FileNotFoundError(f"DNS file not found: {path}")
    saved = json.loads(path.read_text(encoding="utf-8"))
    
    resolvers_map = resolvers or DEFAULT_RESOLVERS
    resolver_instances = {name: _get_resolver(ip) for name, ip in resolvers_map.items()}

    checks = []
    for item in saved:
        domain = item.get("domain", "")
        saved_records = item.get("records", {})
        for rt in RECORD_TYPES:
            expected = set(saved_records.get(rt, []))
            resolver_results = {}
            for res_name, res_inst in resolver_instances.items():
                obs = query_single_record(res_inst, domain, rt)
                obs_set = set(obs["records"])
                presence_agreed = (bool(expected) == bool(obs_set)) if obs["status"] == "NOERROR" else None
                jaccard = (
                    len(expected & obs_set) / len(expected | obs_set)
                    if (expected | obs_set)
                    else 1.0
                )
                resolver_results[res_name] = {
                    "status": obs["status"],
                    "records": obs["records"],
                    "ttl": obs["ttl"],
                    "presence_agreed": presence_agreed,
                    "jaccard": round(jaccard, 4) if obs["status"] == "NOERROR" else None,
                    "error": obs["error"],
                }
            checks.append({
                "domain": domain,
                "record_type": rt,
                "expected_present": bool(expected),
                "expected_records": sorted(expected),
                "resolvers": resolver_results,
            })
    return checks


def validate_manifest(manifest_path, target_root="data/targets", resolvers=None):
    manifest_rows = list(csv.DictReader(open(manifest_path, encoding="utf-8-sig")))
    all_checks = []
    resolvers_map = resolvers or DEFAULT_RESOLVERS
    resolver_instances = {name: _get_resolver(ip) for name, ip in resolvers_map.items()}

    for row in manifest_rows:
        domain = row["domain"].strip().lower()
        dns_file = Path(target_root) / domain / "dns.json"
        if not dns_file.exists():
            continue
        saved = json.loads(dns_file.read_text(encoding="utf-8"))
        for item in saved:
            d = item.get("domain", domain)
            saved_records = item.get("records", {})
            for rt in RECORD_TYPES:
                expected = set(saved_records.get(rt, []))
                res_obs = {}
                for res_name, res_inst in resolver_instances.items():
                    obs = query_single_record(res_inst, d, rt)
                    obs_set = set(obs["records"])
                    res_obs[res_name] = {
                        "status": obs["status"],
                        "records": obs["records"],
                        "ttl": obs["ttl"],
                        "presence_agreed": (bool(expected) == bool(obs_set)) if obs["status"] == "NOERROR" else None,
                        "jaccard": round(len(expected & obs_set) / len(expected | obs_set), 4) if (expected | obs_set) and obs["status"] == "NOERROR" else (1.0 if obs["status"] == "NOERROR" else None),
                        "error": obs["error"],
                    }
                all_checks.append({
                    "target_org": row["organization_id"],
                    "domain": d,
                    "record_type": rt,
                    "expected_present": bool(expected),
                    "expected_records": sorted(expected),
                    "resolvers": res_obs,
                })

    # Aggregate metrics across resolvers
    summary_by_resolver = {}
    for res_name in resolvers_map:
        valid_presence = [c["resolvers"][res_name]["presence_agreed"] for c in all_checks if c["resolvers"][res_name]["presence_agreed"] is not None]
        valid_jaccard = [c["resolvers"][res_name]["jaccard"] for c in all_checks if c["resolvers"][res_name]["jaccard"] is not None]
        timeouts = sum(c["resolvers"][res_name]["status"] == "TIMEOUT" for c in all_checks)
        summary_by_resolver[res_name] = {
            "nameserver": resolvers_map[res_name],
            "total_queries": len(all_checks),
            "successful_queries": len(valid_presence),
            "timeouts_or_transport_loss": timeouts,
            "presence_agreement_rate": round(sum(valid_presence) / len(valid_presence), 4) if valid_presence else None,
            "mean_jaccard_similarity": round(sum(valid_jaccard) / len(valid_jaccard), 4) if valid_jaccard else None,
        }

    return {
        "validated_at": datetime.now(timezone.utc).isoformat(),
        "total_checks": len(all_checks),
        "resolvers_evaluated": summary_by_resolver,
        "checks": all_checks[:20],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Beacon Multi-Resolver Validation Engine")
    parser.add_argument("--dns-json", help="Path to single target dns.json")
    parser.add_argument("--manifest", help="Path to study manifest (validates all target dns.json files)")
    parser.add_argument("--output", default="research/validation_results.json", help="Output path for validation summary")
    args = parser.parse_args()

    if args.manifest:
        summary = validate_manifest(args.manifest)
        Path(args.output).write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(f"Validation completed across all manifest targets. Saved to {args.output}")
        print(json.dumps(summary["resolvers_evaluated"], indent=2))
    elif args.dns_json:
        checks = validate_dns_file(args.dns_json)
        print(json.dumps(checks, indent=2))
    else:
        parser.error("Provide --manifest research/pilot_manifest.csv or --dns-json <path>")
