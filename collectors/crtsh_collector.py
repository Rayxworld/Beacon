"""Collect certificate names from crt.sh without an API key."""

import json
import time
from pathlib import Path

import requests


def _certificate_domains(response, root_domain=None):
    domains = set()
    suffix = f".{root_domain}" if root_domain else None
    for item in response:
        for value in str(item.get("name_value", "")).splitlines():
            value = value.strip().lower().removeprefix("*.")
            if value and " " not in value and (not suffix or value == root_domain or value.endswith(suffix)):
                domains.add(value)
    return sorted(domains)


def collect_domain_domains_detailed(domain):
    """Collect certificate names with source availability and status metadata."""
    domain = domain.strip().lower().removeprefix("www.").rstrip(".")
    discovered = {domain}
    request = {
        "params": {"q": f"%.{domain}", "output": "json"},
        "headers": {"User-Agent": "Africa-Exposed/1.0 (Academic Research; Passive Measurement)"},
        "timeout": 45,
    }
    status = "unavailable"
    for attempt in range(3):
        try:
            response = requests.get("https://crt.sh/", **request)
            if response.status_code == 200:
                try:
                    parsed = response.json()
                    cert_names = _certificate_domains(parsed, domain)
                    discovered.update(cert_names)
                    return {
                        "domains": sorted(discovered),
                        "certificate_source_available": True,
                        "status": "success",
                        "discovered_count": len(discovered),
                    }
                except ValueError:
                    return {
                        "domains": sorted(discovered),
                        "certificate_source_available": False,
                        "status": "invalid_json_response",
                        "discovered_count": len(discovered),
                    }
            if response.status_code == 429:
                status = "rate_limited"
            elif response.status_code in (500, 502, 503, 504):
                status = f"upstream_server_error_{response.status_code}"
            else:
                response.raise_for_status()
        except requests.RequestException as error:
            status = f"request_error_{type(error).__name__}"
            if attempt == 2:
                print(f"   crt.sh unavailable for {domain}: {error}")
        if attempt < 2:
            time.sleep(2 ** attempt)
    return {
        "domains": sorted(discovered),
        "certificate_source_available": False,
        "status": status,
        "discovered_count": len(discovered),
    }


def collect_domain_domains(domain):
    """Collect certificate names belonging to one authorized root domain."""
    return collect_domain_domains_detailed(domain)["domains"]


def collect_country_domains(country_code):
    request = {
        "params": {"q": f"%.{country_code.lower()}", "output": "json"},
        "headers": {"User-Agent": "Africa-Exposed/1.0"},
        "timeout": 45,
    }
    response = None
    for attempt in range(3):
        try:
            candidate = requests.get("https://crt.sh/", **request)
            if candidate.status_code == 200:
                response = candidate
                break
            if candidate.status_code not in (429, 500, 502, 503, 504):
                candidate.raise_for_status()
        except requests.RequestException as error:
            if attempt == 2:
                print(f"   crt.sh unavailable; continuing without certificate domains: {error}")
        if attempt < 2:
            time.sleep(2 ** attempt)
    if response is None:
        print(f"   crt.sh returned no usable response for .{country_code.lower()}")
        return []

    try:
        certificate_rows = response.json()
    except ValueError as error:
        print(f"   crt.sh returned invalid JSON; continuing without certificate domains: {error}")
        return []
    return _certificate_domains(certificate_rows)


def save_crtsh_data(domains, country_code, output_dir="data/crtsh"):
    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)
    output_path = path / f"{country_code.lower()}_domains.json"
    with output_path.open("w", encoding="utf-8") as stream:
        json.dump(sorted(set(domains)), stream, indent=2)
    return output_path
