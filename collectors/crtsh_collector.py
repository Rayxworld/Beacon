"""Collect certificate names from crt.sh with explicit provenance and query status."""

import json
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

from collectors.domain_utils import normalize_domain


def _certificate_domains(response, root_domain=None):
    domains = set()
    suffix = f".{root_domain}" if root_domain else None
    for item in response:
        for value in str(item.get("name_value", "")).splitlines():
            value = value.strip().lower().removeprefix("*.").rstrip(".")
            if value and " " not in value and (not suffix or value == root_domain or value.endswith(suffix)):
                domains.add(value)
    return sorted(domains)


def collect_domain_domains_detailed(domain, timeout=30, max_retries=3):
    """
    Collect certificate names with strict provenance separation:
    - query_status: 'success', 'empty', 'timeout', 'rate_limited', 'server_error', 'parse_error', 'network_error'
    - http_status: integer HTTP code or None
    - error: error description or None
    - result_count: count of discovered certificate names
    - query_timestamp: ISO-8601 UTC timestamp
    - fallback_used: True if fallback to root domain occurred
    - certificate_source_available: True if crt.sh responded validly
    """
    normalized = normalize_domain(domain)
    timestamp = datetime.now(timezone.utc).isoformat()
    request_params = {"q": f"%.{normalized}", "output": "json"}
    headers = {"User-Agent": "Beacon-Research/1.0 (Academic Passive Measurement; +https://github.com/Rayxworld/Beacon)"}

    last_error = None
    http_status = None
    status_code = "network_error"

    for attempt in range(max_retries):
        try:
            response = requests.get(
                "https://crt.sh/",
                params=request_params,
                headers=headers,
                timeout=timeout,
            )
            http_status = response.status_code
            if response.status_code == 200:
                try:
                    parsed = response.json()
                    if not parsed:
                        return {
                            "domain": normalized,
                            "domains": [normalized],
                            "certificate_query_status": "empty",
                            "certificate_http_status": 200,
                            "certificate_error": None,
                            "certificate_result_count": 0,
                            "certificate_source_available": True,
                            "certificate_query_timestamp": timestamp,
                            "fallback_used": True,
                        }
                    cert_names = _certificate_domains(parsed, normalized)
                    all_names = sorted(set(cert_names) | {normalized})
                    return {
                        "domain": normalized,
                        "domains": all_names,
                        "certificate_query_status": "success",
                        "certificate_http_status": 200,
                        "certificate_error": None,
                        "certificate_result_count": len(cert_names),
                        "certificate_source_available": True,
                        "certificate_query_timestamp": timestamp,
                        "fallback_used": False,
                    }
                except (ValueError, TypeError) as parse_err:
                    return {
                        "domain": normalized,
                        "domains": [normalized],
                        "certificate_query_status": "parse_error",
                        "certificate_http_status": 200,
                        "certificate_error": f"JSONDecodeError: {parse_err}",
                        "certificate_result_count": 0,
                        "certificate_source_available": False,
                        "certificate_query_timestamp": timestamp,
                        "fallback_used": True,
                    }
            elif response.status_code == 429:
                last_error = "Rate limit exceeded (HTTP 429)"
                status_code = "rate_limited"
            elif 500 <= response.status_code <= 599:
                last_error = f"Server error (HTTP {response.status_code})"
                status_code = "server_error"
            else:
                last_error = f"HTTP error {response.status_code}"
                status_code = "network_error"
        except requests.Timeout as err:
            last_error = f"Timeout after {timeout}s: {err}"
            status_code = "timeout"
        except requests.RequestException as err:
            last_error = f"Request error: {type(err).__name__}: {err}"
            status_code = "network_error"

        if attempt < max_retries - 1:
            time.sleep(2 ** attempt)

    return {
        "domain": normalized,
        "domains": [normalized],
        "certificate_query_status": status_code,
        "certificate_http_status": http_status,
        "certificate_error": last_error,
        "certificate_result_count": 0,
        "certificate_source_available": False,
        "certificate_query_timestamp": timestamp,
        "fallback_used": True,
    }


def collect_domain_domains(domain):
    """Collect certificate names belonging to one authorized root domain."""
    return collect_domain_domains_detailed(domain)["domains"]


def collect_country_domains(country_code):
    request = {
        "params": {"q": f"%.{country_code.lower()}", "output": "json"},
        "headers": {"User-Agent": "Beacon-Research/1.0"},
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
        return []

    try:
        certificate_rows = response.json()
    except ValueError as error:
        return []
    return _certificate_domains(certificate_rows)


def save_crtsh_data(domains, country_code, output_dir="data/crtsh"):
    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)
    output_path = path / f"{country_code.lower()}_domains.json"
    with output_path.open("w", encoding="utf-8") as stream:
        json.dump(sorted(set(domains)), stream, indent=2)
    return output_path
