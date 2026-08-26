"""Collect country resource allocations from the RIPE Stat API."""

import json
from datetime import datetime, timezone
from pathlib import Path

import requests


AFRICAN_COUNTRIES = {
    "dz": "Algeria",
    "ao": "Angola",
    "bj": "Benin",
    "bw": "Botswana",
    "bf": "Burkina Faso",
    "bi": "Burundi",
    "cv": "Cabo Verde",
    "cm": "Cameroon",
    "cf": "Central African Republic",
    "td": "Chad",
    "km": "Comoros",
    "cg": "Republic of the Congo",
    "cd": "Democratic Republic of the Congo",
    "ci": "Cote d'Ivoire",
    "dj": "Djibouti",
    "eg": "Egypt",
    "gq": "Equatorial Guinea",
    "er": "Eritrea",
    "sz": "Eswatini",
    "et": "Ethiopia",
    "ga": "Gabon",
    "gm": "Gambia",
    "gh": "Ghana",
    "gn": "Guinea",
    "gw": "Guinea-Bissau",
    "ke": "Kenya",
    "ls": "Lesotho",
    "lr": "Liberia",
    "ly": "Libya",
    "mg": "Madagascar",
    "mw": "Malawi",
    "ml": "Mali",
    "mr": "Mauritania",
    "mu": "Mauritius",
    "ma": "Morocco",
    "mz": "Mozambique",
    "na": "Namibia",
    "ne": "Niger",
    "ng": "Nigeria",
    "rw": "Rwanda",
    "st": "Sao Tome and Principe",
    "sn": "Senegal",
    "sc": "Seychelles",
    "sl": "Sierra Leone",
    "so": "Somalia",
    "za": "South Africa",
    "ss": "South Sudan",
    "sd": "Sudan",
    "tz": "Tanzania",
    "tg": "Togo",
    "tn": "Tunisia",
    "ug": "Uganda",
    "zm": "Zambia",
    "zw": "Zimbabwe",
}

RIPE_COUNTRY_RESOURCE_URL = "https://stat.ripe.net/data/country-resource-list/data.json"


def collect_country(country_code):
    """Fetch IPv4, IPv6, and ASN allocations for an ISO country code."""
    code = country_code.lower()
    if code not in AFRICAN_COUNTRIES:
        raise ValueError(f"Unsupported African country code: {country_code}")

    response = requests.get(
        RIPE_COUNTRY_RESOURCE_URL,
        params={"resource": code.upper()},
        timeout=30,
    )
    response.raise_for_status()
    resources = response.json().get("data", {}).get("resources", {})
    ipv4_prefixes = resources.get("ipv4", [])
    ipv6_prefixes = resources.get("ipv6", [])
    asns = resources.get("asn", [])

    return {
        "country_code": code.upper(),
        "country_name": AFRICAN_COUNTRIES[code],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ipv4_prefixes": ipv4_prefixes,
        "ipv6_prefixes": ipv6_prefixes,
        "asns": asns,
        "stats": {
            "ipv4_count": len(ipv4_prefixes),
            "ipv6_count": len(ipv6_prefixes),
            "asn_count": len(asns),
        },
    }


def save_ripe_data(data, country_code):
    """Save a RIPE snapshot under data/ripe and return its path."""
    output_dir = Path("data/ripe")
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{country_code.lower()}_ripe.json"
    with output_path.open("w", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2)
    return output_path
