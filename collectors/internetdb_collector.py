"""Shodan InternetDB enrichment for already discovered DNS addresses."""

import json
import time
from pathlib import Path

import requests


URL = "https://internetdb.shodan.io/{}"


def enrich_ips(ips, delay=1.0):
    results = []
    for ip in sorted({str(value) for value in ips if value}):
        try:
            response = requests.get(URL.format(ip), timeout=15)
            if response.status_code == 200:
                payload = response.json()
                payload.update({"ip": ip, "source": "internetdb", "found": True})
            else:
                payload = {"ip": ip, "source": "internetdb", "found": False}
        except (requests.RequestException, ValueError):
            payload = {"ip": ip, "source": "internetdb", "found": False}
        results.append(payload)
        time.sleep(delay)
    return results


def save_internetdb_data(results, country_code, output_dir="data/free_sources"):
    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)
    output_path = path / f"{country_code.lower()}_free.json"
    with output_path.open("w", encoding="utf-8") as stream:
        json.dump(results, stream, indent=2)
    return output_path


def save_target_internetdb_data(results, domain, output_dir="data/targets"):
    path = Path(output_dir) / domain
    path.mkdir(parents=True, exist_ok=True)
    output_path = path / "internetdb.json"
    with output_path.open("w", encoding="utf-8") as stream:
        json.dump(results, stream, indent=2)
    return output_path
