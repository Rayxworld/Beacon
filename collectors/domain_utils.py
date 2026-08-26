"""
Domain normalization and registrable-domain parsing utilities for Beacon.
Handles standard TLDs, multi-part country-code second-level domains (ccSLDs),
subdomains, punycode/IDN, and protocol stripping without naive split hacks.
"""

from urllib.parse import urlsplit
import idna

# Common and African-specific multi-part public suffixes (ccSLDs / SLDs)
MULTI_PART_SUFFIXES = {
    # Nigeria (.ng)
    "gov.ng", "edu.ng", "com.ng", "org.ng", "net.ng", "mil.ng", "sch.ng", "name.ng", "mobi.ng",
    # Ghana (.gh)
    "gov.gh", "edu.gh", "com.gh", "org.gh", "net.gh", "mil.gh", "biz.gh",
    # Kenya (.ke)
    "go.ke", "ac.ke", "co.ke", "or.ke", "ne.ke", "sc.ke", "me.ke", "mobi.ke", "info.ke",
    # South Africa (.za)
    "gov.za", "ac.za", "co.za", "org.za", "net.za", "mil.za", "edu.za", "web.za", "nom.za",
    # Egypt (.eg)
    "gov.eg", "edu.eg", "com.eg", "org.eg", "net.eg", "mil.eg", "sci.eg",
    # Tanzania (.tz)
    "go.tz", "ac.tz", "co.tz", "or.tz", "ne.tz", "mil.tz", "sc.tz", "hotel.tz", "info.tz",
    # General & International multi-part suffixes
    "co.uk", "gov.uk", "ac.uk", "org.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.in", "net.in", "org.in", "gen.in", "firm.in",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "gc.ca", "gov.bc.ca", "gov.on.ca", "gov.qc.ca",
}

DISALLOWED_CHARS = set(" \t\n\r/\\@:?#")


def normalize_domain(value):
    """
    Convert an input string (URL, FQDN, wildcard) into a clean lowercase ASCII domain.
    Strips schemes, paths, ports, credentials, www-prefixes, wildcards, and trailing dots.
    Converts internationalized domain names (IDNs) to ASCII punycode where applicable.
    """
    if not value or not isinstance(value, str):
        raise ValueError("Domain value must be a non-empty string")

    value = value.strip().lower()

    # Strip URL formatting if present
    if "://" in value or value.startswith("//"):
        parsed = urlsplit(value if "://" in value else f"//{value}")
        host = parsed.hostname or ""
    else:
        # Split off possible path or port if given as host:port/path
        host = value.split("/")[0].split(":")[0]

    # Clean leading wildcards and www
    host = host.rstrip(".")
    while host.startswith("*."):
        host = host[2:]
    if host.startswith("www."):
        host = host[4:]
    host = host.strip()

    if not host or any(c in DISALLOWED_CHARS for c in host):
        raise ValueError(f"Invalid domain format: {value}")

    # Convert IDN to punycode if unicode
    try:
        host = idna.encode(host).decode("ascii")
    except Exception:
        pass

    labels = host.split(".")
    if len(labels) < 2 or any(not label for label in labels):
        raise ValueError(f"Domain must have at least two valid labels: {value}")

    return host


def get_registrable_domain(domain):
    """
    Extract the effective registrable domain (eTLD+1) for a given hostname.
    Correctly recognizes ccSLDs (e.g. unilag.edu.ng -> unilag.edu.ng, mail.unilag.edu.ng -> unilag.edu.ng).
    """
    normalized = normalize_domain(domain)
    labels = normalized.split(".")

    if len(labels) < 2:
        return normalized

    # Check 3-part suffix (e.g. gov.bc.ca)
    if len(labels) >= 4:
        three_part = ".".join(labels[-3:])
        if three_part in MULTI_PART_SUFFIXES:
            return ".".join(labels[-4:])

    # Check 2-part suffix (e.g. edu.ng, co.tz, gov.za)
    if len(labels) >= 3:
        two_part = ".".join(labels[-2:])
        if two_part in MULTI_PART_SUFFIXES:
            return ".".join(labels[-3:])

    # Standard 1-part TLD (e.g. example.com -> example.com, sub.example.com -> example.com)
    return ".".join(labels[-2:])


def is_same_registrable_domain(domain1, domain2):
    """
    Check whether two hostnames belong to the same registrable apex domain.
    """
    try:
        reg1 = get_registrable_domain(domain1)
        reg2 = get_registrable_domain(domain2)
        return reg1 == reg2
    except ValueError:
        return False
