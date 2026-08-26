from collectors.domain_utils import get_registrable_domain, normalize_domain
"""Beacon public exposure intelligence dashboard."""

import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from collectors.ripe_collector import AFRICAN_COUNTRIES
from collectors.findings_engine import disclosure_draft


def read_json(path):
    try:
        with path.open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError):
        return None


def read_text(path):
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def load_data():
    records = {
        code.upper(): {
            "code": code.upper(), "name": name, "ipv4": 0, "ipv6": 0, "asns": 0,
            "domains": 0, "subdomains": 0, "dns": [], "subdomain_records": [], "collected": False,
        }
        for code, name in AFRICAN_COUNTRIES.items()
    }
    for path in (DATA_DIR / "ripe").glob("*_ripe.json"):
        raw = read_json(path) or {}
        code = str(raw.get("country_code", path.stem.replace("_ripe", ""))).upper()
        if code not in records:
            continue
        stats = raw.get("stats", {})
        records[code].update({
            "ipv4": stats.get("ipv4_count", 0), "ipv6": stats.get("ipv6_count", 0),
            "asns": stats.get("asn_count", 0), "collected": True,
            "last_updated": raw.get("timestamp", ""),
        })
    for code, record in records.items():
        stem = code.lower()
        record["domains"] = len(read_json(DATA_DIR / "crtsh" / f"{stem}_domains.json") or [])
        record["dns"] = read_json(DATA_DIR / "dns" / f"{stem}_dns.json") or []
        subdomains = read_json(DATA_DIR / "subdomains" / f"{stem}_subdomains.json") or []
        record["subdomain_records"] = [item for domain in subdomains for item in domain.get("records", [])]
        record["subdomains"] = len(record["subdomain_records"])
        record["footprint"] = record["domains"] + record["subdomains"]
    return pd.DataFrame(records.values())


def email_stats(dns_data):
    total = len(dns_data)
    spf = sum(item.get("security", {}).get("has_spf", False) for item in dns_data)
    dmarc = sum(item.get("security", {}).get("has_dmarc", False) for item in dns_data)
    neither = sum(not item.get("security", {}).get("has_spf", False) and not item.get("security", {}).get("has_dmarc", False) for item in dns_data)
    return {"domains": total, "spf": spf, "dmarc": dmarc, "neither": neither}


def providers(dns_data):
    counts = Counter()
    for item in dns_data:
        for record_type in ("NS", "MX"):
            for value in item.get("records", {}).get(record_type, []):
                val_parts = value.rstrip(".").split()
                host = val_parts[-1] if val_parts else value
                try:
                    counts[get_registrable_domain(host)] += 1
                except ValueError:
                    pass
    return pd.DataFrame(counts.most_common(15), columns=["Provider", "Records"])


def load_target(domain):
    target_dir = DATA_DIR / "targets" / domain
    return {
        "domain": domain,
        "report": read_json(target_dir / "report.json") or {},
        "dns": read_json(target_dir / "dns.json") or [],
        "subdomains": read_json(target_dir / "subdomains.json") or [],
    }


def make_story(country):
    stats = email_stats(country["dns"])
    total = stats["domains"] or 1
    spf_pct = round(stats["spf"] / total * 100)
    dmarc_pct = round(stats["dmarc"] / total * 100)
    return f"""# BEACON: {country['name']}'s DNS Footprint

**Published:** {datetime.now(timezone.utc).strftime('%B %d, %Y')}  
**Classification:** PUBLIC - Open Source Intelligence

## Executive Summary

Public certificate records identified **{country['domains']:,} domains** and DNS enumeration resolved **{country['subdomains']:,} subdomains**. This is an exposure indicator, not a complete security assessment.

## Email Security

- SPF present: **{spf_pct}%** of collected domains
- DMARC present: **{dmarc_pct}%** of collected domains
- Domains missing both: **{stats['neither']:,}**

## Methodology

Data came from RIPE Stat, crt.sh, public DNS resolvers, and Shodan InternetDB. No paid subscriptions or API keys are required for core functionality. DNS records may change and should be validated privately before remediation.
"""


st.set_page_config(page_title="Beacon | Public Exposure Intelligence", page_icon="🌍", layout="wide")
st.markdown("""<style>
.stApp { background: #080b10; color: #e6edf3; }
h1, h2, h3 { letter-spacing: -0.03em; }
[data-testid="stMetric"] { background: #10161e; border: 1px solid #202b38; padding: 14px; }
.muted { color: #8190a0; }
</style>""", unsafe_allow_html=True)

df = load_data()
st.title("BEACON")
st.markdown('<p class="muted">Africa-first public exposure intelligence for organizations.</p>', unsafe_allow_html=True)

target_dirs = sorted(path for path in (DATA_DIR / "targets").glob("*") if path.is_dir())
study_data = read_json(ROOT / "research" / "dataset.json") or {}
if target_dirs:
    st.header("Organization exposure report")
    selected_target = st.selectbox("Organization domain", [path.name for path in target_dirs])
    target = load_target(selected_target)
    report = target["report"]
    target_metrics = st.columns(5)
    posture_data = report.get("posture", {})
    target_metrics[0].metric("Posture", posture_data.get("label", "Not scored"))
    target_metrics[1].metric("Score", f"{posture_data.get('score', 0)}/100")
    target_metrics[2].metric("Findings", posture_data.get("finding_count", 0))
    target_metrics[3].metric("New findings", report.get("changes", {}).get("new_findings", 0))
    target_metrics[4].metric("Resolved", report.get("changes", {}).get("resolved_findings", 0))
    st.subheader("Measurement categories")
    category_columns = st.columns(4)
    category_labels = {
        "email_security": "Email security",
        "asset_visibility": "Asset visibility",
        "public_service_observations": "Public service observations",
        "measurement_quality": "Measurement quality",
    }
    for column, (key, label) in zip(category_columns, category_labels.items()):
        category = report.get("categories", {}).get(key, {})
        score = category.get("score")
        column.metric(label, f"{score}/100" if score is not None else "Not measured")
    st.subheader("Actionable findings")
    findings = report.get("findings", [])
    if findings:
        for finding in sorted(findings, key=lambda item: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(item.get("severity"), 4)):
            with st.expander(f"{finding.get('severity', 'info').upper()} · {finding.get('title', 'Finding')}"):
                st.write(finding.get("description", ""))
                st.caption(f"Evidence: {finding.get('evidence', 'Not recorded')}")
                st.write(f"Recommended action: {finding.get('recommendation', '')}")
    else:
        st.success("No actionable findings from the available public observations.")
    st.download_button("Download exposure report", json.dumps(report, indent=2), file_name=f"beacon-{selected_target}-report.json", mime="application/json")
    st.download_button("Download Markdown report", read_text(DATA_DIR / "targets" / selected_target / "report.md") or "Report not generated yet.", file_name=f"beacon-{selected_target}-report.md", mime="text/markdown")
    st.download_button("Download HTML report", read_text(DATA_DIR / "targets" / selected_target / "report.html") or "Report not generated yet.", file_name=f"beacon-{selected_target}-report.html", mime="text/html")
    st.download_button("Download disclosure draft", disclosure_draft(report), file_name=f"beacon-{selected_target}-disclosure.txt", mime="text/plain")
    target_email = email_stats(target["dns"])
    email_total = target_email["domains"] or 1
    st.subheader("Email security")
    st.dataframe(pd.DataFrame([{
        "Domain": selected_target,
        "Domains checked": target_email["domains"],
        "SPF coverage": f"{round(target_email['spf'] / email_total * 100)}%",
        "DMARC coverage": f"{round(target_email['dmarc'] / email_total * 100)}%",
        "Missing both": target_email["neither"],
    }]), use_container_width=True, hide_index=True)
    target_records = [item for group in target["subdomains"] for item in group.get("records", [])]
    st.subheader("Resolved subdomains")
    st.dataframe(pd.DataFrame(target_records), use_container_width=True, hide_index=True)
    st.divider()

if study_data.get("observations"):
    st.header("Research study")
    study_df = pd.DataFrame(study_data["observations"])
    study_metrics = st.columns(4)
    study_metrics[0].metric("Observations", len(study_df))
    study_metrics[1].metric("Countries", study_df["country"].nunique())
    study_metrics[2].metric("Sectors", study_df["sector"].nunique())
    study_metrics[3].metric("Collection date", study_data.get("metadata", {}).get("collection_date", "unknown"))
    study_tab_country, study_tab_sector, study_tab_data = st.tabs(["Country comparison", "Sector comparison", "Dataset"])
    with study_tab_country:
        country_view = study_df.groupby("country", as_index=False).agg(
            Organizations=("domain_hash", "count"),
            Mean_subdomains=("subdomain_count", "mean"),
            Mean_IPs=("discovered_ip_count", "mean"),
            SPF_rate=("has_spf", "mean"),
            DMARC_rate=("has_dmarc", "mean"),
        )
        st.dataframe(country_view.round(3), use_container_width=True, hide_index=True)
    with study_tab_sector:
        sector_view = study_df.groupby("sector", as_index=False).agg(
            Organizations=("domain_hash", "count"),
            Mean_subdomains=("subdomain_count", "mean"),
            Mean_IPs=("discovered_ip_count", "mean"),
            SPF_rate=("has_spf", "mean"),
            DMARC_rate=("has_dmarc", "mean"),
        )
        st.dataframe(sector_view.round(3), use_container_width=True, hide_index=True)
    with study_tab_data:
        st.dataframe(study_df, use_container_width=True, hide_index=True)

if not df["collected"].any() and not target_dirs:
    st.warning("No RIPE data collected yet. Run `python africa_exposed.py --country ng --collect --dns --subdomains`.")
    st.stop()

st.caption("Sources: RIPE Stat, crt.sh, public DNS, Shodan InternetDB. No paid subscriptions or API keys required for core functionality.")
metrics = st.columns(5)
metrics[0].metric("Countries mapped", f"{int(df['collected'].sum())} / {len(df)}")
metrics[1].metric("Digital footprint", f"{int(df['footprint'].sum()):,}")
metrics[2].metric("Certificate domains", f"{int(df['domains'].sum()):,}")
metrics[3].metric("Subdomains", f"{int(df['subdomains'].sum()):,}")
metrics[4].metric("IPv4 prefixes", f"{int(df['ipv4'].sum()):,}")

tab_map, tab_email, tab_subdomains, tab_providers, tab_story = st.tabs(["Digital footprint", "Email security", "Subdomain exposure", "Infrastructure providers", "Story generator"])

with tab_map:
    fig = px.choropleth(df, locations="code", color="footprint", hover_name="name", scope="africa", color_continuous_scale=["#16212d", "#2d8290", "#ff5470"], title="Digital footprint by country")
    fig.update_traces(hovertemplate="%{hovertext}<br>Digital footprint: %{z:,}<extra></extra>")
    fig.update_layout(paper_bgcolor="#080b10", plot_bgcolor="#080b10", font_color="#d9e2ec", height=520)
    st.plotly_chart(fig, use_container_width=True)

with tab_email:
    rows = []
    for _, country in df.iterrows():
        stats = email_stats(country["dns"])
        total = stats["domains"] or 1
        rows.append({"Country": country["name"], "Domains checked": stats["domains"], "SPF": round(stats["spf"] / total * 100), "DMARC": round(stats["dmarc"] / total * 100), "Missing both": stats["neither"]})
    email_df = pd.DataFrame(rows).sort_values("DMARC", ascending=False)
    st.dataframe(email_df, use_container_width=True, hide_index=True)
    selected = st.selectbox("Email security country", df["name"].tolist(), key="email_country")
    selected_country = df.loc[df["name"] == selected].iloc[0]
    stats = email_stats(selected_country["dns"])
    st.bar_chart(pd.DataFrame({"Domains": [stats["spf"], stats["dmarc"], stats["neither"]]}, index=["SPF present", "DMARC present", "Missing both"]))

with tab_subdomains:
    ranked = df.sort_values("subdomains", ascending=False)[["name", "subdomains", "domains", "footprint"]].copy()
    ranked.columns = ["Country", "Resolved subdomains", "Certificate domains", "Digital footprint"]
    st.dataframe(ranked, use_container_width=True, hide_index=True)
    st.subheader("Vulnerable subdomain labels")
    vulnerable = {"admin", "dev", "test", "staging", "api"}
    rows = []
    for _, country in df.iterrows():
        for item in country["subdomain_records"]:
            if item.get("subdomain", "").split(".")[0] in vulnerable:
                rows.append({"Country": country["name"], "Subdomain": item["subdomain"], "IP": item["ip"], "Record": item["record_type"]})
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

with tab_providers:
    all_dns = [item for _, country in df.iterrows() for item in country["dns"]]
    provider_df = providers(all_dns)
    st.dataframe(provider_df, use_container_width=True, hide_index=True)
    if not provider_df.empty:
        st.bar_chart(provider_df.set_index("Provider"))

with tab_story:
    story_country = st.selectbox("Report country", df["name"].tolist(), key="story_country")
    country = df.loc[df["name"] == story_country].iloc[0]
    story = make_story(country)
    st.download_button("Download Markdown report", story, file_name=f"beacon-{story_country.lower().replace(' ', '-')}.md", mime="text/markdown")
    st.markdown(story)
