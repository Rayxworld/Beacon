"""
Time-series change detection for Beacon longitudinal studies.
Compares organization security posture across multiple measurement periods.

Detects:
- Security improvements (DMARC/SPF adoption)
- Regressions (removed configurations)
- New exposure (subdomains, IPs)
- Remediation patterns (trends across sectors)
"""

import json
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


@dataclass
class MeasurementPeriod:
    """Represents a complete measurement for an organization at a point in time."""
    timestamp: str  # ISO 8601 format
    domain: str
    organization_id: str
    
    # Email security metrics
    spf_present: bool
    spf_enforced: bool  # -all vs ~all
    dmarc_present: bool
    dmarc_policy: Optional[str]  # reject, quarantine, none, absent
    
    # Infrastructure metrics
    certificate_count: int
    subdomain_count: int
    ipv4_count: int
    ipv6_count: int
    
    # Security posture
    finding_count: int
    high_priority_finding_count: int
    posture_score: float
    
    # Metadata
    measurement_source: str  # "beacon_pilot", "automated_scan", etc.


@dataclass
class ChangeDetectionResult:
    """Result of comparing two measurement periods."""
    domain: str
    organization_id: str
    period_start: str
    period_end: str
    
    # Email security changes
    spf_adoption: bool  # False -> True (improvement)
    spf_regression: bool  # True -> False (regression)
    spf_enforcement_improved: bool  # softfail -> hardfail
    spf_enforcement_regressed: bool  # hardfail -> softfail
    
    dmarc_adoption: bool  # False -> True
    dmarc_regression: bool  # True -> False
    dmarc_policy_change: Optional[str]  # "none" -> "reject", etc.
    
    # Infrastructure changes
    new_subdomains: int  # Count of newly discovered
    retired_subdomains: int  # Count no longer resolving
    new_ips: int
    retired_ips: int
    
    # Security posture changes
    posture_improvement: float  # Change in score
    new_findings: int
    resolved_findings: int
    high_priority_trend: str  # "improved", "stable", "regressed"
    
    # Summary
    change_count: int  # Total significant changes
    overall_trend: str  # "improving", "stable", "regressing"


class TimeSeriesAnalyzer:
    """Analyzes organizational security posture changes over time."""
    
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.history_dir = data_dir / "targets"
    
    def load_measurement(
        self,
        domain: str,
        timestamp: Optional[str] = None
    ) -> Optional[MeasurementPeriod]:
        """
        Load a measurement for a domain at a specific time.
        If timestamp is None, loads the most recent measurement.
        """
        target_dir = self.history_dir / domain
        
        if not target_dir.exists():
            return None
        
        history_dir = target_dir / "history"
        if not history_dir.exists():
            return None
        
        # Find all measurement files
        report_files = sorted(history_dir.glob("report_*.json"))
        
        if not report_files:
            return None
        
        # Select specific timestamp or latest
        if timestamp:
            matching = [f for f in report_files if timestamp in f.name]
            if not matching:
                return None
            report_file = matching[0]
        else:
            report_file = report_files[-1]
        
        try:
            with open(report_file) as f:
                data = json.load(f)
            
            return self._parse_report_to_measurement(data, domain)
        except (json.JSONDecodeError, KeyError):
            return None
    
    def _parse_report_to_measurement(self, report: dict, domain: str) -> MeasurementPeriod:
        """Convert a Beacon report to a MeasurementPeriod."""
        metadata = report.get("metadata", {})
        findings = report.get("findings", {})
        infrastructure = report.get("infrastructure", {})
        email_security = report.get("email_security", {})
        
        return MeasurementPeriod(
            timestamp=metadata.get("collection_date", datetime.now(timezone.utc).isoformat()),
            domain=domain,
            organization_id=metadata.get("organization_id", "unknown"),
            
            spf_present=bool(email_security.get("spf")),
            spf_enforced=email_security.get("spf_policy") == "hard" if email_security.get("spf") else False,
            dmarc_present=bool(email_security.get("dmarc")),
            dmarc_policy=email_security.get("dmarc_policy"),
            
            certificate_count=infrastructure.get("certificate_count", 0),
            subdomain_count=infrastructure.get("subdomain_count", 0),
            ipv4_count=infrastructure.get("ipv4_count", 0),
            ipv6_count=infrastructure.get("ipv6_count", 0),
            
            finding_count=len(findings.get("all", [])),
            high_priority_finding_count=len(findings.get("high_priority", [])),
            posture_score=metadata.get("posture_score", 0.0),
            
            measurement_source="beacon_report"
        )
    
    def compare_periods(
        self,
        domain: str,
        earlier_timestamp: Optional[str] = None,
        later_timestamp: Optional[str] = None
    ) -> Optional[ChangeDetectionResult]:
        """
        Compare two measurement periods for a domain.
        
        If timestamps are None, compares the two most recent measurements.
        """
        # Load both measurements
        earlier = self.load_measurement(domain, earlier_timestamp)
        later = self.load_measurement(domain, later_timestamp)
        
        if not earlier or not later:
            return None
        
        # Detect changes
        spf_adoption = not earlier.spf_present and later.spf_present
        spf_regression = earlier.spf_present and not later.spf_present
        spf_enforcement_improved = (
            earlier.spf_present and not earlier.spf_enforced and
            later.spf_present and later.spf_enforced
        )
        spf_enforcement_regressed = (
            earlier.spf_present and earlier.spf_enforced and
            later.spf_present and not later.spf_enforced
        )
        
        dmarc_adoption = not earlier.dmarc_present and later.dmarc_present
        dmarc_regression = earlier.dmarc_present and not later.dmarc_present
        dmarc_policy_change = (
            earlier.dmarc_policy if earlier.dmarc_policy != later.dmarc_policy
            else None
        )
        
        # Infrastructure changes
        new_subdomains = max(0, later.subdomain_count - earlier.subdomain_count)
        retired_subdomains = max(0, earlier.subdomain_count - later.subdomain_count)
        new_ips = max(0, later.ipv4_count + later.ipv6_count - 
                      earlier.ipv4_count - earlier.ipv6_count)
        retired_ips = max(0, earlier.ipv4_count + earlier.ipv6_count - 
                         later.ipv4_count - later.ipv6_count)
        
        # Security posture
        posture_improvement = later.posture_score - earlier.posture_score
        new_findings = max(0, later.finding_count - earlier.finding_count)
        resolved_findings = max(0, earlier.finding_count - later.finding_count)
        
        high_priority_trend = "improved" if later.high_priority_finding_count < earlier.high_priority_finding_count else (
            "regressed" if later.high_priority_finding_count > earlier.high_priority_finding_count else "stable"
        )
        
        # Count significant changes
        change_count = sum([
            int(spf_adoption), int(spf_regression),
            int(spf_enforcement_improved), int(spf_enforcement_regressed),
            int(dmarc_adoption), int(dmarc_regression),
            int(bool(dmarc_policy_change)),
            int(bool(new_subdomains)), int(bool(retired_subdomains)),
            int(bool(new_ips)), int(bool(retired_ips)),
            int(bool(resolved_findings)),
        ])
        
        overall_trend = (
            "improving" if (spf_adoption or dmarc_adoption or spf_enforcement_improved or 
                           resolved_findings > 0 or posture_improvement > 0) else
            "regressing" if (spf_regression or dmarc_regression or spf_enforcement_regressed or 
                           new_findings > 0 or posture_improvement < 0) else
            "stable"
        )
        
        return ChangeDetectionResult(
            domain=domain,
            organization_id=later.organization_id,
            period_start=earlier.timestamp,
            period_end=later.timestamp,
            spf_adoption=spf_adoption,
            spf_regression=spf_regression,
            spf_enforcement_improved=spf_enforcement_improved,
            spf_enforcement_regressed=spf_enforcement_regressed,
            dmarc_adoption=dmarc_adoption,
            dmarc_regression=dmarc_regression,
            dmarc_policy_change=dmarc_policy_change,
            new_subdomains=new_subdomains,
            retired_subdomains=retired_subdomains,
            new_ips=new_ips,
            retired_ips=retired_ips,
            posture_improvement=round(posture_improvement, 4),
            new_findings=new_findings,
            resolved_findings=resolved_findings,
            high_priority_trend=high_priority_trend,
            change_count=change_count,
            overall_trend=overall_trend,
        )
    
    def analyze_sector_trends(
        self,
        organizations: dict[str, str],  # {domain: sector}
        country: Optional[str] = None
    ) -> dict[str, Any]:
        """
        Analyze trends across all organizations in a sector/country.
        
        Args:
            organizations: Mapping of domain to sector
            country: Optional country filter
        
        Returns:
            Aggregated statistics on sector trends
        """
        trends_by_sector = defaultdict(lambda: {
            "organizations": [],
            "spf_improvement_rate": 0,
            "dmarc_improvement_rate": 0,
            "posture_avg_change": 0,
            "security_improving": 0,
            "security_stable": 0,
            "security_regressing": 0,
        })
        
        for domain, sector in organizations.items():
            comparison = self.compare_periods(domain)
            if not comparison:
                continue
            
            trends_by_sector[sector]["organizations"].append(domain)
            
            if comparison.spf_adoption or comparison.spf_enforcement_improved:
                trends_by_sector[sector]["spf_improvement_rate"] += 1
            
            if comparison.dmarc_adoption or (comparison.dmarc_policy_change and 
                                            comparison.dmarc_policy_change.endswith("reject")):
                trends_by_sector[sector]["dmarc_improvement_rate"] += 1
            
            trends_by_sector[sector]["posture_avg_change"] += comparison.posture_improvement
            
            if comparison.overall_trend == "improving":
                trends_by_sector[sector]["security_improving"] += 1
            elif comparison.overall_trend == "stable":
                trends_by_sector[sector]["security_stable"] += 1
            else:
                trends_by_sector[sector]["security_regressing"] += 1
        
        # Normalize rates
        result = {}
        for sector, stats in trends_by_sector.items():
            n = len(stats["organizations"])
            if n > 0:
                result[sector] = {
                    "organization_count": n,
                    "spf_improvement_rate": stats["spf_improvement_rate"] / n,
                    "dmarc_improvement_rate": stats["dmarc_improvement_rate"] / n,
                    "posture_avg_change": round(stats["posture_avg_change"] / n, 4),
                    "security_improving_pct": stats["security_improving"] / n,
                    "security_stable_pct": stats["security_stable"] / n,
                    "security_regressing_pct": stats["security_regressing"] / n,
                    "organizations": stats["organizations"]
                }
        
        return dict(result)
    
    def generate_report(self, output_path: Path) -> None:
        """Generate comprehensive time-series analysis report."""
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "methodology": "Beacon time-series longitudinal study",
            "analysis": {
                "organizational_improvements": [],
                "sector_trends": {},
            }
        }
        
        # Analyze all organizations
        all_domains = [d.name for d in self.history_dir.iterdir() if d.is_dir()]
        
        for domain in all_domains:
            comparison = self.compare_periods(domain)
            if comparison:
                report["analysis"]["organizational_improvements"].append(asdict(comparison))
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"Time-series analysis report saved to {output_path}")
