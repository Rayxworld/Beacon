"""
Data quality validation and integrity checks for Beacon research datasets.
Ensures measurements are valid, consistent, and suitable for publication.
"""

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


@dataclass
class ValidationIssue:
    """Represents a data quality issue."""
    severity: str  # "error", "warning", "info"
    code: str  # Issue type identifier
    message: str
    domain: Optional[str] = None
    field: Optional[str] = None
    value: Optional[Any] = None
    recommendation: Optional[str] = None


class DataValidator:
    """Validates Beacon research data for quality and consistency."""
    
    def __init__(self):
        self.issues: list[ValidationIssue] = []
    
    def validate_organization_report(self, report: dict, domain: str) -> list[ValidationIssue]:
        """Validate a single organization report."""
        self.issues = []
        
        # Required fields
        self._validate_required_fields(report, domain)
        
        # Data type validations
        self._validate_metadata(report, domain)
        self._validate_findings(report, domain)
        self._validate_infrastructure(report, domain)
        self._validate_email_security(report, domain)
        
        # Cross-field consistency
        self._validate_consistency(report, domain)
        
        return self.issues
    
    def validate_dataset(self, dataset: list[dict]) -> list[ValidationIssue]:
        """Validate a full research dataset."""
        self.issues = []
        
        # Basic validation
        if not isinstance(dataset, list):
            self.issues.append(ValidationIssue(
                severity="error",
                code="DATASET_TYPE_ERROR",
                message="Dataset must be a list of records",
                value=type(dataset).__name__
            ))
            return self.issues
        
        if len(dataset) == 0:
            self.issues.append(ValidationIssue(
                severity="warning",
                code="EMPTY_DATASET",
                message="Dataset contains no records"
            ))
            return self.issues
        
        # Validate each record
        for i, record in enumerate(dataset):
            if not isinstance(record, dict):
                self.issues.append(ValidationIssue(
                    severity="error",
                    code="RECORD_TYPE_ERROR",
                    message=f"Record {i} is not a dictionary",
                    value=type(record).__name__
                ))
                continue
            
            domain = record.get("domain", f"record_{i}")
            self._validate_dataset_record(record, domain)
        
        # Dataset-level checks
        self._validate_dataset_consistency(dataset)
        self._validate_no_duplicates(dataset)
        
        return self.issues
    
    def _validate_required_fields(self, report: dict, domain: str) -> None:
        """Check that required top-level fields are present."""
        required = ["metadata", "findings", "infrastructure", "email_security"]
        for field in required:
            if field not in report:
                self.issues.append(ValidationIssue(
                    severity="error",
                    code="MISSING_FIELD",
                    message=f"Missing required field: {field}",
                    domain=domain,
                    field=field,
                    recommendation=f"Ensure {field} is present in all reports"
                ))
    
    def _validate_metadata(self, report: dict, domain: str) -> None:
        """Validate metadata section."""
        metadata = report.get("metadata", {})
        
        # Check collection_date format (ISO 8601)
        collection_date = metadata.get("collection_date")
        if collection_date and not self._is_iso8601(collection_date):
            self.issues.append(ValidationIssue(
                severity="warning",
                code="INVALID_DATE_FORMAT",
                message=f"collection_date not in ISO 8601 format",
                domain=domain,
                field="metadata.collection_date",
                value=collection_date,
                recommendation="Use YYYY-MM-DDTHH:MM:SSZ format"
            ))
        
        # Check posture_score range [0, 100]
        posture_score = metadata.get("posture_score")
        if posture_score is not None:
            if not isinstance(posture_score, (int, float)):
                self.issues.append(ValidationIssue(
                    severity="error",
                    code="INVALID_SCORE_TYPE",
                    message="posture_score must be numeric",
                    domain=domain,
                    field="metadata.posture_score",
                    value=type(posture_score).__name__
                ))
            elif not 0 <= posture_score <= 100:
                self.issues.append(ValidationIssue(
                    severity="error",
                    code="SCORE_OUT_OF_RANGE",
                    message=f"posture_score {posture_score} outside range [0, 100]",
                    domain=domain,
                    field="metadata.posture_score",
                    value=posture_score
                ))
    
    def _validate_findings(self, report: dict, domain: str) -> None:
        """Validate findings section."""
        findings = report.get("findings", {})
        
        # Should have "all" and "high_priority" keys
        if "all" not in findings:
            self.issues.append(ValidationIssue(
                severity="warning",
                code="MISSING_FINDINGS_ALL",
                message="findings.all key not found",
                domain=domain,
                field="findings.all"
            ))
        
        # Check that findings are lists
        for key in ["all", "high_priority"]:
            if key in findings and not isinstance(findings[key], list):
                self.issues.append(ValidationIssue(
                    severity="error",
                    code="FINDINGS_TYPE_ERROR",
                    message=f"findings.{key} must be a list",
                    domain=domain,
                    field=f"findings.{key}",
                    value=type(findings[key]).__name__
                ))
        
        # High priority should be subset of all
        all_count = len(findings.get("all", []))
        high_count = len(findings.get("high_priority", []))
        
        if high_count > all_count:
            self.issues.append(ValidationIssue(
                severity="error",
                code="FINDINGS_INCONSISTENCY",
                message=f"high_priority count ({high_count}) > all count ({all_count})",
                domain=domain,
                field="findings"
            ))
    
    def _validate_infrastructure(self, report: dict, domain: str) -> None:
        """Validate infrastructure metrics."""
        infra = report.get("infrastructure", {})
        
        # Count fields should be non-negative integers
        count_fields = [
            "certificate_count", "subdomain_count", "ipv4_count", 
            "ipv6_count", "mx_count", "ns_count"
        ]
        
        for field in count_fields:
            value = infra.get(field)
            if value is not None:
                if not isinstance(value, int):
                    self.issues.append(ValidationIssue(
                        severity="error",
                        code="INVALID_COUNT_TYPE",
                        message=f"infrastructure.{field} must be integer",
                        domain=domain,
                        field=f"infrastructure.{field}",
                        value=type(value).__name__
                    ))
                elif value < 0:
                    self.issues.append(ValidationIssue(
                        severity="error",
                        code="NEGATIVE_COUNT",
                        message=f"infrastructure.{field} cannot be negative",
                        domain=domain,
                        field=f"infrastructure.{field}",
                        value=value
                    ))
    
    def _validate_email_security(self, report: dict, domain: str) -> None:
        """Validate email security findings."""
        email = report.get("email_security", {})
        
        # SPF validation
        if "spf" in email:
            if not isinstance(email["spf"], bool):
                self.issues.append(ValidationIssue(
                    severity="error",
                    code="INVALID_SPF_TYPE",
                    message="email_security.spf must be boolean",
                    domain=domain,
                    field="email_security.spf"
                ))
        
        # DMARC validation
        if "dmarc" in email:
            if not isinstance(email["dmarc"], bool):
                self.issues.append(ValidationIssue(
                    severity="error",
                    code="INVALID_DMARC_TYPE",
                    message="email_security.dmarc must be boolean",
                    domain=domain,
                    field="email_security.dmarc"
                ))
        
        # DMARC policy validation
        dmarc_policy = email.get("dmarc_policy")
        if dmarc_policy and dmarc_policy not in ["reject", "quarantine", "none", "absent"]:
            self.issues.append(ValidationIssue(
                severity="error",
                code="INVALID_DMARC_POLICY",
                message=f"Invalid DMARC policy: {dmarc_policy}",
                domain=domain,
                field="email_security.dmarc_policy",
                value=dmarc_policy,
                recommendation="Use: reject, quarantine, none, or absent"
            ))
    
    def _validate_consistency(self, report: dict, domain: str) -> None:
        """Validate cross-field consistency."""
        email = report.get("email_security", {})
        
        # If DMARC policy is set, DMARC should be present
        if email.get("dmarc_policy") and email.get("dmarc_policy") != "absent":
            if not email.get("dmarc"):
                self.issues.append(ValidationIssue(
                    severity="warning",
                    code="DMARC_INCONSISTENCY",
                    message="dmarc_policy set but dmarc=false",
                    domain=domain,
                    field="email_security",
                    recommendation="If DMARC policy exists, dmarc should be true"
                ))
    
    def _validate_dataset_record(self, record: dict, domain: str) -> None:
        """Validate a single dataset record."""
        # Required fields for analysis
        required_fields = ["domain_hash", "country", "sector", "collection_date"]
        for field in required_fields:
            if field not in record:
                self.issues.append(ValidationIssue(
                    severity="error",
                    code="MISSING_DATASET_FIELD",
                    message=f"Missing required dataset field: {field}",
                    domain=domain,
                    field=field
                ))
        
        # Anonymization check: original domain names should NOT appear
        for key, value in record.items():
            if isinstance(value, str) and value.endswith(".com"):
                if not key.endswith("_hash"):
                    self.issues.append(ValidationIssue(
                        severity="warning",
                        code="POTENTIAL_DEANONYMIZATION",
                        message=f"Field '{key}' appears to contain domain name",
                        domain=domain,
                        field=key,
                        value=value,
                        recommendation="Ensure sensitive identifiers are hashed"
                    ))
    
    def _validate_dataset_consistency(self, dataset: list[dict]) -> None:
        """Validate consistency across entire dataset."""
        # Check for duplicate domain_hash values
        hashes = [r.get("domain_hash") for r in dataset if "domain_hash" in r]
        duplicates = [h for h, count in Counter(hashes).items() if count > 1]
        
        if duplicates:
            self.issues.append(ValidationIssue(
                severity="warning",
                code="DUPLICATE_HASHES",
                message=f"Found {len(duplicates)} duplicate domain hashes",
                value=duplicates[:5]  # Show first 5
            ))
        
        # Check for consistent structure
        if dataset:
            first_record = dataset[0]
            first_keys = set(first_record.keys())
            
            for i, record in enumerate(dataset[1:], start=1):
                if set(record.keys()) != first_keys:
                    self.issues.append(ValidationIssue(
                        severity="warning",
                        code="INCONSISTENT_STRUCTURE",
                        message=f"Record {i} has different fields than record 0",
                        value={"missing": first_keys - set(record.keys()), 
                               "extra": set(record.keys()) - first_keys}
                    ))
    
    def _validate_no_duplicates(self, dataset: list[dict]) -> None:
        """Check for duplicate records."""
        seen = set()
        duplicates = 0
        
        for record in dataset:
            # Create hashable representation
            record_str = json.dumps(record, sort_keys=True, default=str)
            if record_str in seen:
                duplicates += 1
            seen.add(record_str)
        
        if duplicates > 0:
            self.issues.append(ValidationIssue(
                severity="warning",
                code="DUPLICATE_RECORDS",
                message=f"Found {duplicates} duplicate records in dataset"
            ))
    
    @staticmethod
    def _is_iso8601(date_string: str) -> bool:
        """Check if string is in ISO 8601 format."""
        try:
            from datetime import datetime
            datetime.fromisoformat(date_string.replace('Z', '+00:00'))
            return True
        except (ValueError, AttributeError):
            return False


def generate_validation_report(issues: list[ValidationIssue], output_path: Path) -> None:
    """Generate a human-readable validation report."""
    report = {
        "total_issues": len(issues),
        "by_severity": Counter(i.severity for i in issues),
        "issues": [
            {
                "severity": i.severity,
                "code": i.code,
                "message": i.message,
                "domain": i.domain,
                "field": i.field,
                "recommendation": i.recommendation
            }
            for i in issues
        ]
    }
    
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\nValidation Report:")
    print(f"  Total issues: {report['total_issues']}")
    print(f"  Errors: {report['by_severity'].get('error', 0)}")
    print(f"  Warnings: {report['by_severity'].get('warning', 0)}")
    print(f"  Info: {report['by_severity'].get('info', 0)}")
    print(f"\nFull report saved to: {output_path}")
