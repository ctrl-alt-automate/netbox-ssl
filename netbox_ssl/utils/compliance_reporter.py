"""
Compliance reporting utility.

Generates compliance reports, creates trend snapshots, and exports data.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import date, timedelta
from typing import Any

from django.db.models import Count, F


class ComplianceReporter:
    """Generate compliance reports and manage trend snapshots."""

    def __init__(self) -> None:
        from netbox_ssl.models import (
            Certificate,
            ComplianceCheck,
            CompliancePolicy,
            ComplianceTrendSnapshot,
        )

        self.Certificate = Certificate
        self.ComplianceCheck = ComplianceCheck
        self.CompliancePolicy = CompliancePolicy
        self.ComplianceTrendSnapshot = ComplianceTrendSnapshot

    def generate_report(self, tenant: Any | None = None) -> dict[str, Any]:
        """Aggregate current compliance data into a report dict."""
        checks_qs = self.ComplianceCheck.objects.all()
        certs_qs = self.Certificate.objects.filter(status="active")

        if tenant is not None:
            checks_qs = checks_qs.filter(certificate__tenant=tenant)
            certs_qs = certs_qs.filter(tenant=tenant)

        total_certs = certs_qs.count()
        total_checks = checks_qs.count()
        passed = checks_qs.filter(result="pass").count()
        failed = checks_qs.filter(result="fail").count()
        errors = checks_qs.filter(result="error").count()

        score = (passed / total_checks * 100) if total_checks > 0 else 100.0

        # Breakdown by severity
        severity_breakdown = list(
            checks_qs.filter(result="fail")
            .annotate(severity=F("policy__severity"))
            .values("severity")
            .annotate(count=Count("id"))
            .order_by("severity")
        )

        # Breakdown by policy type
        policy_breakdown = list(
            checks_qs.filter(result="fail")
            .annotate(policy_type=F("policy__policy_type"))
            .values("policy_type")
            .annotate(count=Count("id"))
            .order_by("-count")
        )

        return {
            "snapshot_date": date.today(),
            "total_certificates": total_certs,
            "total_checks": total_checks,
            "passed_checks": passed,
            "failed_checks": failed,
            "error_checks": errors,
            "compliance_score": round(score, 2),
            "severity_breakdown": severity_breakdown,
            "policy_breakdown": policy_breakdown,
        }

    def create_snapshot(self, tenant: Any | None = None) -> Any:
        """Persist current compliance state as a trend snapshot."""
        report = self.generate_report(tenant)
        snapshot, _created = self.ComplianceTrendSnapshot.objects.update_or_create(
            tenant=tenant,
            snapshot_date=report["snapshot_date"],
            defaults={
                "total_certificates": report["total_certificates"],
                "total_checks": report["total_checks"],
                "passed_checks": report["passed_checks"],
                "failed_checks": report["failed_checks"],
                "compliance_score": report["compliance_score"],
                "details": {
                    "severity_breakdown": report["severity_breakdown"],
                    "policy_breakdown": report["policy_breakdown"],
                    "error_checks": report["error_checks"],
                },
            },
        )
        return snapshot

    def get_trend(self, tenant: Any | None = None, days: int = 90) -> list[dict[str, Any]]:
        """Get historical trend snapshots for the last N days."""
        cutoff = date.today() - timedelta(days=days)
        qs = self.ComplianceTrendSnapshot.objects.filter(
            snapshot_date__gte=cutoff,
        )
        qs = qs.filter(tenant=tenant) if tenant is not None else qs.filter(tenant__isnull=True)

        return list(
            qs.order_by("snapshot_date").values(
                "snapshot_date",
                "compliance_score",
                "total_certificates",
                "passed_checks",
                "failed_checks",
            )
        )

    def export_report(self, tenant: Any | None = None, format: str = "csv") -> str:
        """Export compliance report as CSV or JSON string."""
        report = self.generate_report(tenant)

        if format == "json":
            # Make date serializable
            report["snapshot_date"] = report["snapshot_date"].isoformat()
            return json.dumps(report, indent=2)

        # CSV format: one row per failed check detail
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(
            [
                "date",
                "total_certificates",
                "total_checks",
                "passed",
                "failed",
                "score",
            ]
        )
        writer.writerow(
            [
                report["snapshot_date"].isoformat(),
                report["total_certificates"],
                report["total_checks"],
                report["passed_checks"],
                report["failed_checks"],
                report["compliance_score"],
            ]
        )
        return output.getvalue()
