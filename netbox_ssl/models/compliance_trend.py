"""
Compliance trend snapshot model for tracking historical compliance scores.

Stores daily aggregate compliance data for trend analysis and reporting.
"""

from django.db import models
from django.urls import reverse
from netbox.models import NetBoxModel


class ComplianceTrendSnapshot(NetBoxModel):
    """
    Daily snapshot of compliance metrics.

    Created by ComplianceReporter.create_snapshot() to track compliance
    scores over time, optionally scoped to a tenant.
    """

    tenant = models.ForeignKey(
        to="tenancy.Tenant",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="compliance_trend_snapshots",
        help_text="Tenant scope (null = global)",
    )
    snapshot_date = models.DateField(
        help_text="Date of this snapshot",
    )
    total_certificates = models.PositiveIntegerField(
        default=0,
        help_text="Total certificates checked",
    )
    total_checks = models.PositiveIntegerField(
        default=0,
        help_text="Total compliance checks performed",
    )
    passed_checks = models.PositiveIntegerField(
        default=0,
        help_text="Number of checks that passed",
    )
    failed_checks = models.PositiveIntegerField(
        default=0,
        help_text="Number of checks that failed",
    )
    compliance_score = models.FloatField(
        default=0.0,
        help_text="Compliance score (0-100)",
    )
    details = models.JSONField(
        default=dict,
        blank=True,
        help_text="Breakdown by policy type, severity, etc.",
    )

    class Meta:
        ordering = ["-snapshot_date"]
        constraints = [
            models.UniqueConstraint(
                fields=["tenant", "snapshot_date"],
                name="unique_tenant_snapshot_date",
            ),
        ]

    def __str__(self):
        tenant_label = self.tenant.name if self.tenant else "Global"
        return f"{tenant_label} - {self.snapshot_date} ({self.compliance_score:.1f}%)"

    def get_absolute_url(self):
        return reverse("plugins:netbox_ssl:compliance_report")
