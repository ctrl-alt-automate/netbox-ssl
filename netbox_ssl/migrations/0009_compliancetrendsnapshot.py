"""Create ComplianceTrendSnapshot model for historical compliance tracking."""

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("tenancy", "0001_initial"),
        ("netbox_ssl", "0008_certificateeventlog"),
    ]

    operations = [
        migrations.CreateModel(
            name="ComplianceTrendSnapshot",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "created",
                    models.DateTimeField(auto_now_add=True, null=True),
                ),
                (
                    "last_updated",
                    models.DateTimeField(auto_now=True, null=True),
                ),
                (
                    "snapshot_date",
                    models.DateField(help_text="Date of this snapshot"),
                ),
                (
                    "total_certificates",
                    models.PositiveIntegerField(
                        default=0,
                        help_text="Total certificates checked",
                    ),
                ),
                (
                    "total_checks",
                    models.PositiveIntegerField(
                        default=0,
                        help_text="Total compliance checks performed",
                    ),
                ),
                (
                    "passed_checks",
                    models.PositiveIntegerField(
                        default=0,
                        help_text="Number of checks that passed",
                    ),
                ),
                (
                    "failed_checks",
                    models.PositiveIntegerField(
                        default=0,
                        help_text="Number of checks that failed",
                    ),
                ),
                (
                    "compliance_score",
                    models.FloatField(
                        default=0.0,
                        help_text="Compliance score (0-100)",
                    ),
                ),
                (
                    "details",
                    models.JSONField(
                        blank=True,
                        default=dict,
                        help_text="Breakdown by policy type, severity, etc.",
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        blank=True,
                        help_text="Tenant scope (null = global)",
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="compliance_trend_snapshots",
                        to="tenancy.tenant",
                    ),
                ),
            ],
            options={
                "ordering": ["-snapshot_date"],
            },
        ),
        migrations.AddConstraint(
            model_name="compliancetrendsnapshot",
            constraint=models.UniqueConstraint(
                fields=("tenant", "snapshot_date"),
                name="unique_tenant_snapshot_date",
            ),
        ),
    ]
