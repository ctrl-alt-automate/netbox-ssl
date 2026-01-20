"""
Migration to add compliance reporting models.

Adds CompliancePolicy and ComplianceCheck models for certificate compliance tracking.
"""

import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("tenancy", "0001_initial"),
        ("netbox_ssl", "0002_certificate_sans_gin_index"),
    ]

    operations = [
        migrations.CreateModel(
            name="CompliancePolicy",
            fields=[
                (
                    "id",
                    models.BigAutoField(auto_created=True, primary_key=True, serialize=False),
                ),
                ("created", models.DateTimeField(auto_now_add=True, null=True)),
                ("last_updated", models.DateTimeField(auto_now=True, null=True)),
                (
                    "custom_field_data",
                    models.JSONField(blank=True, default=dict, encoder=None),
                ),
                (
                    "name",
                    models.CharField(
                        help_text="Unique name for this compliance policy",
                        max_length=100,
                        unique=True,
                    ),
                ),
                (
                    "description",
                    models.TextField(
                        blank=True,
                        help_text="Detailed description of the policy",
                    ),
                ),
                (
                    "policy_type",
                    models.CharField(
                        choices=[
                            ("min_key_size", "Minimum Key Size"),
                            ("max_validity_days", "Maximum Validity Period"),
                            ("algorithm_allowed", "Algorithm Allowed"),
                            ("algorithm_forbidden", "Algorithm Forbidden"),
                            ("expiry_warning", "Expiry Warning Threshold"),
                            ("chain_required", "Chain Required"),
                            ("san_required", "SAN Required"),
                            ("wildcard_forbidden", "Wildcard Forbidden"),
                            ("issuer_allowed", "Issuer Allowed"),
                            ("issuer_forbidden", "Issuer Forbidden"),
                        ],
                        help_text="Type of compliance check",
                        max_length=30,
                    ),
                ),
                (
                    "severity",
                    models.CharField(
                        choices=[
                            ("critical", "Critical"),
                            ("warning", "Warning"),
                            ("info", "Info"),
                        ],
                        default="warning",
                        help_text="Severity level when policy is violated",
                        max_length=20,
                    ),
                ),
                (
                    "enabled",
                    models.BooleanField(
                        default=True,
                        help_text="Whether this policy is active",
                    ),
                ),
                (
                    "parameters",
                    models.JSONField(
                        blank=True,
                        default=dict,
                        help_text="Policy parameters as JSON (varies by policy type)",
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        blank=True,
                        help_text="Limit policy to specific tenant (null = global)",
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="compliance_policies",
                        to="tenancy.tenant",
                    ),
                ),
            ],
            options={
                "verbose_name_plural": "compliance policies",
                "ordering": ["name"],
            },
        ),
        migrations.CreateModel(
            name="ComplianceCheck",
            fields=[
                (
                    "id",
                    models.BigAutoField(auto_created=True, primary_key=True, serialize=False),
                ),
                ("created", models.DateTimeField(auto_now_add=True, null=True)),
                ("last_updated", models.DateTimeField(auto_now=True, null=True)),
                (
                    "custom_field_data",
                    models.JSONField(blank=True, default=dict, encoder=None),
                ),
                (
                    "result",
                    models.CharField(
                        choices=[
                            ("pass", "Pass"),
                            ("fail", "Fail"),
                            ("error", "Error"),
                            ("skipped", "Skipped"),
                        ],
                        help_text="Result of the compliance check",
                        max_length=20,
                    ),
                ),
                (
                    "message",
                    models.TextField(
                        blank=True,
                        help_text="Detailed message about the check result",
                    ),
                ),
                (
                    "checked_at",
                    models.DateTimeField(
                        default=django.utils.timezone.now,
                        help_text="When the check was performed",
                    ),
                ),
                (
                    "checked_value",
                    models.CharField(
                        blank=True,
                        help_text="The actual value that was checked",
                        max_length=255,
                    ),
                ),
                (
                    "expected_value",
                    models.CharField(
                        blank=True,
                        help_text="The expected value per policy",
                        max_length=255,
                    ),
                ),
                (
                    "certificate",
                    models.ForeignKey(
                        help_text="Certificate that was checked",
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="compliance_checks",
                        to="netbox_ssl.certificate",
                    ),
                ),
                (
                    "policy",
                    models.ForeignKey(
                        help_text="Policy that was applied",
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="checks",
                        to="netbox_ssl.compliancepolicy",
                    ),
                ),
            ],
            options={
                "ordering": ["-checked_at"],
            },
        ),
        migrations.AddConstraint(
            model_name="compliancecheck",
            constraint=models.UniqueConstraint(
                fields=("certificate", "policy"),
                name="unique_certificate_policy_check",
            ),
        ),
    ]
