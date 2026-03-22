"""Create CertificateLifecycleEvent model for lifecycle timeline tracking."""

import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_ssl", "0009_compliancetrendsnapshot"),
    ]

    operations = [
        migrations.CreateModel(
            name="CertificateLifecycleEvent",
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
                    "event_type",
                    models.CharField(
                        help_text="Type of lifecycle event",
                        max_length=30,
                    ),
                ),
                (
                    "timestamp",
                    models.DateTimeField(
                        default=django.utils.timezone.now,
                        help_text="When this event occurred",
                    ),
                ),
                (
                    "description",
                    models.TextField(
                        blank=True,
                        help_text="Human-readable description of the event",
                    ),
                ),
                (
                    "old_status",
                    models.CharField(
                        blank=True,
                        help_text="Previous status (for status change events)",
                        max_length=20,
                    ),
                ),
                (
                    "new_status",
                    models.CharField(
                        blank=True,
                        help_text="New status (for status change events)",
                        max_length=20,
                    ),
                ),
                (
                    "actor",
                    models.CharField(
                        blank=True,
                        help_text="User or system that triggered this event",
                        max_length=150,
                    ),
                ),
                (
                    "certificate",
                    models.ForeignKey(
                        help_text="The certificate this event belongs to",
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="lifecycle_events",
                        to="netbox_ssl.certificate",
                    ),
                ),
                (
                    "related_certificate",
                    models.ForeignKey(
                        blank=True,
                        help_text="Related certificate (e.g., predecessor/successor in renewal)",
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="related_lifecycle_events",
                        to="netbox_ssl.certificate",
                    ),
                ),
            ],
            options={
                "ordering": ["-timestamp"],
                "indexes": [
                    models.Index(
                        fields=["certificate", "-timestamp"],
                        name="netbox_ssl_lifecycle_cert_ts",
                    ),
                ],
            },
        ),
    ]
