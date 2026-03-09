"""Create CertificateEventLog model for expiry scan idempotency tracking."""

import uuid

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_ssl", "0007_merge_acme_and_chain_validation"),
    ]

    operations = [
        migrations.CreateModel(
            name="CertificateEventLog",
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
                        help_text="Event type that was fired (e.g., certificate_expiring_soon)",
                        max_length=50,
                    ),
                ),
                (
                    "threshold_days",
                    models.PositiveIntegerField(
                        blank=True,
                        help_text="Expiry threshold in days that triggered this event",
                        null=True,
                    ),
                ),
                (
                    "fired_at",
                    models.DateTimeField(
                        auto_now_add=True,
                        help_text="When this event was fired",
                    ),
                ),
                (
                    "scan_id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        help_text="Unique ID of the scan run that generated this event",
                    ),
                ),
                (
                    "certificate",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="event_logs",
                        to="netbox_ssl.certificate",
                    ),
                ),
            ],
            options={
                "ordering": ["-fired_at"],
            },
        ),
        migrations.AddIndex(
            model_name="certificateeventlog",
            index=models.Index(
                fields=["certificate", "event_type", "threshold_days"],
                name="idx_cert_event_lookup",
            ),
        ),
        migrations.AddIndex(
            model_name="certificateeventlog",
            index=models.Index(
                fields=["fired_at"],
                name="idx_cert_event_fired_at",
            ),
        ),
    ]
