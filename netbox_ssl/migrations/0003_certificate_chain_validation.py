"""
Migration to add certificate chain validation fields.

Adds fields to track chain validation status and results.
"""

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_ssl", "0002_certificate_sans_gin_index"),
    ]

    operations = [
        migrations.AddField(
            model_name="certificate",
            name="chain_status",
            field=models.CharField(
                choices=[
                    ("unknown", "Unknown"),
                    ("valid", "Valid"),
                    ("invalid", "Invalid"),
                    ("self_signed", "Self-Signed"),
                    ("no_chain", "No Chain"),
                ],
                default="unknown",
                help_text="Status of certificate chain validation",
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name="certificate",
            name="chain_validation_message",
            field=models.TextField(
                blank=True,
                help_text="Detailed message from chain validation",
            ),
        ),
        migrations.AddField(
            model_name="certificate",
            name="chain_validated_at",
            field=models.DateTimeField(
                blank=True,
                help_text="When chain validation was last performed",
                null=True,
            ),
        ),
        migrations.AddField(
            model_name="certificate",
            name="chain_depth",
            field=models.PositiveSmallIntegerField(
                blank=True,
                help_text="Number of certificates in the chain",
                null=True,
            ),
        ),
    ]
