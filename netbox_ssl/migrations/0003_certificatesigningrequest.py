"""
Migration for CertificateSigningRequest model.

Adds CSR tracking support for managing pending certificate requests.
"""

import django.contrib.postgres.fields
import django.db.models.deletion
import taggit.managers
import utilities.json
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("extras", "0001_squashed"),
        ("tenancy", "0001_squashed_0012"),
        ("netbox_ssl", "0002_certificate_sans_gin_index"),
    ]

    operations = [
        migrations.CreateModel(
            name="CertificateSigningRequest",
            fields=[
                (
                    "id",
                    models.BigAutoField(auto_created=True, primary_key=True, serialize=False),
                ),
                ("created", models.DateTimeField(auto_now_add=True, null=True)),
                ("last_updated", models.DateTimeField(auto_now=True, null=True)),
                (
                    "custom_field_data",
                    models.JSONField(blank=True, default=dict, encoder=utilities.json.CustomFieldJSONEncoder),
                ),
                ("comments", models.TextField(blank=True, null=True)),
                (
                    "common_name",
                    models.CharField(
                        help_text="Common Name (CN) from the CSR subject",
                        max_length=255,
                    ),
                ),
                (
                    "organization",
                    models.CharField(
                        blank=True,
                        help_text="Organization (O) from the CSR subject",
                        max_length=255,
                    ),
                ),
                (
                    "organizational_unit",
                    models.CharField(
                        blank=True,
                        help_text="Organizational Unit (OU) from the CSR subject",
                        max_length=255,
                    ),
                ),
                (
                    "locality",
                    models.CharField(
                        blank=True,
                        help_text="Locality/City (L) from the CSR subject",
                        max_length=255,
                    ),
                ),
                (
                    "state",
                    models.CharField(
                        blank=True,
                        help_text="State/Province (ST) from the CSR subject",
                        max_length=255,
                    ),
                ),
                (
                    "country",
                    models.CharField(
                        blank=True,
                        help_text="Country (C) from the CSR subject (2-letter code)",
                        max_length=2,
                    ),
                ),
                (
                    "sans",
                    django.contrib.postgres.fields.ArrayField(
                        base_field=models.CharField(max_length=255),
                        blank=True,
                        default=list,
                        help_text="Requested Subject Alternative Names (DNS names, IPs, etc.)",
                        size=None,
                    ),
                ),
                (
                    "key_size",
                    models.PositiveIntegerField(
                        blank=True,
                        help_text="Key size in bits (e.g., 2048, 4096)",
                        null=True,
                    ),
                ),
                (
                    "algorithm",
                    models.CharField(
                        help_text="Key algorithm (RSA, ECDSA, Ed25519)",
                        max_length=20,
                    ),
                ),
                (
                    "fingerprint_sha256",
                    models.CharField(
                        help_text="SHA256 fingerprint of the CSR",
                        max_length=95,
                        unique=True,
                    ),
                ),
                (
                    "pem_content",
                    models.TextField(
                        help_text="CSR in PEM format",
                    ),
                ),
                (
                    "status",
                    models.CharField(
                        default="pending",
                        help_text="Current status of the CSR",
                        max_length=20,
                    ),
                ),
                (
                    "requested_date",
                    models.DateTimeField(
                        auto_now_add=True,
                        help_text="When the CSR was imported/requested",
                    ),
                ),
                (
                    "requested_by",
                    models.CharField(
                        blank=True,
                        help_text="Who requested this certificate (person/team/system)",
                        max_length=255,
                    ),
                ),
                (
                    "target_ca",
                    models.CharField(
                        blank=True,
                        help_text="Intended Certificate Authority for signing",
                        max_length=255,
                    ),
                ),
                (
                    "notes",
                    models.TextField(
                        blank=True,
                        help_text="Additional notes about this CSR",
                    ),
                ),
                (
                    "resulting_certificate",
                    models.ForeignKey(
                        blank=True,
                        help_text="Certificate issued from this CSR",
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="source_csr",
                        to="netbox_ssl.certificate",
                    ),
                ),
                (
                    "tags",
                    taggit.managers.TaggableManager(through="extras.TaggedItem", to="extras.Tag"),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        blank=True,
                        help_text="Tenant this CSR belongs to",
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="csrs",
                        to="tenancy.tenant",
                    ),
                ),
            ],
            options={
                "ordering": ["-requested_date", "common_name"],
                "verbose_name": "Certificate Signing Request",
                "verbose_name_plural": "Certificate Signing Requests",
            },
        ),
    ]
