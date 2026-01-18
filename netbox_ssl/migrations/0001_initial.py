"""
Initial migration for NetBox SSL plugin.
Creates Certificate and CertificateAssignment models.
"""

import django.contrib.postgres.fields
import django.db.models.deletion
import taggit.managers
import utilities.json
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ("contenttypes", "0002_remove_content_type_name"),
        ("extras", "0001_squashed"),
        ("tenancy", "0001_squashed_0012"),
    ]

    operations = [
        migrations.CreateModel(
            name="Certificate",
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
                        help_text="Primary Common Name (CN) of the certificate",
                        max_length=255,
                    ),
                ),
                (
                    "serial_number",
                    models.CharField(
                        help_text="Certificate serial number (hex format)",
                        max_length=255,
                    ),
                ),
                (
                    "fingerprint_sha256",
                    models.CharField(
                        help_text="SHA256 fingerprint for quick verification",
                        max_length=95,
                        unique=True,
                    ),
                ),
                (
                    "issuer",
                    models.CharField(
                        help_text="Certificate issuer (CA) distinguished name",
                        max_length=512,
                    ),
                ),
                (
                    "issuer_chain",
                    models.TextField(
                        blank=True,
                        help_text="Full certificate chain (PEM format, intermediates + root)",
                    ),
                ),
                (
                    "valid_from",
                    models.DateTimeField(help_text="Certificate validity start date"),
                ),
                (
                    "valid_to",
                    models.DateTimeField(help_text="Certificate expiration date"),
                ),
                (
                    "sans",
                    django.contrib.postgres.fields.ArrayField(
                        base_field=models.CharField(max_length=255),
                        blank=True,
                        default=list,
                        help_text="Subject Alternative Names (DNS names, IPs, etc.)",
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
                    "status",
                    models.CharField(
                        default="active",
                        help_text="Current status of the certificate",
                        max_length=20,
                    ),
                ),
                (
                    "private_key_location",
                    models.CharField(
                        blank=True,
                        help_text="Hint for private key location (e.g., Vault path)",
                        max_length=512,
                    ),
                ),
                (
                    "pem_content",
                    models.TextField(
                        blank=True,
                        help_text="Certificate in PEM format (public certificate only)",
                    ),
                ),
                (
                    "replaced_by",
                    models.ForeignKey(
                        blank=True,
                        help_text="Successor certificate (for renewal tracking)",
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="replaces",
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
                        help_text="Tenant this certificate belongs to",
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="certificates",
                        to="tenancy.tenant",
                    ),
                ),
            ],
            options={
                "ordering": ["-valid_to", "common_name"],
            },
        ),
        migrations.AddConstraint(
            model_name="certificate",
            constraint=models.UniqueConstraint(fields=("serial_number", "issuer"), name="unique_serial_issuer"),
        ),
        migrations.CreateModel(
            name="CertificateAssignment",
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
                (
                    "assigned_object_id",
                    models.PositiveBigIntegerField(help_text="ID of the assigned object"),
                ),
                (
                    "is_primary",
                    models.BooleanField(
                        default=True,
                        help_text="Whether this is the primary certificate for the target",
                    ),
                ),
                (
                    "notes",
                    models.TextField(blank=True, help_text="Additional notes about this assignment"),
                ),
                (
                    "assigned_object_type",
                    models.ForeignKey(
                        help_text="Type of the assigned object",
                        limit_choices_to={"model__in": ["service", "device", "virtualmachine"]},
                        on_delete=django.db.models.deletion.CASCADE,
                        to="contenttypes.contenttype",
                    ),
                ),
                (
                    "certificate",
                    models.ForeignKey(
                        help_text="The certificate being assigned",
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="assignments",
                        to="netbox_ssl.certificate",
                    ),
                ),
                (
                    "tags",
                    taggit.managers.TaggableManager(through="extras.TaggedItem", to="extras.Tag"),
                ),
            ],
            options={
                "ordering": ["certificate", "assigned_object_type"],
            },
        ),
        migrations.AddConstraint(
            model_name="certificateassignment",
            constraint=models.UniqueConstraint(
                fields=("certificate", "assigned_object_type", "assigned_object_id"),
                name="unique_certificate_assignment",
            ),
        ),
    ]
