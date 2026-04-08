"""Add database indexes on frequently filtered Certificate fields for performance."""

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_ssl", "0014_merge_v080"),
    ]

    operations = [
        migrations.AddIndex(
            model_name="certificate",
            index=models.Index(fields=["common_name"], name="idx_cert_common_name"),
        ),
        migrations.AddIndex(
            model_name="certificate",
            index=models.Index(fields=["status"], name="idx_cert_status"),
        ),
        migrations.AddIndex(
            model_name="certificate",
            index=models.Index(fields=["valid_to"], name="idx_cert_valid_to"),
        ),
        migrations.AddIndex(
            model_name="certificate",
            index=models.Index(fields=["issuer"], name="idx_cert_issuer"),
        ),
        migrations.AddIndex(
            model_name="certificate",
            index=models.Index(fields=["algorithm"], name="idx_cert_algorithm"),
        ),
        migrations.AddIndex(
            model_name="certificate",
            index=models.Index(fields=["tenant_id"], name="idx_cert_tenant"),
        ),
        migrations.AddIndex(
            model_name="certificate",
            index=models.Index(fields=["fingerprint_sha256"], name="idx_cert_fingerprint"),
        ),
        migrations.AddIndex(
            model_name="certificate",
            index=models.Index(fields=["status", "valid_to"], name="idx_cert_status_valid_to"),
        ),
        migrations.AddIndex(
            model_name="certificate",
            index=models.Index(fields=["is_acme", "acme_auto_renewal"], name="idx_cert_acme_renewal"),
        ),
    ]
