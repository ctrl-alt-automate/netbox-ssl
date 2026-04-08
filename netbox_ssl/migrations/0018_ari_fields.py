"""Add ACME Renewal Information (ARI) fields to Certificate model — RFC 9773."""

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_ssl", "0014_merge_v080"),
    ]

    operations = [
        migrations.AddField(
            model_name="certificate",
            name="ari_cert_id",
            field=models.CharField(
                blank=True,
                help_text="ARI CertID: base64url(AKI).base64url(serial)",
                max_length=500,
            ),
        ),
        migrations.AddField(
            model_name="certificate",
            name="ari_suggested_start",
            field=models.DateTimeField(
                blank=True,
                help_text="ARI suggested renewal window start",
                null=True,
            ),
        ),
        migrations.AddField(
            model_name="certificate",
            name="ari_suggested_end",
            field=models.DateTimeField(
                blank=True,
                help_text="ARI suggested renewal window end",
                null=True,
            ),
        ),
        migrations.AddField(
            model_name="certificate",
            name="ari_explanation_url",
            field=models.URLField(
                blank=True,
                help_text="URL explaining why early renewal is suggested",
                max_length=500,
            ),
        ),
        migrations.AddField(
            model_name="certificate",
            name="ari_last_checked",
            field=models.DateTimeField(
                blank=True,
                help_text="When ARI was last polled for this certificate",
                null=True,
            ),
        ),
        migrations.AddField(
            model_name="certificate",
            name="ari_retry_after",
            field=models.DateTimeField(
                blank=True,
                help_text="Earliest time to poll ARI again (from Retry-After header)",
                null=True,
            ),
        ),
    ]
