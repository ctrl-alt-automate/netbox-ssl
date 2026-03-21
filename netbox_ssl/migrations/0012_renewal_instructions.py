"""Add renewal_instructions to CertificateAuthority and renewal_note to Certificate."""

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_ssl", "0009_compliancetrendsnapshot"),
    ]

    operations = [
        migrations.AddField(
            model_name="certificateauthority",
            name="renewal_instructions",
            field=models.TextField(
                blank=True,
                help_text="Renewal instructions in Markdown format. Included in expiry event payloads.",
            ),
        ),
        migrations.AddField(
            model_name="certificate",
            name="renewal_note",
            field=models.TextField(
                blank=True,
                help_text="Custom renewal instructions for this specific certificate. Overrides CA-level instructions.",
            ),
        ),
    ]
