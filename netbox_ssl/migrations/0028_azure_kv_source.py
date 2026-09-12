"""
Azure Key Vault source type and opt-in tag sync (#101).

Additive and reversible: one new `source_type` choice and one boolean field
defaulting to False, so existing sources are untouched and no tags are written
to existing certificates on upgrade.
"""

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_ssl", "0027_certificate_type"),
    ]

    operations = [
        migrations.AlterField(
            model_name="externalsource",
            name="source_type",
            field=models.CharField(
                choices=[
                    ("lemur", "Lemur"),
                    ("generic_rest", "Generic REST API"),
                    ("aws_acm", "AWS Certificate Manager"),
                    ("azure_kv", "Azure Key Vault"),
                ],
                help_text="Type of external source backend",
                max_length=30,
            ),
        ),
        migrations.AddField(
            model_name="externalsource",
            name="sync_tags",
            field=models.BooleanField(
                default=False,
                help_text=(
                    "Copy tags from the external source onto imported certificates. "
                    "Only Azure Key Vault sources supply tags today; on other source "
                    "types this has no effect. Where it applies, the source becomes "
                    "authoritative: each sync replaces the full tag set, and clears it "
                    "when the source has no tags."
                ),
            ),
        ),
    ]
