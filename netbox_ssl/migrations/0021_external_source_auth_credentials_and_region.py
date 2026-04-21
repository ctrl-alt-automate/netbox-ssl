"""Add auth_credentials JSONField + region CharField to ExternalSource;
relax base_url to blank=True for region-scoped adapters (AWS ACM).

Backfills auth_credentials from the deprecated auth_credentials_reference
CharField so existing Lemur / Generic REST configurations continue to
work without operator action.

Per the spec at docs/superpowers/specs/2026-04-21-multi-credential-auth-pattern-design.md,
auth_credentials_reference is kept for one minor cycle and removed in v2.0.0.
"""

from django.db import migrations, models

import netbox_ssl.models.external_source  # for validate_external_source_url


def _migrate_auth_credentials(apps, schema_editor):
    """Copy each auth_credentials_reference string into auth_credentials['token'].

    Idempotent: re-running the migration is safe. Rows where
    auth_credentials is already populated are skipped.
    """
    ExternalSource = apps.get_model("netbox_ssl", "ExternalSource")
    for source in ExternalSource.objects.all():
        if source.auth_credentials:
            continue  # already migrated
        if source.auth_credentials_reference:
            source.auth_credentials = {"token": source.auth_credentials_reference}
            source.save(update_fields=["auth_credentials"])


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_ssl", "0020_compliancetrendsnapshot_netboxmodel_fields"),
    ]

    operations = [
        migrations.AlterField(
            model_name="externalsource",
            name="auth_method",
            field=models.CharField(
                choices=[
                    ("bearer", "Bearer Token"),
                    ("api_key", "API Key (Header)"),
                    ("aws_explicit", "AWS Explicit Credentials"),
                    ("aws_instance_role", "AWS Instance Role"),
                    ("azure_explicit", "Azure Service Principal"),
                    ("azure_managed_identity", "Azure Managed Identity"),
                ],
                help_text="Authentication method for the external source",
                max_length=30,
            ),
        ),
        migrations.AddField(
            model_name="externalsource",
            name="auth_credentials",
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AddField(
            model_name="externalsource",
            name="region",
            field=models.CharField(blank=True, max_length=32),
        ),
        migrations.AlterField(
            model_name="externalsource",
            name="base_url",
            field=models.URLField(
                blank=True,
                max_length=500,
                validators=[netbox_ssl.models.external_source.validate_external_source_url],
            ),
        ),
        migrations.RunPython(
            _migrate_auth_credentials,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
