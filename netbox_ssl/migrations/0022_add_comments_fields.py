"""Add the NetBox-standard ``comments`` field to CertificateAuthority and
ExternalSource (issue #112).

The edit forms for Certificate, CertificateAuthority, CertificateSigningRequest
and ExternalSource all declared ``comments = CommentField()``, but the *models*
never declared a matching field, so input was silently dropped on save.

The Certificate (migration 0001) and CertificateSigningRequest (migration 0003)
tables already carry a historical ``comments`` column — only the model field
was missing, so re-declaring it on the model is enough for those two (no schema
change). CertificateAuthority and ExternalSource have no such column, so it is
added here. ``null=True`` matches the historical column definition and keeps the
migration safe on existing installs (no NOT NULL backfill).
"""

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_ssl", "0021_external_source_auth_credentials_and_region"),
    ]

    operations = [
        migrations.AddField(
            model_name="certificateauthority",
            name="comments",
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="externalsource",
            name="comments",
            field=models.TextField(blank=True, null=True),
        ),
    ]
