"""
Add archive_pinned and archived_at fields to Certificate model.

Supports the Auto-Archive Policy feature (#50).
"""

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_ssl", "0009_compliancetrendsnapshot"),
    ]

    operations = [
        migrations.AddField(
            model_name="certificate",
            name="archive_pinned",
            field=models.BooleanField(
                default=False,
                help_text="When enabled, prevents this certificate from being auto-archived",
            ),
        ),
        migrations.AddField(
            model_name="certificate",
            name="archived_at",
            field=models.DateTimeField(
                blank=True,
                help_text="Timestamp when this certificate was archived",
                null=True,
            ),
        ),
    ]
