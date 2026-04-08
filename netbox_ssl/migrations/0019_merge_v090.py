"""Merge migration for v0.9.0 parallel feature branches."""

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_ssl", "0015_compliancepolicy_tag_filter"),
        ("netbox_ssl", "0016_custom_permissions"),
        ("netbox_ssl", "0017_performance_indexes"),
        ("netbox_ssl", "0018_ari_fields"),
    ]

    operations = []
