"""
Merge migration for v0.8.0.

Combines the four parallel v0.8 feature migrations into a single graph node.
"""

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_ssl", "0010_certificate_archive_fields"),
        ("netbox_ssl", "0011_certificatelifecycleevent"),
        ("netbox_ssl", "0012_renewal_instructions"),
        ("netbox_ssl", "0013_external_source_framework"),
    ]

    operations = []
