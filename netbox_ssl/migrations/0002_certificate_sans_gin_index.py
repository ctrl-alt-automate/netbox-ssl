"""
Add GIN index on Certificate.sans field for improved search performance.

PostgreSQL GIN indexes significantly speed up array containment queries (@>)
used when filtering certificates by Subject Alternative Names.

This migration uses AddIndexConcurrently to avoid table locking in production.
"""

from django.contrib.postgres.indexes import GinIndex
from django.contrib.postgres.operations import AddIndexConcurrently
from django.db import migrations


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("netbox_ssl", "0001_initial"),
    ]

    operations = [
        AddIndexConcurrently(
            model_name="certificate",
            index=GinIndex(fields=["sans"], name="netbox_ssl_cert_sans_gin"),
        ),
    ]
