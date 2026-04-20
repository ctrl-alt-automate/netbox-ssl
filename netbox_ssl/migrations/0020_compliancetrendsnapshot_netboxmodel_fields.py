"""
Backfill NetBoxModel fields that were omitted when migration 0009 created
ComplianceTrendSnapshot. The model inherits from NetBoxModel, which provides
``custom_field_data`` and ``tags``, but those were never migrated.
"""

import taggit.managers
import utilities.json
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("extras", "0001_initial"),
        ("netbox_ssl", "0019_merge_v090"),
    ]

    operations = [
        migrations.AddField(
            model_name="compliancetrendsnapshot",
            name="custom_field_data",
            field=models.JSONField(
                blank=True,
                default=dict,
                encoder=utilities.json.CustomFieldJSONEncoder,
            ),
        ),
        migrations.AddField(
            model_name="compliancetrendsnapshot",
            name="tags",
            field=taggit.managers.TaggableManager(
                through="extras.TaggedItem",
                to="extras.Tag",
            ),
        ),
    ]
