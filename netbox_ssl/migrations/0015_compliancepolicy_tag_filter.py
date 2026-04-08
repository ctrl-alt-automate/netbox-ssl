"""Add tag_filter to CompliancePolicy for tag-based policy scoping."""

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("extras", "0001_initial"),
        ("netbox_ssl", "0014_merge_v080"),
    ]

    operations = [
        migrations.AddField(
            model_name="compliancepolicy",
            name="tag_filter",
            field=models.ManyToManyField(
                blank=True,
                help_text="Only apply to certificates with ALL of these tags. Empty = apply to all.",
                related_name="+",
                to="extras.tag",
            ),
        ),
    ]
