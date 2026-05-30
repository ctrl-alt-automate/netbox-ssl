"""
Reconcile migration state with the model definitions (issue #118).

Several NetBoxModel-provided fields and a stale constraint had drifted out of
the migration history, so ``makemigrations netbox_ssl --check`` reported pending
changes on a clean install (the same class of drift as the v1.0.1
ComplianceTrendSnapshot fix, migration 0020):

* ``tags`` was never migrated for ComplianceCheck / CompliancePolicy — both
  inherit NetBoxModel (which provides ``tags`` via TaggableManager) but
  migration 0005 created them without it.
* ``custom_field_data`` on the compliance models and ExternalSource was frozen
  without the ``CustomFieldJSONEncoder`` the model now uses.
* ``tags`` on ExternalSource was frozen as a plain ManyToManyField (0013) but the
  model inherits the NetBoxModel TaggableManager.
* ``unique_external_source_id`` was added on Certificate in 0013 but later
  removed from the model's Meta.constraints without a migration to drop it.

All operations are additive / metadata-only and safe on existing installs (no
NOT NULL backfill, no data migration). The ``extras`` dependency is anchored at
``0001_initial`` — matching migrations 0015/0020 — so this applies cleanly
across the supported NetBox 4.4–4.6 range rather than pinning a version-specific
extras migration.

The ExternalSource ``tags`` reconciliation is wrapped in
``SeparateDatabaseAndState`` with NO database operation: Django refuses to ALTER
between a plain M2M and a TaggableManager (``you cannot alter to or from M2M``),
and no DB change is actually needed. The TaggableManager has always written to
the shared ``extras_taggeditem`` table (via the NetBoxModel parent), so the old
per-model ``netbox_ssl_externalsource_tags`` table created by 0013 has been dead
since v0.8 (verified empty). We update only the migration *state* so the field
matches the model; the dead table is left in place (harmless, and dropping it
would be a non-additive schema change out of scope for this reconciliation).
"""

import taggit.managers
import utilities.json
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("extras", "0001_initial"),
        ("netbox_ssl", "0022_add_comments_fields"),
    ]

    operations = [
        migrations.RemoveConstraint(
            model_name="certificate",
            name="unique_external_source_id",
        ),
        migrations.AddField(
            model_name="compliancecheck",
            name="tags",
            field=taggit.managers.TaggableManager(through="extras.TaggedItem", to="extras.Tag"),
        ),
        migrations.AddField(
            model_name="compliancepolicy",
            name="tags",
            field=taggit.managers.TaggableManager(through="extras.TaggedItem", to="extras.Tag"),
        ),
        migrations.AlterField(
            model_name="compliancecheck",
            name="custom_field_data",
            field=models.JSONField(blank=True, default=dict, encoder=utilities.json.CustomFieldJSONEncoder),
        ),
        migrations.AlterField(
            model_name="compliancepolicy",
            name="custom_field_data",
            field=models.JSONField(blank=True, default=dict, encoder=utilities.json.CustomFieldJSONEncoder),
        ),
        migrations.AlterField(
            model_name="externalsource",
            name="custom_field_data",
            field=models.JSONField(blank=True, default=dict, encoder=utilities.json.CustomFieldJSONEncoder),
        ),
        # State-only: align the field with the model's TaggableManager without a
        # DB ALTER (Django cannot alter to/from M2M; no DB change is needed since
        # tags already live in the shared extras_taggeditem table).
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.AlterField(
                    model_name="externalsource",
                    name="tags",
                    field=taggit.managers.TaggableManager(through="extras.TaggedItem", to="extras.Tag"),
                ),
            ],
            database_operations=[],
        ),
    ]
