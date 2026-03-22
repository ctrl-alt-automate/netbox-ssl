"""
Migration for External Source Framework (#62).

Creates ExternalSource and ExternalSourceSyncLog models, and adds
external_source, external_id, and source_removed fields to Certificate.

NOTE: This migration depends on 0009 (not on 0010/0011/0012) because the
v0.8 feature branches were developed in parallel:
  - 0010: certificate_archive_fields (#50)
  - 0011: certificatelifecycleevent (#49)
  - 0012: renewal_instructions (#47)
  - 0013: external_source_framework (#62, this file)
Migration 0014 is the merge point that combines all four branches.
"""

import django.db.models.deletion
from django.db import migrations, models

import netbox_ssl.models.external_source


class Migration(migrations.Migration):
    dependencies = [
        ("tenancy", "0001_initial"),
        ("netbox_ssl", "0009_compliancetrendsnapshot"),
    ]

    operations = [
        # 1. Create ExternalSource model
        migrations.CreateModel(
            name="ExternalSource",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("created", models.DateTimeField(auto_now_add=True, null=True)),
                ("last_updated", models.DateTimeField(auto_now=True, null=True)),
                (
                    "custom_field_data",
                    models.JSONField(blank=True, default=dict, encoder=None),
                ),
                (
                    "name",
                    models.CharField(
                        help_text="Human-readable name for this source",
                        max_length=255,
                        unique=True,
                    ),
                ),
                (
                    "source_type",
                    models.CharField(
                        help_text="Type of external source backend",
                        max_length=30,
                    ),
                ),
                (
                    "base_url",
                    models.URLField(
                        help_text="HTTPS API endpoint of the external source",
                        max_length=500,
                        validators=[netbox_ssl.models.external_source.validate_external_source_url],
                    ),
                ),
                (
                    "auth_method",
                    models.CharField(
                        help_text="Authentication method for the external source",
                        max_length=20,
                    ),
                ),
                (
                    "auth_credentials_reference",
                    models.CharField(
                        blank=True,
                        help_text='Credential reference (e.g., "env:LEMUR_API_TOKEN"). Never store actual secrets.',
                        max_length=512,
                    ),
                ),
                (
                    "field_mapping",
                    models.JSONField(
                        blank=True,
                        default=dict,
                        help_text="Field mapping for GenericREST adapter (dotted-path notation)",
                    ),
                ),
                (
                    "sync_interval_minutes",
                    models.PositiveIntegerField(
                        default=1440,
                        help_text="Sync interval in minutes (0 = manual only)",
                    ),
                ),
                (
                    "enabled",
                    models.BooleanField(
                        default=True,
                        help_text="Whether this source is active for syncing",
                    ),
                ),
                (
                    "sync_status",
                    models.CharField(
                        default="new",
                        help_text="Current sync status",
                        max_length=20,
                    ),
                ),
                (
                    "last_synced",
                    models.DateTimeField(
                        blank=True,
                        help_text="When the last successful sync completed",
                        null=True,
                    ),
                ),
                (
                    "last_sync_message",
                    models.TextField(
                        blank=True,
                        help_text="Message from the last sync attempt",
                    ),
                ),
                (
                    "verify_ssl",
                    models.BooleanField(
                        default=True,
                        help_text="Verify TLS certificates when connecting to the source",
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        blank=True,
                        help_text="Synced certificates inherit this tenant",
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="external_sources",
                        to="tenancy.tenant",
                    ),
                ),
                ("tags", models.ManyToManyField(blank=True, to="extras.tag")),
            ],
            options={
                "verbose_name": "External Source",
                "verbose_name_plural": "External Sources",
                "ordering": ["name"],
            },
        ),
        # 2. Create ExternalSourceSyncLog model
        migrations.CreateModel(
            name="ExternalSourceSyncLog",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "started_at",
                    models.DateTimeField(
                        auto_now_add=True,
                        help_text="When this sync run started",
                    ),
                ),
                (
                    "finished_at",
                    models.DateTimeField(
                        blank=True,
                        help_text="When this sync run finished",
                        null=True,
                    ),
                ),
                (
                    "success",
                    models.BooleanField(
                        default=False,
                        help_text="Whether the sync completed successfully",
                    ),
                ),
                (
                    "dry_run",
                    models.BooleanField(
                        default=False,
                        help_text="Whether this was a dry-run (no changes made)",
                    ),
                ),
                (
                    "message",
                    models.TextField(
                        blank=True,
                        help_text="Summary message for this sync run",
                    ),
                ),
                (
                    "certificates_fetched",
                    models.PositiveIntegerField(
                        default=0,
                        help_text="Number of certificates fetched from the source",
                    ),
                ),
                (
                    "certificates_created",
                    models.PositiveIntegerField(
                        default=0,
                        help_text="Number of new certificates created",
                    ),
                ),
                (
                    "certificates_updated",
                    models.PositiveIntegerField(
                        default=0,
                        help_text="Number of existing certificates updated",
                    ),
                ),
                (
                    "certificates_renewed",
                    models.PositiveIntegerField(
                        default=0,
                        help_text="Number of certificates renewed (Janus workflow)",
                    ),
                ),
                (
                    "certificates_removed",
                    models.PositiveIntegerField(
                        default=0,
                        help_text="Number of certificates marked as removed from source",
                    ),
                ),
                (
                    "certificates_unchanged",
                    models.PositiveIntegerField(
                        default=0,
                        help_text="Number of certificates that required no changes",
                    ),
                ),
                (
                    "errors",
                    models.JSONField(
                        blank=True,
                        default=list,
                        help_text="List of errors encountered during sync",
                    ),
                ),
                (
                    "source",
                    models.ForeignKey(
                        help_text="The external source this log belongs to",
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="sync_logs",
                        to="netbox_ssl.externalsource",
                    ),
                ),
            ],
            options={
                "ordering": ["-started_at"],
            },
        ),
        # 3. Add external source fields to Certificate
        migrations.AddField(
            model_name="certificate",
            name="external_source",
            field=models.ForeignKey(
                blank=True,
                help_text="External source this certificate was synced from",
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="certificates",
                to="netbox_ssl.externalsource",
            ),
        ),
        migrations.AddField(
            model_name="certificate",
            name="external_id",
            field=models.CharField(
                blank=True,
                help_text="Unique identifier in the external source system",
                max_length=255,
            ),
        ),
        migrations.AddField(
            model_name="certificate",
            name="source_removed",
            field=models.BooleanField(
                default=False,
                help_text="Certificate no longer present in the external source",
            ),
        ),
        # 4. Add UniqueConstraint on (external_source, external_id)
        migrations.AddConstraint(
            model_name="certificate",
            constraint=models.UniqueConstraint(
                condition=models.Q(external_source__isnull=False),
                fields=["external_source", "external_id"],
                name="unique_external_source_id",
            ),
        ),
    ]
