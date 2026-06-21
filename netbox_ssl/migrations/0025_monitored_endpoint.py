"""
Add MonitoredEndpoint and MonitoredEndpointCertificate models (#149).

Website-centric certificate monitoring: track which certificate a URL presents,
with rotation history. MonitoredEndpoint inherits NetBoxModel (custom fields +
tags). MonitoredEndpointCertificate is a plain model (rotation history table).

Generated fields match the NetBoxModel mixin pattern used by other models in
this plugin (see 0013_external_source_framework.py for reference).
"""

import django.db.models.deletion
import taggit.managers
import utilities.json
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("contenttypes", "0002_remove_content_type_name"),
        ("extras", "0001_squashed"),
        ("netbox_ssl", "0024_url_import_fields"),
        ("tenancy", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="MonitoredEndpoint",
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
                    models.JSONField(blank=True, default=dict, encoder=utilities.json.CustomFieldJSONEncoder),
                ),
                (
                    "name",
                    models.CharField(
                        help_text="Human label, e.g. 'HR portal'.",
                        max_length=200,
                    ),
                ),
                (
                    "url",
                    models.CharField(
                        help_text="https://host:port to monitor.",
                        max_length=500,
                    ),
                ),
                (
                    "sni",
                    models.CharField(
                        blank=True,
                        help_text="Optional SNI override (defaults to the URL host).",
                        max_length=255,
                    ),
                ),
                (
                    "assigned_object_id",
                    models.PositiveBigIntegerField(blank=True, null=True),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("pending", "Pending"),
                            ("ok", "OK"),
                            ("unreachable", "Unreachable"),
                            ("untrusted", "Untrusted"),
                        ],
                        default="pending",
                        max_length=20,
                    ),
                ),
                ("last_checked", models.DateTimeField(blank=True, null=True)),
                ("last_seen", models.DateTimeField(blank=True, null=True)),
                ("last_error", models.TextField(blank=True)),
                (
                    "assigned_object_type",
                    models.ForeignKey(
                        blank=True,
                        limit_choices_to={"model__in": ["service", "device", "virtualmachine"]},
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        to="contenttypes.contenttype",
                    ),
                ),
                (
                    "certificate",
                    models.ForeignKey(
                        blank=True,
                        help_text="The certificate this endpoint currently presents.",
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="monitored_endpoints",
                        to="netbox_ssl.certificate",
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="+",
                        to="tenancy.tenant",
                    ),
                ),
                ("tags", taggit.managers.TaggableManager(through="extras.TaggedItem", to="extras.Tag")),
            ],
            options={
                "ordering": ["name"],
            },
        ),
        migrations.CreateModel(
            name="MonitoredEndpointCertificate",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("first_seen", models.DateTimeField()),
                ("last_seen", models.DateTimeField()),
                (
                    "certificate",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="netbox_ssl.certificate",
                    ),
                ),
                (
                    "endpoint",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="cert_history",
                        to="netbox_ssl.monitoredendpoint",
                    ),
                ),
            ],
            options={
                "ordering": ["-last_seen"],
            },
        ),
        migrations.AddConstraint(
            model_name="monitoredendpointcertificate",
            constraint=models.UniqueConstraint(
                fields=["endpoint", "certificate"],
                name="unique_endpoint_certificate",
            ),
        ),
    ]
