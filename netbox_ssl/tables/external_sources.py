"""
Table definitions for ExternalSource model.
"""

import django_tables2 as tables
from django.utils.html import format_html
from netbox.tables import NetBoxTable, columns

from ..models import ExternalSource


class ExternalSourceTable(NetBoxTable):
    """Table for displaying External Sources."""

    name = tables.Column(
        linkify=True,
    )
    source_type = columns.ChoiceFieldColumn()
    enabled = columns.BooleanColumn(
        verbose_name="Enabled",
    )
    sync_status = tables.Column(
        verbose_name="Sync Status",
    )
    last_synced = tables.DateTimeColumn(
        verbose_name="Last Synced",
    )
    certificate_count = tables.Column(
        verbose_name="Certificates",
        accessor="pk",
        orderable=False,
    )
    tenant = tables.Column(
        linkify=True,
    )
    tags = columns.TagColumn(
        url_name="plugins:netbox_ssl:externalsource_list",
    )

    class Meta(NetBoxTable.Meta):
        model = ExternalSource
        fields = (
            "pk",
            "id",
            "name",
            "source_type",
            "enabled",
            "sync_status",
            "last_synced",
            "certificate_count",
            "tenant",
            "tags",
        )
        default_columns = (
            "name",
            "source_type",
            "enabled",
            "sync_status",
            "last_synced",
            "certificate_count",
        )

    def render_enabled(self, value, record):
        """Render enabled status with color coding."""
        if value:
            return format_html(
                '<span class="badge text-bg-success">Enabled</span>',
            )
        return format_html(
            '<span class="badge text-bg-danger">Disabled</span>',
        )

    def render_sync_status(self, value, record):
        """Render sync status with color badges."""
        color_map = {
            "new": "text-bg-info",
            "ok": "text-bg-success",
            "error": "text-bg-danger",
            "syncing": "text-bg-warning",
        }
        css_class = color_map.get(value, "text-bg-secondary")
        display = record.get_sync_status_display()
        return format_html(
            '<span class="badge {}">{}</span>',
            css_class,
            display,
        )

    def render_certificate_count(self, value, record):
        """Render certificate count."""
        return record.certificate_count
