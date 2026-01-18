"""
Table definitions for CertificateAssignment model.
"""

import django_tables2 as tables
from django.utils.html import format_html

from netbox.tables import NetBoxTable, columns

from ..models import CertificateAssignment


class CertificateAssignmentTable(NetBoxTable):
    """Table for displaying certificate assignments."""

    certificate = tables.Column(
        linkify=True,
    )
    assigned_object_type = columns.ContentTypeColumn(
        verbose_name="Object Type",
    )
    assigned_object = tables.Column(
        verbose_name="Assigned To",
        linkify=False,  # We handle linking manually
        accessor="assigned_object",
    )
    is_primary = columns.BooleanColumn(
        verbose_name="Primary",
    )
    tags = columns.TagColumn(
        url_name="plugins:netbox_ssl:certificateassignment_list",
    )

    class Meta(NetBoxTable.Meta):
        model = CertificateAssignment
        fields = (
            "pk",
            "id",
            "certificate",
            "assigned_object_type",
            "assigned_object",
            "is_primary",
            "notes",
            "tags",
        )
        default_columns = (
            "certificate",
            "assigned_object_type",
            "assigned_object",
            "is_primary",
        )

    def render_assigned_object(self, value, record):
        """Render the assigned object with parent info for services."""
        obj = record.assigned_object
        if obj is None:
            return "Unknown"

        obj_link = format_html(
            '<a href="{}">{}</a>',
            obj.get_absolute_url(),
            str(obj),
        )

        # For services, also show the parent device/VM
        if record.assigned_object_type.model == "service":
            parent = getattr(obj, "parent", None)
            if parent:
                return format_html(
                    '{} <span class="text-muted">on <a href="{}">{}</a></span>',
                    obj_link,
                    parent.get_absolute_url(),
                    str(parent),
                )

        return obj_link
