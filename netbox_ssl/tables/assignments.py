"""
Table definitions for CertificateAssignment model.
"""

import django_tables2 as tables

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
        linkify=True,
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
        """Render the assigned object name."""
        return record.assigned_object_name
