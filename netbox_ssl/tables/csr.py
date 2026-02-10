"""
Table definitions for CertificateSigningRequest model.
"""

import django_tables2 as tables
from django.utils.html import format_html
from netbox.tables import NetBoxTable, columns

from ..models import CertificateSigningRequest


class CertificateSigningRequestTable(NetBoxTable):
    """Table for displaying CSRs."""

    common_name = tables.Column(
        linkify=True,
    )
    status = tables.Column(
        verbose_name="Status",
    )
    organization = tables.Column(
        verbose_name="Organization",
    )
    algorithm = tables.Column(
        verbose_name="Algorithm",
    )
    key_size = tables.Column(
        verbose_name="Key Size",
    )
    requested_date = columns.DateTimeColumn(
        verbose_name="Requested",
    )
    requested_by = tables.Column(
        verbose_name="Requested By",
    )
    target_ca = tables.Column(
        verbose_name="Target CA",
    )
    tenant = tables.Column(
        linkify=True,
    )
    resulting_certificate = tables.Column(
        linkify=True,
        verbose_name="Certificate",
    )
    tags = columns.TagColumn(
        url_name="plugins:netbox_ssl:certificatesigningrequest_list",
    )

    class Meta(NetBoxTable.Meta):
        model = CertificateSigningRequest
        fields = (
            "pk",
            "id",
            "common_name",
            "status",
            "organization",
            "algorithm",
            "key_size",
            "requested_date",
            "requested_by",
            "target_ca",
            "tenant",
            "resulting_certificate",
            "tags",
        )
        default_columns = (
            "common_name",
            "status",
            "organization",
            "requested_date",
            "requested_by",
            "target_ca",
        )

    def render_status(self, value, record):
        """Render status with color coding."""
        status_colors = {
            "pending": "warning",
            "approved": "success",
            "rejected": "danger",
            "issued": "info",
            "expired": "secondary",
        }
        color = status_colors.get(record.status, "secondary")
        label = record.get_status_display()
        return format_html(
            '<span class="badge text-bg-{}">{}</span>',
            color,
            label,
        )

    def render_resulting_certificate(self, value, record):
        """Render the resulting certificate link."""
        if value:
            return format_html(
                '<a href="{}">{}</a>',
                value.get_absolute_url(),
                value.common_name,
            )
        return format_html('<span class="text-muted">—</span>')
