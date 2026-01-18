"""
Table definitions for Certificate model.
"""

import django_tables2 as tables
from django.utils.html import format_html

from netbox.tables import NetBoxTable, columns

from ..models import Certificate


class CertificateTable(NetBoxTable):
    """Table for displaying certificates."""

    common_name = tables.Column(
        linkify=True,
    )
    status = tables.Column(
        verbose_name="Status",
    )
    issuer = tables.Column(
        verbose_name="Issuer",
    )
    valid_from = columns.DateTimeColumn(
        verbose_name="Valid From",
    )
    valid_to = columns.DateTimeColumn(
        verbose_name="Valid To",
    )
    days_remaining = tables.Column(
        verbose_name="Days Left",
        accessor="days_remaining",
        orderable=False,
    )
    algorithm = columns.ChoiceFieldColumn()
    key_size = tables.Column(
        verbose_name="Key Size",
    )
    tenant = tables.Column(
        linkify=True,
    )
    assignment_count = tables.Column(
        verbose_name="Assignments",
        accessor="assignments__count",
        orderable=False,
    )
    tags = columns.TagColumn(
        url_name="plugins:netbox_ssl:certificate_list",
    )

    class Meta(NetBoxTable.Meta):
        model = Certificate
        fields = (
            "pk",
            "id",
            "common_name",
            "status",
            "issuer",
            "valid_from",
            "valid_to",
            "days_remaining",
            "algorithm",
            "key_size",
            "tenant",
            "assignment_count",
            "tags",
        )
        default_columns = (
            "common_name",
            "status",
            "issuer",
            "valid_to",
            "days_remaining",
            "algorithm",
            "tenant",
        )

    def render_status(self, value, record):
        """Render status with color coding."""
        status_colors = {
            "active": "success",      # Green
            "expired": "danger",      # Red
            "replaced": "secondary",  # Gray
            "revoked": "danger",      # Red
            "pending": "warning",     # Yellow
        }
        color = status_colors.get(record.status, "secondary")
        label = record.get_status_display()
        return format_html(
            '<span class="badge text-bg-{}">{}</span>',
            color,
            label,
        )

    def render_days_remaining(self, value, record):
        """Render days remaining with color coding."""
        if value is None:
            return "—"

        # Replaced certificates get gray badge
        if record.status == "replaced":
            return format_html(
                '<span class="badge text-bg-secondary">{} days</span>',
                value,
            )

        if value < 0:
            return format_html(
                '<span class="badge text-bg-danger">Expired ({} days ago)</span>',
                abs(value),
            )
        elif value <= 14:
            return format_html(
                '<span class="badge text-bg-danger">{} days</span>',
                value,
            )
        elif value <= 30:
            return format_html(
                '<span class="badge text-bg-warning">{} days</span>',
                value,
            )
        else:
            return format_html(
                '<span class="badge text-bg-success">{} days</span>',
                value,
            )

    def render_assignment_count(self, value, record):
        """Render assignment count with orphan warning."""
        count = record.assignments.count()
        if count == 0:
            return format_html(
                '<span class="badge text-bg-secondary" title="Orphan certificate">0</span>',
            )
        return count
