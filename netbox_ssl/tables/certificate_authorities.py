"""
Table definitions for CertificateAuthority model.
"""

import django_tables2 as tables
from django.utils.html import format_html
from netbox.tables import NetBoxTable, columns

from ..models import CertificateAuthority


class CertificateAuthorityTable(NetBoxTable):
    """Table for displaying Certificate Authorities."""

    name = tables.Column(
        linkify=True,
    )
    type = columns.ChoiceFieldColumn()
    is_approved = columns.BooleanColumn(
        verbose_name="Approved",
    )
    issuer_pattern = tables.Column(
        verbose_name="Issuer Pattern",
    )
    certificate_count = tables.Column(
        verbose_name="Certificates",
        accessor="certificates__count",
        orderable=False,
    )
    website_url = tables.Column(
        verbose_name="Website",
    )
    tags = columns.TagColumn(
        url_name="plugins:netbox_ssl:certificateauthority_list",
    )

    class Meta(NetBoxTable.Meta):
        model = CertificateAuthority
        fields = (
            "pk",
            "id",
            "name",
            "type",
            "is_approved",
            "issuer_pattern",
            "certificate_count",
            "website_url",
            "contact_email",
            "tags",
        )
        default_columns = (
            "name",
            "type",
            "is_approved",
            "certificate_count",
        )

    def render_is_approved(self, value, record):
        """Render approval status with color coding."""
        if value:
            return format_html(
                '<span class="badge text-bg-success">Approved</span>',
            )
        return format_html(
            '<span class="badge text-bg-warning">Not Approved</span>',
        )

    def render_certificate_count(self, value, record):
        """Render certificate count."""
        count = record.certificates.count()
        return count

    def render_website_url(self, value, record):
        """Render website URL as clickable link."""
        if value:
            return format_html(
                '<a href="{}" target="_blank" rel="noopener noreferrer">{}</a>',
                value,
                value,
            )
        return "—"
