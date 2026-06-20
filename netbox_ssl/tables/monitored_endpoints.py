"""
Table definitions for MonitoredEndpoint model.
"""

import django_tables2 as tables
from netbox.tables import NetBoxTable, columns

from ..models import MonitoredEndpoint


class MonitoredEndpointTable(NetBoxTable):
    """Table for displaying Monitored Endpoints."""

    name = tables.Column(
        linkify=True,
    )
    url = tables.Column(
        verbose_name="URL",
    )
    status = columns.ChoiceFieldColumn()
    certificate = tables.Column(
        linkify=True,
    )
    days_remaining = tables.Column(
        verbose_name="Days Remaining",
        accessor="days_remaining",
        orderable=False,
    )
    tenant = tables.Column(
        linkify=True,
    )
    last_checked = tables.DateTimeColumn(
        verbose_name="Last Checked",
    )

    class Meta(NetBoxTable.Meta):
        model = MonitoredEndpoint
        fields = (
            "pk",
            "id",
            "name",
            "url",
            "status",
            "certificate",
            "days_remaining",
            "tenant",
            "last_checked",
        )
        default_columns = (
            "name",
            "url",
            "status",
            "certificate",
            "days_remaining",
            "last_checked",
        )
