"""
Table definitions for CompliancePolicy and ComplianceCheck models.
"""

import django_tables2 as tables
from netbox.tables import NetBoxTable, columns

from ..models import ComplianceCheck, CompliancePolicy


class CompliancePolicyTable(NetBoxTable):
    """Table for displaying compliance policies."""

    name = tables.Column(
        linkify=True,
    )
    policy_type = columns.ChoiceFieldColumn(
        verbose_name="Type",
    )
    severity = columns.ChoiceFieldColumn()
    enabled = columns.BooleanColumn()
    tenant = tables.Column(
        linkify=True,
    )
    check_count = tables.Column(
        verbose_name="Checks",
        accessor="check_count",
        # A real annotation (Count("checks")) added by CompliancePolicyListView,
        # so the database can order on it -- no reason to disable sorting.
        order_by="check_count",
    )
    tags = columns.TagColumn(
        url_name="plugins:netbox_ssl:compliancepolicy_list",
    )

    class Meta(NetBoxTable.Meta):
        model = CompliancePolicy
        fields = (
            "pk",
            "id",
            "name",
            "description",
            "policy_type",
            "severity",
            "enabled",
            "tenant",
            "check_count",
            "tags",
        )
        default_columns = (
            "name",
            "policy_type",
            "severity",
            "enabled",
            "tenant",
            "check_count",
        )


class ComplianceCheckTable(NetBoxTable):
    """Table for displaying compliance check results."""

    certificate = tables.Column(
        linkify=True,
    )
    policy = tables.Column(
        linkify=True,
    )
    result = columns.ChoiceFieldColumn()
    severity = tables.Column(
        accessor="policy__severity",
        verbose_name="Severity",
        orderable=True,
    )
    checked_at = columns.DateTimeColumn(
        verbose_name="Checked At",
    )

    class Meta(NetBoxTable.Meta):
        model = ComplianceCheck
        fields = (
            "pk",
            "id",
            "certificate",
            "policy",
            "result",
            "severity",
            "message",
            "checked_value",
            "expected_value",
            "checked_at",
        )
        default_columns = (
            "certificate",
            "policy",
            "result",
            "severity",
            "message",
            "checked_at",
        )
