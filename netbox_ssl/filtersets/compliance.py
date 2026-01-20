"""
FilterSets for compliance reporting models.
"""

import django_filters
from django.db import models
from netbox.filtersets import NetBoxModelFilterSet

from ..models import (
    ComplianceCheck,
    CompliancePolicy,
    CompliancePolicyTypeChoices,
    ComplianceResultChoices,
    ComplianceSeverityChoices,
)


class CompliancePolicyFilterSet(NetBoxModelFilterSet):
    """FilterSet for CompliancePolicy model."""

    name = django_filters.CharFilter(lookup_expr="icontains")
    policy_type = django_filters.MultipleChoiceFilter(
        choices=CompliancePolicyTypeChoices.CHOICES,
    )
    severity = django_filters.MultipleChoiceFilter(
        choices=ComplianceSeverityChoices.CHOICES,
    )
    enabled = django_filters.BooleanFilter()
    tenant_id = django_filters.NumberFilter()
    tenant = django_filters.CharFilter(
        field_name="tenant__name",
        lookup_expr="icontains",
    )

    class Meta:
        model = CompliancePolicy
        fields = [
            "id",
            "name",
            "policy_type",
            "severity",
            "enabled",
            "tenant_id",
            "tenant",
        ]

    def search(self, queryset, name, value):
        """Search by name or description."""
        if not value.strip():
            return queryset
        return queryset.filter(
            models.Q(name__icontains=value) | models.Q(description__icontains=value)
        )


class ComplianceCheckFilterSet(NetBoxModelFilterSet):
    """FilterSet for ComplianceCheck model."""

    certificate_id = django_filters.NumberFilter()
    certificate = django_filters.CharFilter(
        field_name="certificate__common_name",
        lookup_expr="icontains",
    )
    policy_id = django_filters.NumberFilter()
    policy = django_filters.CharFilter(
        field_name="policy__name",
        lookup_expr="icontains",
    )
    result = django_filters.MultipleChoiceFilter(
        choices=ComplianceResultChoices.CHOICES,
    )
    severity = django_filters.MultipleChoiceFilter(
        field_name="policy__severity",
        choices=ComplianceSeverityChoices.CHOICES,
    )
    checked_after = django_filters.DateTimeFilter(
        field_name="checked_at",
        lookup_expr="gte",
    )
    checked_before = django_filters.DateTimeFilter(
        field_name="checked_at",
        lookup_expr="lte",
    )

    class Meta:
        model = ComplianceCheck
        fields = [
            "id",
            "certificate_id",
            "certificate",
            "policy_id",
            "policy",
            "result",
            "severity",
            "checked_after",
            "checked_before",
        ]

    def search(self, queryset, name, value):
        """Search by certificate name or message."""
        if not value.strip():
            return queryset
        return queryset.filter(
            models.Q(certificate__common_name__icontains=value)
            | models.Q(message__icontains=value)
        )
