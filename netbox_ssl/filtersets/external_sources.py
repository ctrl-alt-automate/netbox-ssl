"""
FilterSet for ExternalSource model.
"""

import django_filters
from django.db.models import Q
from netbox.filtersets import NetBoxModelFilterSet
from tenancy.models import Tenant

from ..models import ExternalSource, ExternalSourceTypeChoices, SyncStatusChoices


class ExternalSourceFilterSet(NetBoxModelFilterSet):
    """FilterSet for ExternalSource model."""

    name = django_filters.CharFilter(
        lookup_expr="icontains",
        label="Name",
    )
    source_type = django_filters.MultipleChoiceFilter(
        choices=ExternalSourceTypeChoices,
        label="Source Type",
    )
    enabled = django_filters.BooleanFilter(
        label="Enabled",
    )
    sync_status = django_filters.MultipleChoiceFilter(
        choices=SyncStatusChoices,
        label="Sync Status",
    )
    tenant_id = django_filters.ModelMultipleChoiceFilter(
        queryset=Tenant.objects.all(),
        label="Tenant",
    )

    class Meta:
        model = ExternalSource
        fields = [
            "id",
            "name",
            "source_type",
            "enabled",
            "sync_status",
        ]

    def search(self, queryset, name, value):
        """Full-text search across multiple fields."""
        if not value.strip():
            return queryset
        return queryset.filter(
            Q(name__icontains=value) | Q(base_url__icontains=value) | Q(last_sync_message__icontains=value)
        )
