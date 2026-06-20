"""
FilterSet for MonitoredEndpoint model.
"""

import django_filters
from django.db.models import Q
from netbox.filtersets import NetBoxModelFilterSet
from tenancy.models import Tenant

from ..models import Certificate, MonitoredEndpoint, MonitoredEndpointStatusChoices


class MonitoredEndpointFilterSet(NetBoxModelFilterSet):
    """FilterSet for MonitoredEndpoint model."""

    status = django_filters.MultipleChoiceFilter(
        choices=MonitoredEndpointStatusChoices,
        label="Status",
    )
    certificate_id = django_filters.ModelMultipleChoiceFilter(
        queryset=Certificate.objects.all(),
        label="Certificate",
    )
    tenant_id = django_filters.ModelMultipleChoiceFilter(
        queryset=Tenant.objects.all(),
        label="Tenant",
    )

    class Meta:
        model = MonitoredEndpoint
        fields = [
            "id",
            "name",
            "status",
        ]

    def search(self, queryset, name, value):
        """Full-text search across name and url fields."""
        if not value.strip():
            return queryset
        return queryset.filter(
            Q(name__icontains=value) | Q(url__icontains=value)
        )
