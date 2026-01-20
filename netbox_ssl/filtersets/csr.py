"""
FilterSet for CertificateSigningRequest model.
"""

import django_filters
from django.db.models import Q
from netbox.filtersets import NetBoxModelFilterSet
from tenancy.models import Tenant

from ..models import CertificateSigningRequest, CSRStatusChoices


class CertificateSigningRequestFilterSet(NetBoxModelFilterSet):
    """FilterSet for CertificateSigningRequest model."""

    common_name = django_filters.CharFilter(
        lookup_expr="icontains",
        label="Common Name",
    )
    organization = django_filters.CharFilter(
        lookup_expr="icontains",
        label="Organization",
    )
    status = django_filters.MultipleChoiceFilter(
        choices=CSRStatusChoices,
        label="Status",
    )
    requested_by = django_filters.CharFilter(
        lookup_expr="icontains",
        label="Requested By",
    )
    target_ca = django_filters.CharFilter(
        lookup_expr="icontains",
        label="Target CA",
    )
    tenant_id = django_filters.ModelMultipleChoiceFilter(
        queryset=Tenant.objects.all(),
        label="Tenant",
    )
    tenant = django_filters.ModelMultipleChoiceFilter(
        queryset=Tenant.objects.all(),
        field_name="tenant__name",
        to_field_name="name",
        label="Tenant (name)",
    )
    has_certificate = django_filters.BooleanFilter(
        method="filter_has_certificate",
        label="Has Resulting Certificate",
    )

    class Meta:
        model = CertificateSigningRequest
        fields = [
            "id",
            "common_name",
            "organization",
            "status",
            "tenant",
        ]

    def search(self, queryset, name, value):
        """Full-text search across multiple fields."""
        if not value.strip():
            return queryset
        return queryset.filter(
            Q(common_name__icontains=value)
            | Q(organization__icontains=value)
            | Q(requested_by__icontains=value)
            | Q(target_ca__icontains=value)
        )

    def filter_has_certificate(self, queryset, name, value):
        """Filter CSRs by whether they have a resulting certificate."""
        if value:
            return queryset.filter(resulting_certificate__isnull=False)
        return queryset.filter(resulting_certificate__isnull=True)
