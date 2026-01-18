"""
FilterSet for Certificate model.
"""

import django_filters
from django.db.models import Q
from netbox.filtersets import NetBoxModelFilterSet
from tenancy.models import Tenant

from ..models import Certificate, CertificateAlgorithmChoices, CertificateStatusChoices


class CertificateFilterSet(NetBoxModelFilterSet):
    """FilterSet for Certificate model."""

    common_name = django_filters.CharFilter(
        lookup_expr="icontains",
        label="Common Name",
    )
    serial_number = django_filters.CharFilter(
        lookup_expr="icontains",
        label="Serial Number",
    )
    issuer = django_filters.CharFilter(
        lookup_expr="icontains",
        label="Issuer",
    )
    status = django_filters.MultipleChoiceFilter(
        choices=CertificateStatusChoices,
        label="Status",
    )
    algorithm = django_filters.MultipleChoiceFilter(
        choices=CertificateAlgorithmChoices,
        label="Algorithm",
    )
    key_size = django_filters.NumberFilter(
        label="Key Size",
    )
    key_size__gte = django_filters.NumberFilter(
        field_name="key_size",
        lookup_expr="gte",
        label="Key Size (min)",
    )
    key_size__lte = django_filters.NumberFilter(
        field_name="key_size",
        lookup_expr="lte",
        label="Key Size (max)",
    )
    valid_from = django_filters.DateTimeFromToRangeFilter(
        label="Valid From",
    )
    valid_to = django_filters.DateTimeFromToRangeFilter(
        label="Valid To",
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
    san = django_filters.CharFilter(
        method="filter_san",
        label="Subject Alternative Name",
    )
    expiring_soon = django_filters.BooleanFilter(
        method="filter_expiring_soon",
        label="Expiring Soon (30 days)",
    )
    expired = django_filters.BooleanFilter(
        method="filter_expired",
        label="Expired",
    )
    has_assignments = django_filters.BooleanFilter(
        method="filter_has_assignments",
        label="Has Assignments",
    )

    class Meta:
        model = Certificate
        fields = [
            "id",
            "common_name",
            "serial_number",
            "fingerprint_sha256",
            "issuer",
            "status",
            "algorithm",
            "key_size",
            "tenant",
        ]

    def search(self, queryset, name, value):
        """Full-text search across multiple fields."""
        if not value.strip():
            return queryset
        return queryset.filter(
            Q(common_name__icontains=value)
            | Q(serial_number__icontains=value)
            | Q(issuer__icontains=value)
            | Q(fingerprint_sha256__icontains=value)
            | Q(sans__contains=[value])
        )

    def filter_san(self, queryset, name, value):
        """Filter by Subject Alternative Name."""
        if not value:
            return queryset
        return queryset.filter(sans__contains=[value])

    def filter_expiring_soon(self, queryset, name, value):
        """Filter certificates expiring within 30 days."""
        from datetime import timedelta

        from django.utils import timezone

        if value:
            threshold = timezone.now() + timedelta(days=30)
            return queryset.filter(
                valid_to__lte=threshold,
                valid_to__gt=timezone.now(),
            )
        return queryset

    def filter_expired(self, queryset, name, value):
        """Filter expired certificates."""
        from django.utils import timezone

        if value:
            return queryset.filter(valid_to__lt=timezone.now())
        return queryset.filter(valid_to__gte=timezone.now())

    def filter_has_assignments(self, queryset, name, value):
        """Filter certificates by whether they have assignments."""
        if value:
            return queryset.filter(assignments__isnull=False).distinct()
        return queryset.filter(assignments__isnull=True)
