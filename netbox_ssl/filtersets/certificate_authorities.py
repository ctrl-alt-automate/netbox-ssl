"""
FilterSet for CertificateAuthority model.
"""

import django_filters
from django.db.models import Q
from netbox.filtersets import NetBoxModelFilterSet

from ..models import CATypeChoices, CertificateAuthority


class CertificateAuthorityFilterSet(NetBoxModelFilterSet):
    """FilterSet for CertificateAuthority model."""

    name = django_filters.CharFilter(
        lookup_expr="icontains",
        label="Name",
    )
    type = django_filters.MultipleChoiceFilter(
        choices=CATypeChoices,
        label="Type",
    )
    is_approved = django_filters.BooleanFilter(
        label="Is Approved",
    )
    issuer_pattern = django_filters.CharFilter(
        lookup_expr="icontains",
        label="Issuer Pattern",
    )

    class Meta:
        model = CertificateAuthority
        fields = [
            "id",
            "name",
            "type",
            "is_approved",
        ]

    def search(self, queryset, name, value):
        """Full-text search across multiple fields."""
        if not value.strip():
            return queryset
        return queryset.filter(
            Q(name__icontains=value) | Q(description__icontains=value) | Q(issuer_pattern__icontains=value)
        )
