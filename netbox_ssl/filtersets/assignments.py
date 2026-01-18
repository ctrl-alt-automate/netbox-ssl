"""
FilterSet for CertificateAssignment model.
"""

import django_filters
from django.contrib.contenttypes.models import ContentType
from netbox.filtersets import NetBoxModelFilterSet

from ..models import Certificate, CertificateAssignment


class CertificateAssignmentFilterSet(NetBoxModelFilterSet):
    """FilterSet for CertificateAssignment model."""

    certificate_id = django_filters.ModelMultipleChoiceFilter(
        queryset=Certificate.objects.all(),
        label="Certificate",
    )
    certificate = django_filters.CharFilter(
        field_name="certificate__common_name",
        lookup_expr="icontains",
        label="Certificate (name)",
    )
    assigned_object_type_id = django_filters.ModelMultipleChoiceFilter(
        queryset=ContentType.objects.filter(model__in=["service", "device", "virtualmachine"]),
        label="Object Type",
    )
    is_primary = django_filters.BooleanFilter(
        label="Is Primary",
    )

    class Meta:
        model = CertificateAssignment
        fields = [
            "id",
            "certificate_id",
            "assigned_object_type_id",
            "assigned_object_id",
            "is_primary",
        ]

    def search(self, queryset, name, value):
        """Search assignments by certificate name or notes."""
        if not value.strip():
            return queryset
        return queryset.filter(certificate__common_name__icontains=value) | queryset.filter(notes__icontains=value)
