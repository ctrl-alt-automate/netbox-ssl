"""
FilterSet for CertificateAssignment model.
"""

import django_filters
from django.contrib.contenttypes.models import ContentType
from django.db import models
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
    assigned_object = django_filters.CharFilter(
        method="filter_assigned_object_name",
        label="Assigned To (name)",
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

    def filter_assigned_object_name(self, queryset, name, value):
        """Filter on the name of the Device/VM/Service the certificate is assigned to."""
        if not value.strip():
            return queryset
        return queryset.with_assigned_object_name().filter(_assigned_object_name__icontains=value)

    def search(self, queryset, name, value):
        """Search by certificate name, assigned object name, or notes.

        The assigned object was previously unsearchable because it is a
        GenericForeignKey; the annotation makes it reachable (issue #167).
        """
        if not value.strip():
            return queryset
        return queryset.with_assigned_object_name().filter(
            models.Q(certificate__common_name__icontains=value)
            | models.Q(_assigned_object_name__icontains=value)
            | models.Q(notes__icontains=value)
        )
