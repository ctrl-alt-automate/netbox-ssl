"""
REST API views for NetBox SSL plugin.
"""

from netbox.api.viewsets import NetBoxModelViewSet

from ..models import Certificate, CertificateAssignment
from ..filtersets import CertificateFilterSet, CertificateAssignmentFilterSet
from .serializers import CertificateSerializer, CertificateAssignmentSerializer


class CertificateViewSet(NetBoxModelViewSet):
    """API viewset for Certificate model."""

    queryset = Certificate.objects.prefetch_related(
        "tenant",
        "tags",
        "assignments",
    )
    serializer_class = CertificateSerializer
    filterset_class = CertificateFilterSet


class CertificateAssignmentViewSet(NetBoxModelViewSet):
    """API viewset for CertificateAssignment model."""

    queryset = CertificateAssignment.objects.prefetch_related(
        "certificate",
        "assigned_object_type",
        "tags",
    )
    serializer_class = CertificateAssignmentSerializer
    filterset_class = CertificateAssignmentFilterSet
