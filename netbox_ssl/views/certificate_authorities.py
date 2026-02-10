"""
Views for CertificateAuthority model.
"""

from netbox.views import generic

from ..filtersets import CertificateAuthorityFilterSet
from ..forms import (
    CertificateAuthorityBulkEditForm,
    CertificateAuthorityFilterForm,
    CertificateAuthorityForm,
)
from ..models import CertificateAuthority
from ..tables import CertificateAuthorityTable


class CertificateAuthorityListView(generic.ObjectListView):
    """List all Certificate Authorities."""

    queryset = CertificateAuthority.objects.prefetch_related("certificates")
    filterset = CertificateAuthorityFilterSet
    filterset_form = CertificateAuthorityFilterForm
    table = CertificateAuthorityTable


class CertificateAuthorityView(generic.ObjectView):
    """Display a single Certificate Authority."""

    queryset = CertificateAuthority.objects.prefetch_related("certificates")

    def get_extra_context(self, request, instance):
        """Add certificates to context."""
        certificates = instance.certificates.all()[:10]
        return {
            "certificates": certificates,
            "certificates_count": instance.certificates.count(),
        }


class CertificateAuthorityEditView(generic.ObjectEditView):
    """Create or edit a Certificate Authority."""

    queryset = CertificateAuthority.objects.all()
    form = CertificateAuthorityForm


class CertificateAuthorityDeleteView(generic.ObjectDeleteView):
    """Delete a Certificate Authority."""

    queryset = CertificateAuthority.objects.all()


class CertificateAuthorityBulkEditView(generic.BulkEditView):
    """Bulk edit Certificate Authorities."""

    queryset = CertificateAuthority.objects.all()
    filterset = CertificateAuthorityFilterSet
    table = CertificateAuthorityTable
    form = CertificateAuthorityBulkEditForm


class CertificateAuthorityBulkDeleteView(generic.BulkDeleteView):
    """Bulk delete Certificate Authorities."""

    queryset = CertificateAuthority.objects.all()
    filterset = CertificateAuthorityFilterSet
    table = CertificateAuthorityTable
