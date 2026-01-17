"""
Views for CertificateAssignment model.
"""

from netbox.views import generic

from ..filtersets import CertificateAssignmentFilterSet
from ..forms import CertificateAssignmentForm, CertificateAssignmentFilterForm
from ..models import CertificateAssignment
from ..tables import CertificateAssignmentTable


class CertificateAssignmentListView(generic.ObjectListView):
    """List all certificate assignments."""

    queryset = CertificateAssignment.objects.prefetch_related(
        "certificate",
        "assigned_object_type",
    )
    filterset = CertificateAssignmentFilterSet
    filterset_form = CertificateAssignmentFilterForm
    table = CertificateAssignmentTable


class CertificateAssignmentView(generic.ObjectView):
    """Display a single certificate assignment."""

    queryset = CertificateAssignment.objects.prefetch_related(
        "certificate",
        "assigned_object_type",
    )


class CertificateAssignmentEditView(generic.ObjectEditView):
    """Create or edit a certificate assignment."""

    queryset = CertificateAssignment.objects.all()
    form = CertificateAssignmentForm


class CertificateAssignmentDeleteView(generic.ObjectDeleteView):
    """Delete a certificate assignment."""

    queryset = CertificateAssignment.objects.all()


class CertificateAssignmentBulkDeleteView(generic.BulkDeleteView):
    """Bulk delete certificate assignments."""

    queryset = CertificateAssignment.objects.all()
    filterset = CertificateAssignmentFilterSet
    table = CertificateAssignmentTable
