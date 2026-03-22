"""
Views for ExternalSource model.
"""

from django.db.models import Count
from netbox.views import generic

from ..filtersets import ExternalSourceFilterSet
from ..forms import (
    ExternalSourceBulkEditForm,
    ExternalSourceFilterForm,
    ExternalSourceForm,
)
from ..models import ExternalSource
from ..tables import ExternalSourceTable


class ExternalSourceListView(generic.ObjectListView):
    """List all External Sources."""

    queryset = ExternalSource.objects.prefetch_related("tenant", "tags").annotate(
        certificate_count=Count("certificates")
    )
    filterset = ExternalSourceFilterSet
    filterset_form = ExternalSourceFilterForm
    table = ExternalSourceTable


class ExternalSourceView(generic.ObjectView):
    """Display a single External Source."""

    queryset = ExternalSource.objects.prefetch_related("tenant", "tags")

    def get_extra_context(self, request, instance):
        """Add sync logs and certificate count to context."""
        sync_logs = instance.sync_logs.all()[:10]
        return {
            "sync_logs": sync_logs,
            "certificate_count": instance.certificate_count,
        }


class ExternalSourceEditView(generic.ObjectEditView):
    """Create or edit an External Source."""

    queryset = ExternalSource.objects.all()
    form = ExternalSourceForm


class ExternalSourceDeleteView(generic.ObjectDeleteView):
    """Delete an External Source."""

    queryset = ExternalSource.objects.all()


class ExternalSourceBulkEditView(generic.BulkEditView):
    """Bulk edit External Sources."""

    queryset = ExternalSource.objects.all()
    filterset = ExternalSourceFilterSet
    table = ExternalSourceTable
    form = ExternalSourceBulkEditForm


class ExternalSourceBulkDeleteView(generic.BulkDeleteView):
    """Bulk delete External Sources."""

    queryset = ExternalSource.objects.all()
    filterset = ExternalSourceFilterSet
    table = ExternalSourceTable
