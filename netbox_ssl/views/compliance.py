"""
Views for CompliancePolicy and ComplianceCheck models.

The compliance data model, filtersets and REST API shipped in v0.7 but the
presentation layer was never wired up, so policies were reachable only through
the API even though both models declare ``get_absolute_url()`` and the docs
described an Admin UI (issue #164).

ComplianceCheck rows are *results*, produced by the checker rather than typed in
by an operator, so they get list and detail views but no create/edit form.
"""

from django.db.models import Count
from netbox.views import generic

from ..filtersets import ComplianceCheckFilterSet, CompliancePolicyFilterSet
from ..forms import ComplianceCheckFilterForm, CompliancePolicyFilterForm, CompliancePolicyForm
from ..models import ComplianceCheck, CompliancePolicy, ComplianceResultChoices
from ..tables import ComplianceCheckTable, CompliancePolicyTable


class CompliancePolicyListView(generic.ObjectListView):
    """List all compliance policies."""

    queryset = CompliancePolicy.objects.select_related("tenant").annotate(check_count=Count("checks"))
    filterset = CompliancePolicyFilterSet
    filterset_form = CompliancePolicyFilterForm
    table = CompliancePolicyTable


class CompliancePolicyView(generic.ObjectView):
    """Display a single compliance policy and its most recent results."""

    queryset = CompliancePolicy.objects.select_related("tenant").prefetch_related("tags", "tag_filter")

    def get_extra_context(self, request, instance):
        """Count the certificates currently failing this policy.

        The results table itself is rendered by ``{% htmx_table %}`` against the
        compliance check list view, so it is lazily loaded, paginated and
        permission-filtered by that view rather than assembled here.
        """
        failing = (
            ComplianceCheck.objects.restrict(request.user, "view")
            .filter(policy=instance, result=ComplianceResultChoices.RESULT_FAIL)
            .count()
        )
        return {"failing_count": failing}


class CompliancePolicyEditView(generic.ObjectEditView):
    """Create or edit a compliance policy."""

    queryset = CompliancePolicy.objects.all()
    form = CompliancePolicyForm


class CompliancePolicyDeleteView(generic.ObjectDeleteView):
    """Delete a compliance policy."""

    queryset = CompliancePolicy.objects.all()


class CompliancePolicyBulkDeleteView(generic.BulkDeleteView):
    """Delete multiple compliance policies."""

    queryset = CompliancePolicy.objects.all()
    filterset = CompliancePolicyFilterSet
    table = CompliancePolicyTable


class ComplianceCheckListView(generic.ObjectListView):
    """List compliance check results."""

    queryset = ComplianceCheck.objects.select_related("certificate", "policy")
    filterset = ComplianceCheckFilterSet
    filterset_form = ComplianceCheckFilterForm
    table = ComplianceCheckTable
    # Results are produced by the checker, so no add/import actions -- but a
    # stale result set should still be clearable in bulk.
    actions = {"export": {"view"}, "bulk_delete": {"delete"}}


class ComplianceCheckView(generic.ObjectView):
    """Display a single compliance check result."""

    queryset = ComplianceCheck.objects.select_related("certificate", "policy")


class ComplianceCheckBulkDeleteView(generic.BulkDeleteView):
    """Delete multiple compliance check results."""

    queryset = ComplianceCheck.objects.all()
    filterset = ComplianceCheckFilterSet
    table = ComplianceCheckTable
