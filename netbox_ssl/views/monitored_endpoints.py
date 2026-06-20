"""
Views for MonitoredEndpoint model.
"""

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import render
from django.utils.translation import gettext_lazy as _
from django.views.generic import View
from netbox.views import generic

from ..filtersets import MonitoredEndpointFilterSet
from ..forms import MonitoredEndpointFilterForm, MonitoredEndpointForm
from ..forms.monitored_endpoints import MonitoredEndpointImportForm
from ..models import MonitoredEndpoint, MonitoredEndpointStatusChoices
from ..tables import MonitoredEndpointTable
from ..utils.url_bulk_parser import parse as parse_url_csv


class MonitoredEndpointListView(generic.ObjectListView):
    """List all Monitored Endpoints."""

    queryset = MonitoredEndpoint.objects.select_related("certificate", "tenant").prefetch_related("tags")
    filterset = MonitoredEndpointFilterSet
    filterset_form = MonitoredEndpointFilterForm
    table = MonitoredEndpointTable


class MonitoredEndpointView(generic.ObjectView):
    """Display a single Monitored Endpoint."""

    queryset = MonitoredEndpoint.objects.select_related("certificate", "tenant").prefetch_related("tags")

    def get_extra_context(self, request, instance):
        return {}


class MonitoredEndpointEditView(generic.ObjectEditView):
    """Create or edit a Monitored Endpoint."""

    queryset = MonitoredEndpoint.objects.all()
    form = MonitoredEndpointForm


class MonitoredEndpointDeleteView(generic.ObjectDeleteView):
    """Delete a Monitored Endpoint."""

    queryset = MonitoredEndpoint.objects.all()


class MonitoredEndpointBulkDeleteView(generic.BulkDeleteView):
    """Bulk delete Monitored Endpoints."""

    queryset = MonitoredEndpoint.objects.all()
    filterset = MonitoredEndpointFilterSet
    table = MonitoredEndpointTable


class MonitoredEndpointImportView(LoginRequiredMixin, View):
    """Bulk-import Monitored Endpoints from a CSV of URLs."""

    template_name = "netbox_ssl/monitored_endpoint_import.html"
    MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10 MB

    def get(self, request):
        form = MonitoredEndpointImportForm()
        return render(request, self.template_name, {"form": form, "step": "input"})

    def post(self, request):
        form = MonitoredEndpointImportForm(request.POST, request.FILES)
        if not form.is_valid():
            return render(request, self.template_name, {"form": form, "step": "input"})

        # Read content from file or pasted text.
        content = ""
        if form.cleaned_data.get("csv_file"):
            uploaded = form.cleaned_data["csv_file"]
            if uploaded.size > self.MAX_UPLOAD_SIZE:
                messages.error(request, _("File too large. Maximum is 10 MB."))
                return render(request, self.template_name, {"form": form, "step": "input"})
            content = uploaded.read().decode("utf-8-sig")
        else:
            content = form.cleaned_data.get("csv_text", "")

        if len(content.encode()) > self.MAX_UPLOAD_SIZE:
            messages.error(request, _("Pasted content too large."))
            return render(request, self.template_name, {"form": form, "step": "input"})

        result = parse_url_csv(content)

        if result.has_errors and not result.valid_rows:
            return render(
                request,
                self.template_name,
                {"form": form, "step": "input", "errors": result.errors},
            )

        created_count = 0
        updated_count = 0
        outcomes = []

        for row in result.valid_rows:
            name = row.sni or row.host
            _ep, created = MonitoredEndpoint.objects.update_or_create(
                url=row.url,
                defaults={
                    "name": name,
                    "sni": row.sni or "",
                    "status": MonitoredEndpointStatusChoices.STATUS_PENDING,
                },
            )
            if created:
                created_count += 1
                outcomes.append({"url": row.url, "action": "created"})
            else:
                updated_count += 1
                outcomes.append({"url": row.url, "action": "updated"})

        if created_count:
            messages.success(
                request,
                _("Created %(n)d monitored endpoint(s).") % {"n": created_count},
            )
        if updated_count:
            messages.info(
                request,
                _("Updated %(n)d existing monitored endpoint(s).") % {"n": updated_count},
            )
        if result.has_errors:
            messages.warning(
                request,
                _("%(n)d row(s) had errors and were skipped.") % {"n": len(result.errors)},
            )

        return render(
            request,
            self.template_name,
            {
                "form": MonitoredEndpointImportForm(),
                "step": "result",
                "outcomes": outcomes,
                "created": created_count,
                "updated": updated_count,
                "errors": result.errors,
            },
        )
