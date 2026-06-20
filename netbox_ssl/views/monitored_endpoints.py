"""
Views for MonitoredEndpoint model.
"""

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.contenttypes.models import ContentType
from django.shortcuts import redirect, render
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

    queryset = MonitoredEndpoint.objects.select_related("certificate", "tenant").prefetch_related(
        "tags",
        "cert_history__certificate",
    )


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
        if not request.user.has_perm("netbox_ssl.add_monitoredendpoint"):
            messages.error(request, _("You do not have permission to create monitored endpoints."))
            return redirect("plugins:netbox_ssl:monitoredendpoint_list")

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

        from tenancy.models import Tenant

        user_tenants = Tenant.objects.restrict(request.user, "view")

        created_count = 0
        updated_count = 0
        outcomes = []

        for row in result.valid_rows:
            name = row.sni or row.host
            tenant = self._resolve_tenant(row.tenant, user_tenants)
            assigned_object_type, assigned_object_id = self._resolve_assignment(
                row.assigned_device,
                row.assigned_vm,
                row.assigned_service,
            )
            # Rows are already HTTPS-validated by url_bulk_parser (_normalize_url enforces
            # HTTPS-only), so update_or_create (which bypasses Model.clean()) is safe here.
            defaults = {
                "name": name,
                "sni": row.sni or "",
                "status": MonitoredEndpointStatusChoices.STATUS_PENDING,
            }
            if tenant is not None:
                defaults["tenant"] = tenant
            if assigned_object_type is not None:
                defaults["assigned_object_type"] = assigned_object_type
                defaults["assigned_object_id"] = assigned_object_id
            _ep, created = MonitoredEndpoint.objects.update_or_create(
                url=row.url,
                defaults=defaults,
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

    @staticmethod
    def _resolve_tenant(ref, user_tenants):
        """Resolve a tenant name/slug/ID string against the user's accessible tenants."""
        ref = (ref or "").strip()
        if not ref:
            return None
        if ref.isdigit():
            tenant = user_tenants.filter(pk=int(ref)).first()
            if tenant:
                return tenant
        return user_tenants.filter(name=ref).first() or user_tenants.filter(slug=ref).first()

    @staticmethod
    def _resolve_assignment(
        device_ref: str,
        vm_ref: str,
        service_ref: str,
    ) -> tuple:
        """Resolve device/VM/service reference strings to (ContentType, pk) or (None, None).

        Priority: service > device > VM (mirrors MonitoredEndpointForm.save()).
        Reference format: name or numeric ID.  Returns (None, None) when no ref given
        or no matching object found — callers should skip setting assigned_object fields.
        """
        from dcim.models import Device
        from ipam.models import Service
        from virtualization.models import VirtualMachine

        def _lookup(qs, ref):
            ref = (ref or "").strip()
            if not ref:
                return None
            if ref.isdigit():
                return qs.filter(pk=int(ref)).first()
            return qs.filter(name=ref).first()

        service = _lookup(Service.objects.all(), service_ref)
        if service:
            ct = ContentType.objects.get_for_model(Service)
            return ct, service.pk

        device = _lookup(Device.objects.all(), device_ref)
        if device:
            ct = ContentType.objects.get_for_model(Device)
            return ct, device.pk

        vm = _lookup(VirtualMachine.objects.all(), vm_ref)
        if vm:
            ct = ContentType.objects.get_for_model(VirtualMachine)
            return ct, vm.pk

        return None, None
