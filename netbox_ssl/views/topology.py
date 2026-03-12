"""
Certificate map (topology) view.
"""

from __future__ import annotations

from typing import Any

from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import Http404, HttpRequest
from django.views.generic import TemplateView

from ..models import CertificateStatusChoices
from ..utils.topology import CertificateTopologyBuilder

_VALID_STATUSES = frozenset(s[0] for s in CertificateStatusChoices.CHOICES)


def _parse_map_filters(
    request: HttpRequest,
) -> tuple[Any, str | None, int | None]:
    """Extract tenant, status and CA filter from request query parameters."""
    from tenancy.models import Tenant

    tenant_id = request.GET.get("tenant")
    status = request.GET.get("status")
    ca_id = request.GET.get("ca")

    tenant = None
    if tenant_id and tenant_id.isdigit():
        tenant = Tenant.objects.restrict(request.user, "view").filter(pk=tenant_id).first()

    status_filter = status if status in _VALID_STATUSES else None
    ca_filter = int(ca_id) if ca_id and ca_id.isdigit() else None

    return tenant, status_filter, ca_filter


class CertificateMapView(LoginRequiredMixin, TemplateView):
    """Visual certificate topology: Tenant -> Device/VM -> Service -> Cert."""

    template_name = "netbox_ssl/certificate_map.html"

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        context = super().get_context_data(**kwargs)

        tenant, status_filter, ca_filter = _parse_map_filters(self.request)

        builder = CertificateTopologyBuilder()
        tree = builder.build_tree(
            tenant=tenant,
            status_filter=status_filter,
            ca_filter=ca_filter,
        )

        context["tree"] = tree
        context["tenant"] = tenant
        context["status_filter"] = status_filter
        context["ca_filter"] = ca_filter

        # Stats
        total_devices = sum(len(t.get("devices", [])) for t in tree)
        total_certs = sum(len(d.get("certificates", [])) for t in tree for d in t.get("devices", []))
        context["total_tenants"] = len(tree)
        context["total_devices"] = total_devices
        context["total_certs"] = total_certs

        return context


class CertificateMapFragmentView(LoginRequiredMixin, TemplateView):
    """HTMX fragment: load devices for a single tenant in the certificate map."""

    template_name = "netbox_ssl/inc/certificate_map_devices.html"

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        context = super().get_context_data(**kwargs)

        tenant, status_filter, ca_filter = _parse_map_filters(self.request)

        if not tenant:
            raise Http404("tenant parameter required")

        builder = CertificateTopologyBuilder()
        tree = builder.build_tree(
            tenant=tenant,
            status_filter=status_filter,
            ca_filter=ca_filter,
        )

        context["devices"] = tree[0].get("devices", []) if tree else []
        return context
