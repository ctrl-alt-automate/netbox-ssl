"""
Certificate map (topology) view.
"""

from __future__ import annotations

from django.views.generic import TemplateView

from ..utils.topology import CertificateTopologyBuilder


class CertificateMapView(TemplateView):
    """Visual certificate topology: Tenant -> Device/VM -> Service -> Cert."""

    template_name = "netbox_ssl/certificate_map.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Parse filters
        tenant_id = self.request.GET.get("tenant")
        status = self.request.GET.get("status")
        ca_id = self.request.GET.get("ca")

        tenant = None
        if tenant_id:
            from tenancy.models import Tenant

            tenant = Tenant.objects.filter(pk=tenant_id).first()

        ca_filter = int(ca_id) if ca_id and ca_id.isdigit() else None

        builder = CertificateTopologyBuilder()
        tree = builder.build_tree(
            tenant=tenant,
            status_filter=status or None,
            ca_filter=ca_filter,
        )

        context["tree"] = tree
        context["tenant"] = tenant
        context["status_filter"] = status
        context["ca_filter"] = ca_id

        # Stats
        total_devices = sum(len(t["devices"]) for t in tree)
        total_certs = sum(
            len(d["certificates"]) for t in tree for d in t["devices"]
        )
        context["total_tenants"] = len(tree)
        context["total_devices"] = total_devices
        context["total_certs"] = total_certs

        return context
