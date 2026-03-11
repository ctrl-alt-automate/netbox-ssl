"""
Analytics dashboard views for certificate landscape insights.
"""

from __future__ import annotations

from typing import Any

from django.views.generic import TemplateView

from ..utils.analytics import CertificateAnalytics

STATUS_COLORS: dict[str, str] = {
    "active": "#28a745",
    "expired": "#dc3545",
    "replaced": "#6c757d",
    "revoked": "#fd7e14",
    "pending": "#007bff",
}

ALGORITHM_COLORS: dict[str, str] = {
    "rsa": "#007bff",
    "ecdsa": "#28a745",
    "ed25519": "#6f42c1",
    "unknown": "#6c757d",
}


def _prepare_bar_data(
    items: list[dict[str, Any]],
    label_key: str,
    count_key: str,
    colors: dict[str, str],
) -> list[dict[str, Any]]:
    """Pre-process items for bar chart rendering with percentage widths."""
    max_val = max((d[count_key] for d in items), default=1)
    return [
        {
            "label": (d[label_key] or "unknown").replace("_", " ").title(),
            "count": d[count_key],
            "pct": round(d[count_key] / max_val * 100) if max_val else 0,
            "color": colors.get(d[label_key], "#6c757d"),
        }
        for d in items
    ]


class CertificateAnalyticsDashboardView(TemplateView):
    """Dashboard with aggregated certificate statistics and charts."""

    template_name = "netbox_ssl/analytics_dashboard.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        tenant_id = self.request.GET.get("tenant")
        tenant = None
        if tenant_id:
            from tenancy.models import Tenant

            tenant = Tenant.objects.filter(pk=tenant_id).first()

        analytics = CertificateAnalytics()
        dashboard = analytics.get_dashboard_context(tenant)
        context.update(dashboard)

        context["tenant"] = tenant
        context["status_bars"] = _prepare_bar_data(dashboard["status_distribution"], "status", "count", STATUS_COLORS)
        context["algo_bars"] = _prepare_bar_data(
            dashboard["algorithm_distribution"], "algorithm", "count", ALGORITHM_COLORS
        )

        # Prepare forecast bars
        forecast = dashboard["expiry_forecast"]
        max_fc = max((d["count"] for d in forecast), default=1)
        context["forecast_bars"] = [
            {
                "label": d["month"].strftime("%b %Y"),
                "count": d["count"],
                "pct": round(d["count"] / max_fc * 100) if max_fc else 0,
            }
            for d in forecast
        ]

        return context
