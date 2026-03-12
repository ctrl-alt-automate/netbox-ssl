"""
Analytics dashboard views for certificate landscape insights.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView

from ..utils.analytics import CertificateAnalytics

STATUS_COLORS: dict[str, str] = {
    "active": "bg-success",
    "expired": "bg-danger",
    "replaced": "bg-secondary",
    "revoked": "bg-warning",
    "pending": "bg-primary",
}

ALGORITHM_COLORS: dict[str, str] = {
    "rsa": "bg-primary",
    "ecdsa": "bg-success",
    "ed25519": "bg-purple",
    "unknown": "bg-secondary",
}

# Forecast chart color band thresholds (calendar days from today)
_FORECAST_CRITICAL_DAYS = 30  # within 30 days = red
_FORECAST_WARNING_DAYS = 90  # within 90 days = yellow


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
            "color": colors.get(d[label_key], "bg-secondary"),
        }
        for d in items
    ]


class CertificateAnalyticsDashboardView(LoginRequiredMixin, TemplateView):
    """Dashboard with aggregated certificate statistics and charts."""

    template_name = "netbox_ssl/analytics_dashboard.html"

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        context = super().get_context_data(**kwargs)

        tenant_id = self.request.GET.get("tenant")
        tenant = None
        if tenant_id and tenant_id.isdigit():
            from tenancy.models import Tenant

            tenant = Tenant.objects.restrict(self.request.user, "view").filter(pk=tenant_id).first()

        analytics = CertificateAnalytics()
        dashboard = analytics.get_dashboard_context(tenant)
        context.update(dashboard)

        context["tenant"] = tenant
        context["status_bars"] = _prepare_bar_data(dashboard["status_distribution"], "status", "count", STATUS_COLORS)
        context["algo_bars"] = _prepare_bar_data(
            dashboard["algorithm_distribution"], "algorithm", "count", ALGORITHM_COLORS
        )

        # Prepare forecast bars with contextual colors based on calendar date
        forecast = dashboard["expiry_forecast"]
        max_fc = max((d["count"] for d in forecast), default=1)
        today = date.today()
        forecast_bars: list[dict[str, Any]] = []
        for d in forecast:
            days_away = (d["month"].date() - today).days if hasattr(d["month"], "date") else (d["month"] - today).days
            if days_away <= _FORECAST_CRITICAL_DAYS:
                color = "bg-danger"
            elif days_away <= _FORECAST_WARNING_DAYS:
                color = "bg-warning"
            else:
                color = "bg-info"
            forecast_bars.append(
                {
                    "label": d["month"].strftime("%b %Y"),
                    "count": d["count"],
                    "pct": round(d["count"] / max_fc * 100) if max_fc else 0,
                    "color": color,
                }
            )
        context["forecast_bars"] = forecast_bars

        return context
