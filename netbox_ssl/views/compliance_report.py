"""
Compliance report view for certificate compliance overview and trends.
"""

from __future__ import annotations

from typing import Any

from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpRequest, HttpResponse
from django.views.generic import TemplateView

from ..utils.compliance_reporter import ComplianceReporter


class ComplianceReportView(LoginRequiredMixin, TemplateView):
    """Compliance report with current scores and historical trends."""

    template_name = "netbox_ssl/compliance_report.html"

    def _get_tenant(self, request: HttpRequest) -> Any | None:
        """Resolve tenant from query parameter with permission check."""
        tenant_id = request.GET.get("tenant")
        if tenant_id and tenant_id.isdigit():
            from tenancy.models import Tenant

            return Tenant.objects.restrict(request.user, "view").filter(pk=tenant_id).first()
        return None

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        context = super().get_context_data(**kwargs)

        tenant = self._get_tenant(self.request)

        reporter = ComplianceReporter()
        report = reporter.generate_report(tenant)
        trend = reporter.get_trend(tenant)

        context["tenant"] = tenant
        context["report"] = report
        context["trend"] = trend

        # Prepare trend chart bars
        if trend:
            context["trend_bars"] = [
                {
                    "label": t["snapshot_date"].strftime("%b %d"),
                    "score": t["compliance_score"],
                    "pct": round(t["compliance_score"]),
                    "passed": t["passed_checks"],
                    "failed": t["failed_checks"],
                }
                for t in trend
            ]
        else:
            context["trend_bars"] = []

        return context

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        # Handle export requests
        export_format = request.GET.get("export")
        if export_format in ("csv", "json"):
            tenant = self._get_tenant(request)

            reporter = ComplianceReporter()
            data = reporter.export_report(tenant, export_format=export_format)

            content_type = "application/json" if export_format == "json" else "text/csv"
            response = HttpResponse(data, content_type=content_type)
            response["Content-Disposition"] = f'attachment; filename="compliance_report.{export_format}"'
            return response

        return super().get(request, *args, **kwargs)
