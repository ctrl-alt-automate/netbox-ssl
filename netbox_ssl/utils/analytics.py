"""
Certificate analytics aggregation utilities.

Provides server-side aggregation via Django ORM for the analytics dashboard.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from django.db.models import Avg, Count, F, Q
from django.db.models.functions import TruncMonth
from django.utils import timezone


class CertificateAnalytics:
    """Aggregate certificate statistics for dashboard display."""

    def __init__(self) -> None:
        # Lazy import to avoid circular imports
        from netbox_ssl.models import Certificate, CertificateAssignment

        self.Certificate = Certificate
        self.CertificateAssignment = CertificateAssignment

    def _base_qs(self, tenant: Any | None = None):
        """Return base queryset, optionally filtered by tenant."""
        qs = self.Certificate.objects.all()
        if tenant is not None:
            qs = qs.filter(tenant=tenant)
        return qs

    def get_status_distribution(self, tenant: Any | None = None) -> list[dict[str, Any]]:
        """Count certificates per status."""
        return list(self._base_qs(tenant).values("status").annotate(count=Count("id")).order_by("status"))

    def get_ca_distribution(self, tenant: Any | None = None) -> list[dict[str, Any]]:
        """Count certificates per issuing CA."""
        return list(
            self._base_qs(tenant)
            .filter(issuing_ca__isnull=False)
            .values(name=F("issuing_ca__name"))
            .annotate(count=Count("id"))
            .order_by("-count")
        )

    def get_algorithm_distribution(self, tenant: Any | None = None) -> list[dict[str, Any]]:
        """Count certificates per key algorithm."""
        return list(self._base_qs(tenant).values("algorithm").annotate(count=Count("id")).order_by("-count"))

    def get_avg_remaining_days(self, tenant: Any | None = None) -> float | None:
        """Average days remaining on active certificates."""
        now = timezone.now()
        result = (
            self._base_qs(tenant)
            .filter(status="active", valid_to__gt=now)
            .aggregate(avg_remaining=Avg(F("valid_to") - now))
        )
        delta = result["avg_remaining"]
        if delta is None:
            return None
        return delta.total_seconds() / 86400

    def get_orphan_count(self, tenant: Any | None = None) -> int:
        """Count active certificates with no assignments."""
        return (
            self._base_qs(tenant)
            .filter(status="active")
            .annotate(assignment_count=Count("assignments"))
            .filter(assignment_count=0)
            .count()
        )

    def get_acme_distribution(self, tenant: Any | None = None) -> dict[str, int]:
        """Count ACME vs non-ACME certificates."""
        qs = self._base_qs(tenant).filter(status="active")
        acme = qs.filter(is_acme=True).count()
        non_acme = qs.filter(Q(is_acme=False) | Q(is_acme__isnull=True)).count()
        return {"acme": acme, "non_acme": non_acme}

    def get_expiry_forecast(self, tenant: Any | None = None, months: int = 12) -> list[dict[str, Any]]:
        """Count certificates expiring per month for the next N months."""
        now = timezone.now()
        end = now + timedelta(days=months * 30)
        return list(
            self._base_qs(tenant)
            .filter(status="active", valid_to__gt=now, valid_to__lte=end)
            .annotate(month=TruncMonth("valid_to"))
            .values("month")
            .annotate(count=Count("id"))
            .order_by("month")
        )

    def get_total_active(self, tenant: Any | None = None) -> int:
        """Count of active certificates."""
        return self._base_qs(tenant).filter(status="active").count()

    def get_dashboard_context(self, tenant: Any | None = None) -> dict[str, Any]:
        """Build complete dashboard context in a single call."""
        return {
            "status_distribution": self.get_status_distribution(tenant),
            "ca_distribution": self.get_ca_distribution(tenant),
            "algorithm_distribution": self.get_algorithm_distribution(tenant),
            "avg_remaining_days": self.get_avg_remaining_days(tenant),
            "orphan_count": self.get_orphan_count(tenant),
            "acme_distribution": self.get_acme_distribution(tenant),
            "expiry_forecast": self.get_expiry_forecast(tenant),
            "total_active": self.get_total_active(tenant),
        }
