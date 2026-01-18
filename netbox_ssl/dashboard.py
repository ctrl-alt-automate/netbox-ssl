"""
Dashboard widgets for NetBox SSL plugin.

Provides an expiry alert widget showing certificates organized by status:
- Expired: Already expired certificates
- Critical: < 14 days until expiry
- Warning: < 30 days until expiry
- Orphan: Certificates without assignments
"""

from datetime import timedelta

from django.db.models import Count
from django.template.loader import render_to_string
from django.utils import timezone
from extras.dashboard.utils import register_widget
from extras.dashboard.widgets import DashboardWidget


@register_widget
class CertificateExpiryWidget(DashboardWidget):
    """Dashboard widget showing certificate expiry status."""

    default_title = "SSL Certificate Status"
    description = "Shows certificates that are expiring soon, expired, or without assignments."
    width = 4
    height = 3

    def render(self, request):
        """Render the widget content."""
        from .models import Certificate

        now = timezone.now()
        critical_threshold = now + timedelta(days=14)
        warning_threshold = now + timedelta(days=30)

        # Get certificate lists by status (limit to 5 each)
        critical_certs = Certificate.objects.filter(
            status="active",
            valid_to__gt=now,
            valid_to__lte=critical_threshold,
        ).order_by("valid_to")[:5]

        warning_certs = Certificate.objects.filter(
            status="active",
            valid_to__gt=critical_threshold,
            valid_to__lte=warning_threshold,
        ).order_by("valid_to")[:5]

        expired_certs = Certificate.objects.filter(
            status="active",
            valid_to__lt=now,
        ).order_by("-valid_to")[:5]

        orphan_certs = Certificate.objects.filter(
            status="active",
        ).annotate(
            assignment_count=Count("assignments")
        ).filter(
            assignment_count=0
        ).order_by("valid_to")[:5]

        # Get counts for badges
        critical_count = Certificate.objects.filter(
            status="active",
            valid_to__gt=now,
            valid_to__lte=critical_threshold,
        ).count()

        warning_count = Certificate.objects.filter(
            status="active",
            valid_to__gt=critical_threshold,
            valid_to__lte=warning_threshold,
        ).count()

        expired_count = Certificate.objects.filter(
            status="active",
            valid_to__lt=now,
        ).count()

        orphan_count = Certificate.objects.filter(
            status="active",
        ).annotate(
            assignment_count=Count("assignments")
        ).filter(
            assignment_count=0
        ).count()

        return render_to_string(
            "netbox_ssl/widgets/certificate_expiry.html",
            {
                "critical_certs": critical_certs,
                "critical_count": critical_count,
                "warning_certs": warning_certs,
                "warning_count": warning_count,
                "expired_certs": expired_certs,
                "expired_count": expired_count,
                "orphan_certs": orphan_certs,
                "orphan_count": orphan_count,
            },
            request=request,
        )
