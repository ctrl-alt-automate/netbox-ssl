"""
Dashboard widgets for NetBox SSL plugin.

Provides an expiry alert widget showing certificates organized by status:
- Critical: < 14 days
- Warning: < 30 days
- Orphan: Certificates without assignments
"""

from datetime import timedelta

from django.db.models import Count, Q
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from netbox.plugins import PluginTemplateExtension


class CertificateExpiryWidget(PluginTemplateExtension):
    """Dashboard widget showing certificate expiry status."""

    model = "netbox_ssl.certificate"

    def right_page(self):
        """Render the widget content."""
        from .models import Certificate

        now = timezone.now()
        critical_threshold = now + timedelta(days=14)
        warning_threshold = now + timedelta(days=30)

        # Get certificate counts by status
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

        # Counts for badges
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

        return self.render(
            "netbox_ssl/widgets/certificate_expiry.html",
            extra_context={
                "critical_certs": critical_certs,
                "critical_count": critical_count,
                "warning_certs": warning_certs,
                "warning_count": warning_count,
                "expired_certs": expired_certs,
                "expired_count": expired_count,
                "orphan_certs": orphan_certs,
                "orphan_count": orphan_count,
            },
        )


# Register template extensions
template_extensions = [CertificateExpiryWidget]
