"""
Certificate Expiry Notification Script.

This script checks for certificates that are expiring soon and generates
notifications. It can be scheduled via NetBox's job scheduler or triggered
manually. Results can be sent to external systems via webhooks.
"""

from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from extras.scripts import BooleanVar, IntegerVar, ObjectVar, Script

from netbox_ssl.models import Certificate, CertificateStatusChoices


class CertificateExpiryNotification(Script):
    """
    Check for expiring certificates and generate notifications.

    This script queries the certificate database for certificates that will
    expire within the specified thresholds and outputs a report suitable
    for webhook notifications or manual review.
    """

    class Meta:
        name = "Certificate Expiry Notification"
        description = "Check for expiring certificates and generate alerts"
        commit_default = False
        job_timeout = 300

    # Script variables
    warning_days = IntegerVar(
        description="Days before expiry to trigger warning (default: plugin setting)",
        default=None,
        required=False,
    )
    critical_days = IntegerVar(
        description="Days before expiry to trigger critical alert (default: plugin setting)",
        default=None,
        required=False,
    )
    tenant = ObjectVar(
        model="tenancy.Tenant",
        description="Filter certificates by tenant (optional)",
        required=False,
    )
    include_expired = BooleanVar(
        description="Include already expired certificates in the report",
        default=True,
    )
    active_only = BooleanVar(
        description="Only check certificates with 'Active' status",
        default=True,
    )

    def get_plugin_setting(self, setting_name, default=None):
        """Get a plugin setting value."""
        plugin_settings = getattr(settings, "PLUGINS_CONFIG", {}).get("netbox_ssl", {})
        return plugin_settings.get(setting_name, default)

    def run(self, data, commit):
        """Execute the expiry notification check."""
        # Get thresholds from input or plugin settings
        # Use explicit None check to allow 0 as a valid value
        warning_days = data.get("warning_days")
        if warning_days is None:
            warning_days = self.get_plugin_setting("expiry_warning_days", 30)
        critical_days = data.get("critical_days")
        if critical_days is None:
            critical_days = self.get_plugin_setting("expiry_critical_days", 14)
        tenant = data.get("tenant")
        include_expired = data.get("include_expired", True)
        active_only = data.get("active_only", True)

        self.log_info("Checking certificates with thresholds:")
        self.log_info(f"  Warning: {warning_days} days")
        self.log_info(f"  Critical: {critical_days} days")

        now = timezone.now()
        warning_threshold = now + timedelta(days=warning_days)
        critical_threshold = now + timedelta(days=critical_days)

        # Build base queryset
        queryset = Certificate.objects.all()

        # Filter by status if requested
        if active_only:
            queryset = queryset.filter(status=CertificateStatusChoices.STATUS_ACTIVE)

        # Filter by tenant if specified
        if tenant:
            queryset = queryset.filter(tenant=tenant)
            self.log_info(f"  Tenant filter: {tenant.name}")

        # Categorize certificates with a single optimized query
        expired = []
        critical = []
        warning = []

        # Fetch all certificates within the warning threshold in one query
        certs_to_check = queryset.filter(valid_to__lte=warning_threshold)
        if not include_expired:
            certs_to_check = certs_to_check.filter(valid_to__gte=now)

        for cert in certs_to_check.order_by("valid_to"):
            if cert.valid_to < now:
                expired.append(cert)
            elif cert.valid_to <= critical_threshold:
                critical.append(cert)
            else:
                warning.append(cert)

        # Generate report
        total_alerts = len(expired) + len(critical) + len(warning)

        self.log_info(f"\n{'=' * 60}")
        self.log_info("CERTIFICATE EXPIRY REPORT")
        self.log_info(f"{'=' * 60}")
        self.log_info(f"Generated: {now.strftime('%Y-%m-%d %H:%M:%S %Z')}")
        self.log_info(f"Total alerts: {total_alerts}")

        # Report expired certificates
        if expired:
            self.log_failure(f"\nEXPIRED CERTIFICATES ({len(expired)}):")
            self.log_failure("-" * 40)
            for cert in expired:
                days_ago = (now - cert.valid_to).days
                self.log_failure(f"  [{cert.pk}] {cert.common_name}")
                self.log_failure(f"      Expired: {cert.valid_to.strftime('%Y-%m-%d')} ({days_ago} days ago)")
                self.log_failure(
                    f"      Issuer: {cert.issuer[:50]}..." if len(cert.issuer) > 50 else f"      Issuer: {cert.issuer}"
                )
                if cert.tenant:
                    self.log_failure(f"      Tenant: {cert.tenant.name}")

        # Report critical certificates
        if critical:
            self.log_warning(f"\nCRITICAL - Expiring within {critical_days} days ({len(critical)}):")
            self.log_warning("-" * 40)
            for cert in critical:
                days_left = (cert.valid_to - now).days
                self.log_warning(f"  [{cert.pk}] {cert.common_name}")
                self.log_warning(f"      Expires: {cert.valid_to.strftime('%Y-%m-%d')} ({days_left} days left)")
                self.log_warning(
                    f"      Issuer: {cert.issuer[:50]}..." if len(cert.issuer) > 50 else f"      Issuer: {cert.issuer}"
                )
                if cert.tenant:
                    self.log_warning(f"      Tenant: {cert.tenant.name}")

        # Report warning certificates
        if warning:
            self.log_info(f"\nWARNING - Expiring within {warning_days} days ({len(warning)}):")
            self.log_info("-" * 40)
            for cert in warning:
                days_left = (cert.valid_to - now).days
                self.log_info(f"  [{cert.pk}] {cert.common_name}")
                self.log_info(f"      Expires: {cert.valid_to.strftime('%Y-%m-%d')} ({days_left} days left)")
                self.log_info(
                    f"      Issuer: {cert.issuer[:50]}..." if len(cert.issuer) > 50 else f"      Issuer: {cert.issuer}"
                )
                if cert.tenant:
                    self.log_info(f"      Tenant: {cert.tenant.name}")

        if total_alerts == 0:
            self.log_success("\nNo certificates require attention.")

        self.log_info(f"\n{'=' * 60}")

        # Return structured data for webhook consumption
        return {
            "summary": {
                "total_alerts": total_alerts,
                "expired_count": len(expired),
                "critical_count": len(critical),
                "warning_count": len(warning),
                "thresholds": {
                    "warning_days": warning_days,
                    "critical_days": critical_days,
                },
                "filters": {
                    "tenant": tenant.name if tenant else None,
                    "active_only": active_only,
                    "include_expired": include_expired,
                },
                "generated_at": now.isoformat(),
            },
            "expired": [
                {
                    "id": cert.pk,
                    "common_name": cert.common_name,
                    "serial_number": cert.serial_number,
                    "issuer": cert.issuer,
                    "valid_to": cert.valid_to.isoformat(),
                    "days_expired": (now - cert.valid_to).days,
                    "tenant": cert.tenant.name if cert.tenant else None,
                    "url": cert.get_absolute_url(),
                }
                for cert in expired
            ],
            "critical": [
                {
                    "id": cert.pk,
                    "common_name": cert.common_name,
                    "serial_number": cert.serial_number,
                    "issuer": cert.issuer,
                    "valid_to": cert.valid_to.isoformat(),
                    "days_remaining": (cert.valid_to - now).days,
                    "tenant": cert.tenant.name if cert.tenant else None,
                    "url": cert.get_absolute_url(),
                }
                for cert in critical
            ],
            "warning": [
                {
                    "id": cert.pk,
                    "common_name": cert.common_name,
                    "serial_number": cert.serial_number,
                    "issuer": cert.issuer,
                    "valid_to": cert.valid_to.isoformat(),
                    "days_remaining": (cert.valid_to - now).days,
                    "tenant": cert.tenant.name if cert.tenant else None,
                    "url": cert.get_absolute_url(),
                }
                for cert in warning
            ],
        }
