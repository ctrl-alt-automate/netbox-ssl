"""
Auto-Archive Policy for expired certificates.

Archives certificates that have been expired for longer than the configured
threshold (default: 90 days). Certificates with archive_pinned=True are
skipped. Designed to be scheduled via NetBox's job scheduler or run manually.

Follows the same idempotent, auditable pattern as the expiry scan script.
"""

from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from extras.scripts import BooleanVar, IntegerVar, ObjectVar, Script

from netbox_ssl.models import Certificate, CertificateStatusChoices
from netbox_ssl.utils.events import (
    EVENT_CERTIFICATE_ARCHIVED,
    fire_certificate_event,
)


class CertificateAutoArchive(Script):
    """
    Auto-archive expired certificates past a configurable threshold.

    This script finds certificates with status "expired" that have been
    expired for longer than the configured number of days, and transitions
    them to "archived" status. Pinned certificates are always skipped.

    Features:
    - Configurable archive threshold (default: 90 days from plugin settings)
    - Per-tenant filtering
    - Dry-run mode for previewing changes
    - Override days parameter for ad-hoc runs
    - Fires certificate_archived events for Event Rules
    """

    class Meta:
        name = "Certificate Auto-Archive"
        description = "Archive expired certificates past the configured threshold"
        commit_default = True
        job_timeout = 600

    # Script variables
    tenant = ObjectVar(
        model="tenancy.Tenant",
        description="Filter certificates by tenant (optional)",
        required=False,
    )
    dry_run = BooleanVar(
        description="Preview mode: show what would be archived without making changes",
        default=False,
    )
    override_days = IntegerVar(
        description="Override the plugin setting for archive_after_days (optional)",
        required=False,
    )

    def get_plugin_setting(self, name: str, default=None):
        """Get a plugin setting value."""
        return settings.PLUGINS_CONFIG.get("netbox_ssl", {}).get(name, default)

    def run(self, data, commit):
        """Execute the auto-archive scan."""
        now = timezone.now()
        tenant = data.get("tenant")
        dry_run = data.get("dry_run", False)
        override_days = data.get("override_days")

        # Determine archive threshold
        if override_days is not None:
            archive_days = override_days
        else:
            archive_days = self.get_plugin_setting("auto_archive_after_days", 90)

        cutoff_date = now - timedelta(days=archive_days)

        self.log_info(f"Certificate Auto-Archive — {now.strftime('%Y-%m-%d %H:%M:%S %Z')}")
        self.log_info(f"  Archive threshold: {archive_days} days")
        self.log_info(f"  Cutoff date: {cutoff_date.strftime('%Y-%m-%d %H:%M:%S %Z')}")
        if tenant:
            self.log_info(f"  Tenant filter: {tenant.name}")
        if dry_run:
            self.log_warning("  DRY RUN MODE — no changes will be made")

        # Build queryset: expired, not pinned, expired before cutoff
        queryset = Certificate.objects.filter(
            status=CertificateStatusChoices.STATUS_EXPIRED,
            archive_pinned=False,
            valid_to__lt=cutoff_date,
        ).select_related("tenant")

        if tenant:
            queryset = queryset.filter(tenant=tenant)

        total_candidates = queryset.count()
        self.log_info(f"\nFound {total_candidates} candidates for archival...")

        archived_count = 0
        skipped_count = 0
        event_payloads = []

        for cert in queryset:
            self.log_info(f"  Archiving: {cert.common_name} (expired {cert.days_expired} days ago, id={cert.pk})")

            if not dry_run and commit:
                cert.status = CertificateStatusChoices.STATUS_ARCHIVED
                cert.save()

                payload = fire_certificate_event(
                    cert,
                    EVENT_CERTIFICATE_ARCHIVED,
                    extra={"archive_days_threshold": archive_days},
                )
                event_payloads.append(payload)

            archived_count += 1

        # Summary
        self.log_info(f"\n{'=' * 50}")
        self.log_info("AUTO-ARCHIVE SUMMARY")
        self.log_info(f"{'=' * 50}")
        self.log_info(f"  Candidates found: {total_candidates}")
        self.log_info(f"  Archived: {archived_count}")
        self.log_info(f"  Skipped (pinned): {skipped_count}")

        if archived_count == 0:
            self.log_success("  No certificates require archival.")
        elif dry_run:
            self.log_warning(f"  {archived_count} certificate(s) would be archived (dry run).")
        else:
            self.log_success(f"  {archived_count} certificate(s) archived successfully.")

        return {
            "archived_at": now.isoformat(),
            "archive_days_threshold": archive_days,
            "total_candidates": total_candidates,
            "archived_count": archived_count,
            "skipped_count": skipped_count,
            "dry_run": dry_run,
            "tenant": tenant.name if tenant else None,
            "events": event_payloads,
        }
