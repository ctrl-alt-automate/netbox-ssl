"""
Scheduled Certificate Expiry Scan.

Scans all active certificates against configurable expiry thresholds and
fires events for certificates that are expiring soon or have expired.

Designed to be idempotent: running the same scan twice within the cooldown
window does not produce duplicate events. Uses CertificateEventLog for
deduplication tracking.

Can be scheduled via NetBox's job scheduler or triggered manually.
"""

import uuid
from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from extras.scripts import BooleanVar, ObjectVar, Script

from netbox_ssl.models import Certificate, CertificateStatusChoices
from netbox_ssl.models.event_log import CertificateEventLog
from netbox_ssl.utils.events import (
    EVENT_CERTIFICATE_EXPIRED,
    EVENT_CERTIFICATE_EXPIRING_SOON,
    fire_certificate_event,
)


class CertificateExpiryScan(Script):
    """
    Scan certificates for expiry and fire events for Event Rules.

    This script checks all active certificates against configurable
    thresholds and generates events that can be picked up by NetBox
    Event Rules for webhook notifications.

    Features:
    - Configurable thresholds (default: 14, 30, 60, 90 days)
    - Idempotent: won't fire duplicate events within the cooldown window
    - Per-tenant filtering
    - Dry-run mode for testing
    - Audit log of all fired events
    """

    class Meta:
        name = "Certificate Expiry Scan"
        description = "Scan for expiring certificates and fire events for Event Rules"
        commit_default = True
        job_timeout = 600

    # Script variables
    tenant = ObjectVar(
        model="tenancy.Tenant",
        description="Filter certificates by tenant (optional)",
        required=False,
    )
    dry_run = BooleanVar(
        description="Preview mode: show what events would be fired without actually firing them",
        default=False,
    )
    ignore_cooldown = BooleanVar(
        description="Ignore cooldown window and fire events even if recently fired",
        default=False,
    )
    cleanup_old_events = BooleanVar(
        description="Clean up event log entries older than 90 days",
        default=True,
    )

    def get_plugin_setting(self, name: str, default=None):
        """Get a plugin setting value."""
        return settings.PLUGINS_CONFIG.get("netbox_ssl", {}).get(name, default)

    def run(self, data, commit):
        """Execute the expiry scan."""
        scan_id = uuid.uuid4()
        now = timezone.now()
        tenant = data.get("tenant")
        dry_run = data.get("dry_run", False)
        ignore_cooldown = data.get("ignore_cooldown", False)
        cleanup = data.get("cleanup_old_events", True)

        # Get configuration
        thresholds = self.get_plugin_setting("expiry_scan_thresholds", [14, 30, 60, 90])
        cooldown_hours = self.get_plugin_setting("expiry_scan_cooldown_hours", 24)

        # Sort thresholds descending so we process the widest window first
        thresholds = sorted(thresholds, reverse=True)

        self.log_info(f"Certificate Expiry Scan — {now.strftime('%Y-%m-%d %H:%M:%S %Z')}")
        self.log_info(f"  Scan ID: {scan_id}")
        self.log_info(f"  Thresholds: {thresholds} days")
        self.log_info(f"  Cooldown: {cooldown_hours} hours")
        if tenant:
            self.log_info(f"  Tenant filter: {tenant.name}")
        if dry_run:
            self.log_warning("  DRY RUN MODE — no events will be fired")

        # Build base queryset
        queryset = Certificate.objects.filter(
            status=CertificateStatusChoices.STATUS_ACTIVE,
        ).select_related("tenant")
        if tenant:
            queryset = queryset.filter(tenant=tenant)

        total_scanned = queryset.count()
        self.log_info(f"\nScanning {total_scanned} active certificates...")

        # Track results
        events_fired = 0
        events_skipped = 0
        events_by_threshold = {}
        event_payloads = []

        # Process expired certificates
        expired_certs = queryset.filter(valid_to__lt=now)
        for cert in expired_certs:
            if not ignore_cooldown and CertificateEventLog.was_recently_fired(
                cert.pk, EVENT_CERTIFICATE_EXPIRED, None, cooldown_hours
            ):
                events_skipped += 1
                continue

            payload = fire_certificate_event(cert, EVENT_CERTIFICATE_EXPIRED)

            if not dry_run and commit:
                CertificateEventLog.objects.create(
                    certificate=cert,
                    event_type=EVENT_CERTIFICATE_EXPIRED,
                    threshold_days=None,
                    scan_id=scan_id,
                )
            events_fired += 1
            events_by_threshold["expired"] = events_by_threshold.get("expired", 0) + 1
            event_payloads.append(payload)

        if expired_certs.exists():
            self.log_failure(f"  Expired: {expired_certs.count()} certificates")

        # Process each threshold (widest first, assign to smallest matching threshold)
        for threshold in thresholds:
            threshold_date = now + timedelta(days=threshold)
            certs_in_window = queryset.filter(
                valid_to__gte=now,
                valid_to__lte=threshold_date,
            )

            count = 0
            for cert in certs_in_window:
                # Find the smallest threshold this cert falls into
                smallest_threshold = threshold
                for t in sorted(thresholds):
                    if cert.valid_to <= now + timedelta(days=t):
                        smallest_threshold = t
                        break

                # Only fire for the smallest matching threshold to avoid duplicates
                if smallest_threshold != threshold:
                    continue

                if not ignore_cooldown and CertificateEventLog.was_recently_fired(
                    cert.pk, EVENT_CERTIFICATE_EXPIRING_SOON, threshold, cooldown_hours
                ):
                    events_skipped += 1
                    continue

                payload = fire_certificate_event(
                    cert, EVENT_CERTIFICATE_EXPIRING_SOON, threshold_days=threshold
                )

                if not dry_run and commit:
                    CertificateEventLog.objects.create(
                        certificate=cert,
                        event_type=EVENT_CERTIFICATE_EXPIRING_SOON,
                        threshold_days=threshold,
                        scan_id=scan_id,
                    )
                events_fired += 1
                count += 1
                event_payloads.append(payload)

            events_by_threshold[f"{threshold}_days"] = count
            if count > 0:
                if threshold <= 14:
                    self.log_failure(f"  ≤{threshold} days: {count} certificates")
                elif threshold <= 30:
                    self.log_warning(f"  ≤{threshold} days: {count} certificates")
                else:
                    self.log_info(f"  ≤{threshold} days: {count} certificates")

        # Clean up old event log entries
        cleaned_up = 0
        if cleanup and not dry_run and commit:
            cleaned_up = CertificateEventLog.cleanup_old_entries(days=90)
            if cleaned_up:
                self.log_info(f"\n  Cleaned up {cleaned_up} old event log entries")

        # Summary
        self.log_info(f"\n{'=' * 50}")
        self.log_info("SCAN SUMMARY")
        self.log_info(f"{'=' * 50}")
        self.log_info(f"  Certificates scanned: {total_scanned}")
        self.log_info(f"  Events fired: {events_fired}")
        self.log_info(f"  Events skipped (cooldown): {events_skipped}")
        if cleaned_up:
            self.log_info(f"  Old entries cleaned: {cleaned_up}")

        if events_fired == 0 and events_skipped == 0:
            self.log_success("  No certificates require attention.")
        elif events_fired > 0:
            self.log_warning(f"  {events_fired} event(s) fired for expiring/expired certificates.")

        return {
            "scan_id": str(scan_id),
            "scanned_at": now.isoformat(),
            "total_scanned": total_scanned,
            "events_fired": events_fired,
            "events_skipped": events_skipped,
            "events_by_threshold": events_by_threshold,
            "dry_run": dry_run,
            "thresholds": thresholds,
            "cooldown_hours": cooldown_hours,
            "tenant": tenant.name if tenant else None,
            "events": event_payloads,
        }
