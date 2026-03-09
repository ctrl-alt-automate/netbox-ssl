"""
CertificateEventLog model for tracking fired events.

Provides idempotency for the scheduled expiry scan: prevents duplicate
notifications within a configurable cooldown window.
"""

import uuid

from django.db import models


class CertificateEventLog(models.Model):
    """
    Tracks certificate events fired by the scheduled scan.

    Used for idempotency: before firing an event, the scan checks if
    the same (certificate, event_type, threshold_days) combination was
    already fired within the cooldown window.
    """

    certificate = models.ForeignKey(
        to="netbox_ssl.Certificate",
        on_delete=models.CASCADE,
        related_name="event_logs",
    )
    event_type = models.CharField(
        max_length=50,
        help_text="Event type that was fired (e.g., certificate_expiring_soon)",
    )
    threshold_days = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text="Expiry threshold in days that triggered this event",
    )
    fired_at = models.DateTimeField(
        auto_now_add=True,
        help_text="When this event was fired",
    )
    scan_id = models.UUIDField(
        default=uuid.uuid4,
        help_text="Unique ID of the scan run that generated this event",
    )

    class Meta:
        ordering = ["-fired_at"]
        indexes = [
            models.Index(
                fields=["certificate", "event_type", "threshold_days"],
                name="idx_cert_event_lookup",
            ),
            models.Index(
                fields=["fired_at"],
                name="idx_cert_event_fired_at",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.event_type} for {self.certificate} at {self.fired_at}"

    @classmethod
    def was_recently_fired(
        cls,
        certificate_id: int,
        event_type: str,
        threshold_days: int | None,
        cooldown_hours: int = 24,
    ) -> bool:
        """
        Check if this event was already fired within the cooldown window.

        Args:
            certificate_id: ID of the certificate.
            event_type: Event type string.
            threshold_days: Threshold that triggered the event.
            cooldown_hours: Hours to look back for duplicates.

        Returns:
            True if a matching event was fired within the cooldown window.
        """
        from datetime import timedelta

        from django.utils import timezone

        cutoff = timezone.now() - timedelta(hours=cooldown_hours)
        return cls.objects.filter(
            certificate_id=certificate_id,
            event_type=event_type,
            threshold_days=threshold_days,
            fired_at__gte=cutoff,
        ).exists()

    @classmethod
    def cleanup_old_entries(cls, days: int = 90) -> int:
        """
        Remove event log entries older than the specified number of days.

        Args:
            days: Delete entries older than this many days.

        Returns:
            Number of entries deleted.
        """
        from datetime import timedelta

        from django.utils import timezone

        cutoff = timezone.now() - timedelta(days=days)
        count, _ = cls.objects.filter(fired_at__lt=cutoff).delete()
        return count
