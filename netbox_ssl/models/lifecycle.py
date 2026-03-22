"""
Certificate lifecycle event tracking.

Records significant events in a certificate's lifecycle for timeline display
and audit purposes.
"""

import logging

from django.db import models
from django.utils import timezone
from utilities.choices import ChoiceSet

logger = logging.getLogger("netbox_ssl.models")


class LifecycleEventTypeChoices(ChoiceSet):
    """Type choices for lifecycle events."""

    EVENT_IMPORTED = "imported"
    EVENT_ISSUED = "issued"
    EVENT_ACTIVATED = "activated"
    EVENT_STATUS_CHANGED = "status_changed"
    EVENT_RENEWED = "renewed"
    EVENT_REVOKED = "revoked"
    EVENT_ARCHIVED = "archived"
    EVENT_ASSIGNMENT_ADDED = "assignment_added"
    EVENT_ASSIGNMENT_REMOVED = "assignment_removed"

    CHOICES = [
        (EVENT_IMPORTED, "Imported", "blue"),
        (EVENT_ISSUED, "Issued", "green"),
        (EVENT_ACTIVATED, "Activated", "green"),
        (EVENT_STATUS_CHANGED, "Status Changed", "yellow"),
        (EVENT_RENEWED, "Renewed", "cyan"),
        (EVENT_REVOKED, "Revoked", "orange"),
        (EVENT_ARCHIVED, "Archived", "dark"),
        (EVENT_ASSIGNMENT_ADDED, "Assignment Added", "purple"),
        (EVENT_ASSIGNMENT_REMOVED, "Assignment Removed", "gray"),
    ]


class CertificateLifecycleEvent(models.Model):
    """
    Records a significant event in a certificate's lifecycle.

    Events are created automatically by Certificate.save() and
    CertificateAssignment.save()/delete() to build a timeline.
    """

    certificate = models.ForeignKey(
        to="netbox_ssl.Certificate",
        on_delete=models.CASCADE,
        related_name="lifecycle_events",
        help_text="The certificate this event belongs to",
    )
    event_type = models.CharField(
        max_length=30,
        choices=LifecycleEventTypeChoices,
        help_text="Type of lifecycle event",
    )
    timestamp = models.DateTimeField(
        default=timezone.now,
        help_text="When this event occurred",
    )
    description = models.TextField(
        blank=True,
        help_text="Human-readable description of the event",
    )
    old_status = models.CharField(
        max_length=20,
        blank=True,
        help_text="Previous status (for status change events)",
    )
    new_status = models.CharField(
        max_length=20,
        blank=True,
        help_text="New status (for status change events)",
    )
    related_certificate = models.ForeignKey(
        to="netbox_ssl.Certificate",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="related_lifecycle_events",
        help_text="Related certificate (e.g., predecessor/successor in renewal)",
    )
    actor = models.CharField(
        max_length=150,
        blank=True,
        help_text="User or system that triggered this event",
    )

    class Meta:
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["certificate", "-timestamp"], name="netbox_ssl_lifecycle_cert_ts"),
        ]

    def __str__(self) -> str:
        return f"{self.certificate} — {self.get_event_type_display()} ({self.timestamp:%Y-%m-%d %H:%M})"
