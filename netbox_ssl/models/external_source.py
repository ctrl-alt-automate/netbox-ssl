"""
External Source models for syncing certificates from external systems.
"""

import logging
import re
from urllib.parse import urlparse

from django.core.exceptions import ValidationError
from django.db import models
from django.urls import reverse
from django.utils import timezone
from netbox.models import NetBoxModel
from utilities.choices import ChoiceSet

logger = logging.getLogger("netbox_ssl.models")

# Env var name validation
_ENV_VAR_PATTERN = re.compile(r"^[A-Z_][A-Z0-9_]{0,254}$")


def validate_external_source_url(value: str) -> None:
    """Validate that URL uses HTTPS and doesn't point to private addresses."""
    import ipaddress

    try:
        parsed = urlparse(value)
    except Exception as exc:
        raise ValidationError("Invalid URL.") from exc

    if parsed.scheme != "https":
        raise ValidationError("Only HTTPS URLs are permitted for external sources.")

    hostname = parsed.hostname or ""
    blocked = {"localhost", "127.0.0.1", "::1"}
    if hostname in blocked:
        raise ValidationError("URL must not point to a loopback address.")

    try:
        addr = ipaddress.ip_address(hostname)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            raise ValidationError("URL must not point to a private or loopback address.")
    except ValueError:
        pass  # DNS name — can't fully validate


class ExternalSourceTypeChoices(ChoiceSet):
    """Type choices for external sources."""

    TYPE_LEMUR = "lemur"
    TYPE_GENERIC_REST = "generic_rest"

    CHOICES = [
        (TYPE_LEMUR, "Lemur", "purple"),
        (TYPE_GENERIC_REST, "Generic REST API", "blue"),
    ]


class AuthMethodChoices(ChoiceSet):
    """Authentication method choices for external sources."""

    AUTH_BEARER = "bearer"
    AUTH_API_KEY = "api_key"

    CHOICES = [
        (AUTH_BEARER, "Bearer Token", "blue"),
        (AUTH_API_KEY, "API Key (Header)", "yellow"),
    ]


class SyncStatusChoices(ChoiceSet):
    """Sync status choices for external sources."""

    STATUS_NEW = "new"
    STATUS_OK = "ok"
    STATUS_ERROR = "error"
    STATUS_SYNCING = "syncing"

    CHOICES = [
        (STATUS_NEW, "New", "blue"),
        (STATUS_OK, "OK", "green"),
        (STATUS_ERROR, "Error", "red"),
        (STATUS_SYNCING, "Syncing", "yellow"),
    ]


class ExternalSource(NetBoxModel):
    """Configuration for an external certificate management system."""

    name = models.CharField(
        max_length=255,
        unique=True,
        help_text="Human-readable name for this source",
    )
    source_type = models.CharField(
        max_length=30,
        choices=ExternalSourceTypeChoices,
        help_text="Type of external source backend",
    )
    base_url = models.URLField(
        max_length=500,
        validators=[validate_external_source_url],
        help_text="HTTPS API endpoint of the external source",
    )
    auth_method = models.CharField(
        max_length=20,
        choices=AuthMethodChoices,
        help_text="Authentication method for the external source",
    )
    auth_credentials_reference = models.CharField(
        max_length=512,
        blank=True,
        help_text='Credential reference (e.g., "env:LEMUR_API_TOKEN"). Never store actual secrets.',
    )
    field_mapping = models.JSONField(
        blank=True,
        default=dict,
        help_text="Field mapping for GenericREST adapter (dotted-path notation)",
    )
    sync_interval_minutes = models.PositiveIntegerField(
        default=1440,
        help_text="Sync interval in minutes (0 = manual only)",
    )
    enabled = models.BooleanField(
        default=True,
        help_text="Whether this source is active for syncing",
    )
    tenant = models.ForeignKey(
        to="tenancy.Tenant",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="external_sources",
        help_text="Synced certificates inherit this tenant",
    )
    sync_status = models.CharField(
        max_length=20,
        choices=SyncStatusChoices,
        default=SyncStatusChoices.STATUS_NEW,
        help_text="Current sync status",
    )
    last_synced = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When the last successful sync completed",
    )
    last_sync_message = models.TextField(
        blank=True,
        help_text="Message from the last sync attempt",
    )
    verify_ssl = models.BooleanField(
        default=True,
        help_text="Verify TLS certificates when connecting to the source",
    )

    class Meta:
        ordering = ["name"]
        verbose_name = "External Source"
        verbose_name_plural = "External Sources"

    def __str__(self) -> str:
        return self.name

    def get_absolute_url(self) -> str:
        return reverse("plugins:netbox_ssl:externalsource", args=[self.pk])

    def save(self, *args, **kwargs) -> None:
        if not self.verify_ssl:
            logger.warning(
                "ExternalSource '%s' (pk=%s) has TLS verification disabled.",
                self.name,
                self.pk,
            )
        super().save(*args, **kwargs)

    @property
    def certificate_count(self) -> int:
        """Return the number of certificates synced from this source."""
        return self.certificates.count()

    @property
    def is_sync_due(self) -> bool:
        """Check if this source is due for a sync based on its interval."""
        if not self.enabled or self.sync_interval_minutes == 0:
            return False
        if not self.last_synced:
            return True
        from datetime import timedelta

        return timezone.now() >= self.last_synced + timedelta(minutes=self.sync_interval_minutes)


class ExternalSourceSyncLog(models.Model):
    """Per-sync-run statistics."""

    source = models.ForeignKey(
        to="netbox_ssl.ExternalSource",
        on_delete=models.CASCADE,
        related_name="sync_logs",
        help_text="The external source this log belongs to",
    )
    started_at = models.DateTimeField(
        auto_now_add=True,
        help_text="When this sync run started",
    )
    finished_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When this sync run finished",
    )
    success = models.BooleanField(
        default=False,
        help_text="Whether the sync completed successfully",
    )
    dry_run = models.BooleanField(
        default=False,
        help_text="Whether this was a dry-run (no changes made)",
    )
    message = models.TextField(
        blank=True,
        help_text="Summary message for this sync run",
    )
    certificates_fetched = models.PositiveIntegerField(
        default=0,
        help_text="Number of certificates fetched from the source",
    )
    certificates_created = models.PositiveIntegerField(
        default=0,
        help_text="Number of new certificates created",
    )
    certificates_updated = models.PositiveIntegerField(
        default=0,
        help_text="Number of existing certificates updated",
    )
    certificates_renewed = models.PositiveIntegerField(
        default=0,
        help_text="Number of certificates renewed (Janus workflow)",
    )
    certificates_removed = models.PositiveIntegerField(
        default=0,
        help_text="Number of certificates marked as removed from source",
    )
    certificates_unchanged = models.PositiveIntegerField(
        default=0,
        help_text="Number of certificates that required no changes",
    )
    errors = models.JSONField(
        default=list,
        blank=True,
        help_text="List of errors encountered during sync",
    )

    class Meta:
        ordering = ["-started_at"]

    def __str__(self) -> str:
        status = "OK" if self.success else "FAILED"
        return f"{self.source.name} sync at {self.started_at:%Y-%m-%d %H:%M} — {status}"
