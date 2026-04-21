"""
External Source models for syncing certificates from external systems.
"""

import ipaddress
import logging
import re
import socket
from datetime import timedelta
from urllib.parse import urlparse

from django.core.exceptions import ValidationError
from django.db import models
from django.urls import reverse
from django.utils import timezone
from netbox.models import NetBoxModel
from utilities.choices import ChoiceSet

logger = logging.getLogger("netbox_ssl.models")

# Fields that must never appear in field_mapping (mirrors adapters.base.PROHIBITED_SYNC_FIELDS).
# Keep in sync with adapters/base.py — a mismatch allows sensitive keys in field_mapping.
_PROHIBITED_MAPPING_KEYS: frozenset[str] = frozenset(
    {
        # Pre-v1.1 entries
        "private_key",
        "key_material",
        "p12",
        "pfx",
        "pkcs12",
        # v1.1 additions for AWS ACM and Azure Key Vault parity
        "pem_bundle",
        "secret_value",
        "key",
    }
)

# Env var name validation
_ENV_VAR_PATTERN = re.compile(r"^[A-Z_][A-Z0-9_]{0,254}$")


def validate_external_source_url(value: str) -> None:
    """Validate that URL uses HTTPS and doesn't point to private addresses."""
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
        # HIGH-3: DNS name — resolve and check if any IP is private/loopback/link-local.
        try:
            addrs = socket.getaddrinfo(hostname, None)
            for _family, _type, _proto, _canonname, sockaddr in addrs:
                resolved_ip = sockaddr[0]
                try:
                    resolved_addr = ipaddress.ip_address(resolved_ip)
                    if resolved_addr.is_private or resolved_addr.is_loopback or resolved_addr.is_link_local:
                        raise ValidationError("URL hostname resolves to a private or loopback address.")
                except ValueError:
                    continue
        except OSError:
            # DNS resolution failed — allow for now (host may not be reachable
            # at validation time, e.g. in CI).
            pass


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
    AUTH_AWS_EXPLICIT = "aws_explicit"
    AUTH_AWS_INSTANCE_ROLE = "aws_instance_role"
    AUTH_AZURE_EXPLICIT = "azure_explicit"
    AUTH_AZURE_MANAGED_IDENTITY = "azure_managed_identity"

    CHOICES = [
        (AUTH_BEARER, "Bearer Token", "blue"),
        (AUTH_API_KEY, "API Key (Header)", "yellow"),
        (AUTH_AWS_EXPLICIT, "AWS Explicit Credentials", "orange"),
        (AUTH_AWS_INSTANCE_ROLE, "AWS Instance Role", "green"),
        (AUTH_AZURE_EXPLICIT, "Azure Service Principal", "blue"),
        (AUTH_AZURE_MANAGED_IDENTITY, "Azure Managed Identity", "green"),
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
        blank=True,
        validators=[validate_external_source_url],
        help_text=("HTTPS API endpoint of the external source. Not required for region-scoped adapters (AWS ACM)."),
    )
    auth_method = models.CharField(
        max_length=30,
        choices=AuthMethodChoices,
        help_text="Authentication method for the external source",
    )
    auth_credentials = models.JSONField(
        default=dict,
        blank=True,
        help_text=(
            "Mapping of credential component name to a reference string "
            "(e.g. {'access_key_id': 'env:AWS_KEY'}). "
            "Leave empty for role-based auth methods "
            "(aws_instance_role, azure_managed_identity)."
        ),
    )

    region = models.CharField(
        max_length=32,
        blank=True,
        help_text=(
            "Cloud region identifier (e.g., 'us-east-1'). "
            "Required for region-scoped adapters such as AWS ACM; "
            "ignored by others."
        ),
    )

    auth_credentials_reference = models.CharField(
        max_length=512,
        blank=True,
        help_text=(
            "DEPRECATED in v1.1, removed in v2.0. Use auth_credentials instead — existing rows auto-migrate via 0021."
        ),
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
        help_text=(
            "Verify TLS certificates when connecting to the source. "
            "WARNING: Disabling this removes protection against MITM attacks."
        ),
    )

    class Meta:
        ordering = ["name"]
        verbose_name = "External Source"
        verbose_name_plural = "External Sources"

    def __str__(self) -> str:
        return self.name

    def get_absolute_url(self) -> str:
        return reverse("plugins:netbox_ssl:externalsource", args=[self.pk])

    def clean(self) -> None:
        """Validate model fields before saving.

        MED-2: Ensure field_mapping keys do not include prohibited sync fields.
        """
        super().clean()
        if self.field_mapping and isinstance(self.field_mapping, dict):
            prohibited_found = _PROHIBITED_MAPPING_KEYS & set(self.field_mapping.keys())
            if prohibited_found:
                raise ValidationError(
                    {"field_mapping": (f"Field mapping must not contain prohibited fields: {sorted(prohibited_found)}")}
                )

    def save(self, *args, **kwargs) -> None:
        if not self.verify_ssl:
            logger.warning(
                "ExternalSource '%s' (pk=%s) has TLS verification disabled.",
                self.name,
                self.pk,
            )
        super().save(*args, **kwargs)

    def snapshot(self) -> None:
        """Override changelog snapshot to redact credential values.

        Key-level audit trail is preserved (adds/removes of credential
        components show in diffs) but reference strings are redacted to
        prevent historical env-var-name leakage. NetBox stores the snapshot
        as self._prechange_snapshot; we mutate it in-place after super().
        """
        super().snapshot()
        if self._prechange_snapshot is None:
            return
        creds = self._prechange_snapshot.get("auth_credentials")
        if isinstance(creds, dict):
            self._prechange_snapshot["auth_credentials"] = dict.fromkeys(creds, "<redacted>")
        if self._prechange_snapshot.get("auth_credentials_reference"):
            self._prechange_snapshot["auth_credentials_reference"] = "<redacted>"

    @property
    def certificate_count(self) -> int:
        """Return the number of certificates synced from this source.

        Note (HIGH-9): This property triggers a COUNT query per instance.
        For list views, use ``annotate(Count("certificates"))`` on the
        queryset to avoid N+1 queries.  This property is kept for
        single-object views.
        """
        return self.certificates.count()

    @property
    def is_sync_due(self) -> bool:
        """Check if this source is due for a sync based on its interval."""
        if not self.enabled or self.sync_interval_minutes == 0:
            return False
        if not self.last_synced:
            return True
        # LOW-5: timedelta imported at module level.
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

    @classmethod
    def cleanup_old_logs(cls, keep_days: int = 90) -> int:
        """Remove sync log entries older than the specified number of days.

        Follows the pattern from ``CertificateEventLog.cleanup_old_entries()``.

        Args:
            keep_days: Delete entries older than this many days.

        Returns:
            Number of entries deleted.
        """
        cutoff = timezone.now() - timedelta(days=keep_days)
        count, _ = cls.objects.filter(started_at__lt=cutoff).delete()
        return count
