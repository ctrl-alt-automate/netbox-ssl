"""
GraphQL types for NetBox SSL plugin.
"""

from typing import Annotated

import strawberry
import strawberry_django
from netbox.graphql.types import NetBoxObjectType

from .. import filtersets
from ..models import (
    Certificate,
    CertificateAssignment,
    CertificateAuthority,
    CertificateLifecycleEvent,
    CertificateSigningRequest,
    ExternalSource,
)


@strawberry_django.type(
    CertificateAuthority,
    fields=[
        "id",
        "name",
        "description",
        "issuer_pattern",
        "website",
        "is_acme",
        "renewal_instructions",
        "tags",
        "created",
        "last_updated",
    ],
    filters=filtersets.CertificateAuthorityFilterSet,
)
class CertificateAuthorityType(NetBoxObjectType):
    """GraphQL type for CertificateAuthority model."""

    name: str
    type: str
    description: str
    issuer_pattern: str
    website_url: str
    portal_url: str
    contact_email: str
    renewal_instructions: str
    is_approved: bool

    @strawberry_django.field
    def certificate_count(self) -> int:
        return self.certificates.count()


@strawberry_django.type(
    ExternalSource,
    fields=[
        "id",
        "name",
        "source_type",
        "base_url",
        "region",
        "auth_method",
        "sync_interval_minutes",
        "enabled",
        "sync_status",
        "last_synced",
        "verify_ssl",
        "tags",
        "created",
        "last_updated",
    ],
    filters=filtersets.ExternalSourceFilterSet,
)
class ExternalSourceType(NetBoxObjectType):
    """GraphQL type for ExternalSource model.

    Note: auth_credentials and auth_credentials_reference are intentionally
    excluded for security — both hold env-var references that would be a
    reconnaissance leak if exposed. Use has_credentials to check
    configuration presence.
    """

    name: str
    source_type: str
    base_url: str
    region: str
    auth_method: str
    sync_interval_minutes: int
    enabled: bool
    sync_status: str
    verify_ssl: bool

    @strawberry_django.field
    def certificate_count(self) -> int:
        return self.certificates.count()

    @strawberry_django.field
    def has_credentials(self) -> bool:
        """Are credentials configured for this source?

        True for role-based auth (e.g., AWS instance role, Azure Managed Identity)
        even when auth_credentials is empty — those methods authorize via host
        identity. The set of role-based methods is declared per-adapter via
        IMPLICIT_AUTH_METHODS.
        """
        from ..adapters import get_adapter_class

        try:
            if self.auth_method in get_adapter_class(self.source_type).IMPLICIT_AUTH_METHODS:
                return True
        except KeyError:
            pass
        return bool(self.auth_credentials) or bool(self.auth_credentials_reference)


@strawberry_django.type(
    Certificate,
    fields=[
        "id",
        "common_name",
        "serial_number",
        "fingerprint_sha256",
        "issuer",
        "valid_from",
        "valid_to",
        "algorithm",
        "key_size",
        "status",
        "sans",
        "tenant",
        "issuing_ca",
        "archive_pinned",
        "archived_at",
        "renewal_note",
        "external_source",
        "external_id",
        "source_removed",
        "ari_cert_id",
        "ari_suggested_start",
        "ari_suggested_end",
        "ari_explanation_url",
        "ari_last_checked",
        "ari_retry_after",
        "tags",
        "comments",
        "created",
        "last_updated",
    ],
    filters=filtersets.CertificateFilterSet,
)
class CertificateType(NetBoxObjectType):
    """GraphQL type for Certificate model."""

    common_name: str
    serial_number: str
    fingerprint_sha256: str
    issuer: str
    valid_from: str
    valid_to: str
    sans: list[str]
    key_size: int | None
    algorithm: str
    status: str
    archive_pinned: bool
    archived_at: str | None
    renewal_note: str
    issuing_ca: Annotated["CertificateAuthorityType", strawberry.lazy(".types")] | None
    external_source: Annotated["ExternalSourceType", strawberry.lazy(".types")] | None
    external_id: str
    source_removed: bool
    ari_cert_id: str
    ari_explanation_url: str

    @strawberry_django.field
    def ari_window_active(self) -> bool:
        return self.ari_window_active

    @strawberry_django.field
    def ari_status(self) -> str:
        return self.ari_status

    @strawberry_django.field
    def effective_renewal_instructions(self) -> str:
        """Get renewal instructions with fallback: cert note > CA instructions > empty."""
        if self.renewal_note:
            return self.renewal_note
        if self.issuing_ca and hasattr(self.issuing_ca, "renewal_instructions"):
            return self.issuing_ca.renewal_instructions or ""
        return ""

    @strawberry_django.field
    def days_remaining(self) -> int | None:
        return self.days_remaining

    @strawberry_django.field
    def is_expired(self) -> bool:
        return self.is_expired

    @strawberry_django.field
    def is_expiring_soon(self) -> bool:
        return self.is_expiring_soon

    @strawberry_django.field
    def expiry_status(self) -> str:
        return self.expiry_status

    @strawberry_django.field
    def assignment_count(self) -> int:
        return self.assignments.count()


@strawberry_django.type(
    CertificateAssignment,
    fields=[
        "id",
        "certificate",
        "assigned_object_type",
        "assigned_object_id",
        "is_primary",
        "created",
        "last_updated",
    ],
    filters=filtersets.CertificateAssignmentFilterSet,
)
class CertificateAssignmentType(NetBoxObjectType):
    """GraphQL type for CertificateAssignment model."""

    certificate: Annotated["CertificateType", strawberry.lazy(".types")]
    is_primary: bool


@strawberry_django.type(
    CertificateSigningRequest,
    fields=[
        "id",
        "common_name",
        "organization",
        "organizational_unit",
        "country",
        "state",
        "locality",
        "sans",
        "key_size",
        "algorithm",
        "status",
        "tenant",
        "tags",
        "created",
        "last_updated",
    ],
    filters=filtersets.CertificateSigningRequestFilterSet,
)
class CertificateSigningRequestType(NetBoxObjectType):
    """GraphQL type for CertificateSigningRequest model."""

    common_name: str
    organization: str
    organizational_unit: str
    locality: str
    state: str
    country: str
    sans: list[str]
    key_size: int | None
    algorithm: str
    status: str
    # resulting_certificate is auto-resolved by strawberry_django from the ForeignKey
    resulting_certificate: Annotated["CertificateType", strawberry.lazy(".types")] | None

    @strawberry_django.field
    def subject_string(self) -> str:
        """Build a subject string from the CSR fields."""
        parts = []
        if self.common_name:
            parts.append(f"CN={self.common_name}")
        if self.organization:
            parts.append(f"O={self.organization}")
        if self.organizational_unit:
            parts.append(f"OU={self.organizational_unit}")
        if self.locality:
            parts.append(f"L={self.locality}")
        if self.state:
            parts.append(f"ST={self.state}")
        if self.country:
            parts.append(f"C={self.country}")
        return ", ".join(parts) if parts else ""


@strawberry_django.type(
    CertificateLifecycleEvent,
    fields=[
        "id",
        "event_type",
        "timestamp",
        "description",
        "old_status",
        "new_status",
        "actor",
    ],
)
class CertificateLifecycleEventType:
    """GraphQL type for CertificateLifecycleEvent model."""

    event_type: str
    timestamp: str
    description: str
    old_status: str
    new_status: str
    actor: str
