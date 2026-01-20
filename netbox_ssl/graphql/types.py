"""
GraphQL types for NetBox SSL plugin.
"""

from typing import Annotated

import strawberry
import strawberry_django
from netbox.graphql.types import NetBoxObjectType

from .. import filtersets
from ..models import Certificate, CertificateAssignment, CertificateAuthority, CertificateSigningRequest


@strawberry_django.type(
    CertificateAuthority,
    fields="__all__",
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
    is_approved: bool

    @strawberry_django.field
    def certificate_count(self) -> int:
        return self.certificates.count()


@strawberry_django.type(
    Certificate,
    fields="__all__",
    filters=filtersets.CertificateFilterSet,
)
class CertificateType(NetBoxObjectType):
    """GraphQL type for Certificate model."""

    common_name: str
    serial_number: str
    fingerprint_sha256: str
    issuer: str
    issuer_chain: str
    valid_from: str
    valid_to: str
    sans: list[str]
    key_size: int | None
    algorithm: str
    status: str
    private_key_location: str
    pem_content: str
    issuing_ca: Annotated["CertificateAuthorityType", strawberry.lazy(".types")] | None

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
    fields="__all__",
    filters=filtersets.CertificateAssignmentFilterSet,
)
class CertificateAssignmentType(NetBoxObjectType):
    """GraphQL type for CertificateAssignment model."""

    certificate: Annotated["CertificateType", strawberry.lazy(".types")]
    is_primary: bool
    notes: str


@strawberry_django.type(
    CertificateSigningRequest,
    fields="__all__",
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
    fingerprint_sha256: str
    pem_content: str
    status: str
    requested_date: str
    requested_by: str
    target_ca: str
    notes: str
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
