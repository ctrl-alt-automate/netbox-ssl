"""
GraphQL types for NetBox SSL plugin.
"""

from typing import Annotated

import strawberry
import strawberry_django
from netbox.graphql.types import NetBoxObjectType

from .. import filtersets
from ..models import Certificate, CertificateAssignment, CertificateSigningRequest


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

    @strawberry_django.field
    def resulting_certificate(self) -> CertificateType | None:
        if self.resulting_certificate:
            return self.resulting_certificate
        return None

    @strawberry_django.field
    def subject_string(self) -> str:
        return self.subject_string
