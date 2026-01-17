"""
GraphQL types for NetBox SSL plugin.
"""

from typing import Annotated, List, Optional

import strawberry
import strawberry_django

from netbox.graphql.types import NetBoxObjectType

from ..models import Certificate, CertificateAssignment
from .. import filtersets


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
    sans: List[str]
    key_size: Optional[int]
    algorithm: str
    status: str
    private_key_location: str
    pem_content: str

    @strawberry_django.field
    def days_remaining(self) -> Optional[int]:
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
