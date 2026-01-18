"""
GraphQL schema for NetBox SSL plugin.
"""

import strawberry
import strawberry_django

from .types import CertificateAssignmentType, CertificateType


@strawberry.type(name="Query")
class NetBoxSSLQuery:
    """GraphQL query type for NetBox SSL plugin."""

    @strawberry_django.field
    def certificate(self, id: int) -> CertificateType:
        from ..models import Certificate

        return Certificate.objects.get(pk=id)

    @strawberry_django.field
    def certificate_list(self) -> list[CertificateType]:
        from ..models import Certificate

        return Certificate.objects.all()

    @strawberry_django.field
    def certificate_assignment(self, id: int) -> CertificateAssignmentType:
        from ..models import CertificateAssignment

        return CertificateAssignment.objects.get(pk=id)

    @strawberry_django.field
    def certificate_assignment_list(self) -> list[CertificateAssignmentType]:
        from ..models import CertificateAssignment

        return CertificateAssignment.objects.all()


schema = [NetBoxSSLQuery]
