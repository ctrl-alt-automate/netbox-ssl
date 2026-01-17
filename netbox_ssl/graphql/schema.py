"""
GraphQL schema for NetBox SSL plugin.
"""

from typing import List

import strawberry
import strawberry_django

from .types import CertificateType, CertificateAssignmentType


@strawberry.type(name="Query")
class NetBoxSSLQuery:
    """GraphQL query type for NetBox SSL plugin."""

    @strawberry_django.field
    def certificate(self, id: int) -> CertificateType:
        from ..models import Certificate
        return Certificate.objects.get(pk=id)

    @strawberry_django.field
    def certificate_list(self) -> List[CertificateType]:
        from ..models import Certificate
        return Certificate.objects.all()

    @strawberry_django.field
    def certificate_assignment(self, id: int) -> CertificateAssignmentType:
        from ..models import CertificateAssignment
        return CertificateAssignment.objects.get(pk=id)

    @strawberry_django.field
    def certificate_assignment_list(self) -> List[CertificateAssignmentType]:
        from ..models import CertificateAssignment
        return CertificateAssignment.objects.all()


schema = [NetBoxSSLQuery]
