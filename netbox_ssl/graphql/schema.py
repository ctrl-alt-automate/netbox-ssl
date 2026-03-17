"""
GraphQL schema for NetBox SSL plugin.
"""

import strawberry
import strawberry_django

from .types import (
    CertificateAssignmentType,
    CertificateAuthorityType,
    CertificateSigningRequestType,
    CertificateType,
)


@strawberry.type(name="Query")
class NetBoxSSLQuery:
    """GraphQL query type for NetBox SSL plugin."""

    @strawberry_django.field
    def certificate(self, info: strawberry.types.Info, id: int) -> CertificateType | None:
        from ..models import Certificate

        try:
            return Certificate.objects.restrict(info.context.request.user, "view").get(pk=id)
        except Certificate.DoesNotExist:
            return None

    @strawberry_django.field
    def certificate_list(self, info: strawberry.types.Info) -> list[CertificateType]:
        from ..models import Certificate

        return Certificate.objects.restrict(info.context.request.user, "view")

    @strawberry_django.field
    def certificate_assignment(self, info: strawberry.types.Info, id: int) -> CertificateAssignmentType | None:
        from ..models import CertificateAssignment

        try:
            return CertificateAssignment.objects.restrict(info.context.request.user, "view").get(pk=id)
        except CertificateAssignment.DoesNotExist:
            return None

    @strawberry_django.field
    def certificate_assignment_list(self, info: strawberry.types.Info) -> list[CertificateAssignmentType]:
        from ..models import CertificateAssignment

        return CertificateAssignment.objects.restrict(info.context.request.user, "view")

    @strawberry_django.field
    def certificate_authority(self, info: strawberry.types.Info, id: int) -> CertificateAuthorityType | None:
        from ..models import CertificateAuthority

        try:
            return CertificateAuthority.objects.restrict(info.context.request.user, "view").get(pk=id)
        except CertificateAuthority.DoesNotExist:
            return None

    @strawberry_django.field
    def certificate_authority_list(self, info: strawberry.types.Info) -> list[CertificateAuthorityType]:
        from ..models import CertificateAuthority

        return CertificateAuthority.objects.restrict(info.context.request.user, "view")

    @strawberry_django.field
    def certificate_signing_request(self, info: strawberry.types.Info, id: int) -> CertificateSigningRequestType | None:
        from ..models import CertificateSigningRequest

        try:
            return CertificateSigningRequest.objects.restrict(info.context.request.user, "view").get(pk=id)
        except CertificateSigningRequest.DoesNotExist:
            return None

    @strawberry_django.field
    def certificate_signing_request_list(self, info: strawberry.types.Info) -> list[CertificateSigningRequestType]:
        from ..models import CertificateSigningRequest

        return CertificateSigningRequest.objects.restrict(info.context.request.user, "view")


schema = [NetBoxSSLQuery]
