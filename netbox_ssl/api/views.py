"""
REST API views for NetBox SSL plugin.
"""

from django.conf import settings
from django.db import DatabaseError, IntegrityError, transaction
from netbox.api.viewsets import NetBoxModelViewSet
from rest_framework import serializers, status
from rest_framework.decorators import action
from rest_framework.response import Response

from ..filtersets import CertificateAssignmentFilterSet, CertificateFilterSet
from ..models import Certificate, CertificateAssignment
from .serializers import (
    CertificateAssignmentSerializer,
    CertificateImportSerializer,
    CertificateSerializer,
)


class CertificateViewSet(NetBoxModelViewSet):
    """API viewset for Certificate model."""

    queryset = Certificate.objects.prefetch_related(
        "tenant",
        "tags",
        "assignments",
    )
    serializer_class = CertificateSerializer
    filterset_class = CertificateFilterSet

    @action(detail=False, methods=["post"], url_path="import")
    def import_certificate(self, request):
        """
        Import a certificate from PEM content.

        Accepts raw PEM content and automatically parses all X.509 attributes.
        Private keys are rejected for security reasons.
        """
        serializer = CertificateImportSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        certificate = serializer.save()

        # Return the created certificate using the standard serializer
        output_serializer = CertificateSerializer(certificate, context={"request": request})
        return Response(output_serializer.data, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=["post"], url_path="bulk-import")
    def bulk_import(self, request):
        """
        Import multiple certificates from a list of PEM content objects.

        Accepts a JSON array of certificate objects. The operation is atomic:
        if any certificate fails validation, the entire batch is rejected.

        Example payload:
        [
            {
                "pem_content": "-----BEGIN CERTIFICATE-----\\n...",
                "private_key_location": "Vault: /secret/prod/web1",
                "tenant": 1
            },
            {
                "pem_content": "-----BEGIN CERTIFICATE-----\\n...",
                "tenant": 2
            }
        ]
        """
        # Validate input is a list
        if not isinstance(request.data, list):
            raise serializers.ValidationError({"detail": "Expected a list of certificate objects."})

        if len(request.data) == 0:
            raise serializers.ValidationError({"detail": "Empty list provided. At least one certificate is required."})

        # Limit batch size to prevent abuse (configurable via PLUGINS_CONFIG)
        plugin_settings = settings.PLUGINS_CONFIG.get("netbox_ssl", {})
        max_batch_size = plugin_settings.get("bulk_import_max_batch_size", 100)
        if len(request.data) > max_batch_size:
            raise serializers.ValidationError(
                {"detail": f"Batch size exceeds maximum of {max_batch_size} certificates."}
            )

        # Validate all certificates first (before creating any)
        validated_serializers = []
        errors = []

        for index, cert_data in enumerate(request.data):
            serializer = CertificateImportSerializer(data=cert_data)
            if serializer.is_valid():
                validated_serializers.append(serializer)
            else:
                errors.append({"index": index, "errors": serializer.errors})

        # If any validation errors, reject the entire batch
        if errors:
            raise serializers.ValidationError(
                {
                    "detail": "Validation failed for one or more certificates.",
                    "failed_certificates": errors,
                }
            )

        # All validated - create certificates atomically
        created_certificates = []
        try:
            with transaction.atomic():
                for serializer in validated_serializers:
                    certificate = serializer.save()
                    created_certificates.append(certificate)
        except IntegrityError as e:
            raise serializers.ValidationError(
                {"detail": f"Database integrity error during bulk import: {str(e)}"}
            ) from e
        except DatabaseError as e:
            raise serializers.ValidationError({"detail": f"Database error during bulk import: {str(e)}"}) from e

        # Return created certificates
        output_serializer = CertificateSerializer(created_certificates, many=True, context={"request": request})
        return Response(
            {
                "created_count": len(created_certificates),
                "certificates": output_serializer.data,
            },
            status=status.HTTP_201_CREATED,
        )

    @action(detail=True, methods=["post"], url_path="validate-chain")
    def validate_chain(self, request, pk=None):
        """
        Validate the certificate chain for a specific certificate.

        Performs chain validation and updates the certificate's chain_status,
        chain_validation_message, chain_validated_at, and chain_depth fields.
        """
        certificate = self.get_object()

        if not certificate.pem_content:
            return Response(
                {
                    "status": "error",
                    "message": "Certificate has no PEM content for validation",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        result = certificate.validate_chain(save=True)

        if result is None:
            return Response(
                {
                    "status": "error",
                    "message": "Chain validation failed - no PEM content",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response(
            {
                "status": result.status.value,
                "is_valid": result.is_valid,
                "message": result.message,
                "chain_depth": result.chain_depth,
                "certificates": result.certificates,
                "errors": result.errors,
                "validated_at": result.validated_at.isoformat(),
            },
            status=status.HTTP_200_OK,
        )

    @action(detail=False, methods=["post"], url_path="bulk-validate-chain")
    def bulk_validate_chain(self, request):
        """
        Validate certificate chains for multiple certificates.

        Accepts a list of certificate IDs and validates each one.
        """
        certificate_ids = request.data.get("ids", [])

        if not certificate_ids:
            raise serializers.ValidationError({"detail": "No certificate IDs provided. Send {'ids': [1, 2, 3]}."})

        # Limit batch size
        plugin_settings = settings.PLUGINS_CONFIG.get("netbox_ssl", {})
        max_batch_size = plugin_settings.get("bulk_validate_max_batch_size", 100)
        if len(certificate_ids) > max_batch_size:
            raise serializers.ValidationError(
                {"detail": f"Batch size exceeds maximum of {max_batch_size} certificates."}
            )

        certificates = Certificate.objects.filter(pk__in=certificate_ids)
        results = []

        for cert in certificates:
            if cert.pem_content:
                result = cert.validate_chain(save=True)
                results.append(
                    {
                        "id": cert.pk,
                        "common_name": cert.common_name,
                        "status": result.status.value if result else "error",
                        "is_valid": result.is_valid if result else False,
                        "message": result.message if result else "No PEM content",
                        "chain_depth": result.chain_depth if result else None,
                    }
                )
            else:
                results.append(
                    {
                        "id": cert.pk,
                        "common_name": cert.common_name,
                        "status": "error",
                        "is_valid": False,
                        "message": "No PEM content available",
                        "chain_depth": None,
                    }
                )

        valid_count = sum(1 for r in results if r["is_valid"])
        return Response(
            {
                "validated_count": len(results),
                "valid_count": valid_count,
                "invalid_count": len(results) - valid_count,
                "results": results,
            },
            status=status.HTTP_200_OK,
        )


class CertificateAssignmentViewSet(NetBoxModelViewSet):
    """API viewset for CertificateAssignment model."""

    queryset = CertificateAssignment.objects.prefetch_related(
        "certificate",
        "assigned_object_type",
        "tags",
    )
    serializer_class = CertificateAssignmentSerializer
    filterset_class = CertificateAssignmentFilterSet
