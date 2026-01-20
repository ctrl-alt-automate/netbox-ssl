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

    @action(detail=True, methods=["post"], url_path="detect-acme")
    def detect_acme(self, request, pk=None):
        """
        Auto-detect if a certificate was issued via ACME protocol.

        Analyzes the certificate issuer and updates is_acme and acme_provider
        fields based on known ACME CA patterns (Let's Encrypt, ZeroSSL, etc.).

        Returns the detection result and updated certificate data.
        """
        certificate = self.get_object()
        result = certificate.auto_detect_acme(save=True)

        if result:
            is_acme, provider = result
            output_serializer = CertificateSerializer(certificate, context={"request": request})
            return Response(
                {
                    "detected": True,
                    "is_acme": is_acme,
                    "acme_provider": provider,
                    "certificate": output_serializer.data,
                },
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {
                    "detected": False,
                    "message": "Certificate issuer does not match any known ACME provider patterns.",
                },
                status=status.HTTP_200_OK,
            )

    @action(detail=False, methods=["post"], url_path="bulk-detect-acme")
    def bulk_detect_acme(self, request):
        """
        Auto-detect ACME status for multiple certificates.

        Accepts a list of certificate IDs and runs ACME detection on each.
        Returns a summary of detection results.

        Example payload:
        {
            "ids": [1, 2, 3, 4, 5]
        }
        """
        ids = request.data.get("ids", [])

        if not ids:
            raise serializers.ValidationError({"detail": "No certificate IDs provided."})

        if not isinstance(ids, list):
            raise serializers.ValidationError({"detail": "Expected a list of certificate IDs."})

        # Limit batch size
        plugin_settings = settings.PLUGINS_CONFIG.get("netbox_ssl", {})
        max_batch_size = plugin_settings.get("bulk_detect_max_batch_size", 100)
        if len(ids) > max_batch_size:
            raise serializers.ValidationError(
                {"detail": f"Batch size exceeds maximum of {max_batch_size} certificates."}
            )

        certificates = list(Certificate.objects.filter(pk__in=ids))
        found_ids = {cert.pk for cert in certificates}
        missing_ids = set(ids) - found_ids

        results = {
            "total": len(ids),
            "processed": 0,
            "detected_acme": 0,
            "not_acme": 0,
            "missing_ids": list(missing_ids),
            "detections": [],
        }

        # Collect certificates that need updating (avoid N+1 queries)
        certs_to_update = []

        for certificate in certificates:
            result = certificate.auto_detect_acme(save=False)
            results["processed"] += 1

            if result:
                _, provider = result
                certs_to_update.append(certificate)
                results["detected_acme"] += 1
                results["detections"].append(
                    {
                        "id": certificate.pk,
                        "common_name": certificate.common_name,
                        "detected": True,
                        "acme_provider": provider,
                    }
                )
            else:
                results["not_acme"] += 1
                results["detections"].append(
                    {
                        "id": certificate.pk,
                        "common_name": certificate.common_name,
                        "detected": False,
                    }
                )

        # Bulk update all detected certificates in a single query
        if certs_to_update:
            Certificate.objects.bulk_update(certs_to_update, ["is_acme", "acme_provider"])

        return Response(results, status=status.HTTP_200_OK)


class CertificateAssignmentViewSet(NetBoxModelViewSet):
    """API viewset for CertificateAssignment model."""

    queryset = CertificateAssignment.objects.prefetch_related(
        "certificate",
        "assigned_object_type",
        "tags",
    )
    serializer_class = CertificateAssignmentSerializer
    filterset_class = CertificateAssignmentFilterSet
