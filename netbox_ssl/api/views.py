"""
REST API views for NetBox SSL plugin.
"""

from django.conf import settings
from django.db import DatabaseError, IntegrityError, transaction
from django.http import HttpResponse
from netbox.api.viewsets import NetBoxModelViewSet
from rest_framework import serializers, status
from rest_framework.decorators import action
from rest_framework.response import Response

from ..filtersets import CertificateAssignmentFilterSet, CertificateFilterSet
from ..models import Certificate, CertificateAssignment
from ..utils import CertificateExporter, ExportFormatChoices
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

    @action(detail=False, methods=["get", "post"], url_path="export")
    def export(self, request):
        """
        Export certificates in various formats.

        GET parameters or POST body:
        - format: Export format (csv, json, yaml, pem). Default: json
        - ids: List of certificate IDs to export (optional, exports all if not specified)
        - fields: List of fields to include (optional)
        - include_pem: Include PEM content (json/yaml only). Default: false
        - include_chain: Include certificate chain (pem only). Default: true

        Supports filtering via standard query parameters (status, tenant_id, etc.)

        Example:
        GET /certificates/export/?format=csv&status=active
        POST /certificates/export/ {"format": "json", "ids": [1,2,3], "include_pem": true}
        """
        # Get parameters from query string or request body
        if request.method == "GET":
            params = request.query_params
            export_format = params.get("format", "json")
            ids = params.getlist("ids") or params.getlist("ids[]")
            fields = params.getlist("fields") or params.getlist("fields[]")
            include_pem = params.get("include_pem", "false").lower() == "true"
            include_chain = params.get("include_chain", "true").lower() != "false"
        else:  # POST
            params = request.data
            export_format = params.get("format", "json")
            ids = params.get("ids", [])
            fields = params.get("fields", [])
            include_pem = params.get("include_pem", False)
            include_chain = params.get("include_chain", True)

        # Validate format
        valid_formats = [c[0] for c in ExportFormatChoices.get_choices()]
        if export_format.lower() not in valid_formats:
            raise serializers.ValidationError({"format": f"Invalid format. Choose from: {valid_formats}"})

        # Get certificates to export
        if ids:
            try:
                ids = [int(i) for i in ids]
                certificates = Certificate.objects.filter(pk__in=ids)
            except (ValueError, TypeError):
                raise serializers.ValidationError({"ids": "Invalid certificate IDs. Must be a list of integers."})
        else:
            # Apply filters from query parameters
            certificates = self.filter_queryset(self.get_queryset())

        # Limit export size
        plugin_settings = settings.PLUGINS_CONFIG.get("netbox_ssl", {})
        max_export_size = plugin_settings.get("max_export_size", 1000)
        if certificates.count() > max_export_size:
            raise serializers.ValidationError(
                {
                    "detail": f"Export size exceeds maximum of {max_export_size} certificates. "
                    "Use filters or specify IDs to reduce the result set."
                }
            )

        # Parse fields if provided
        if fields:
            if isinstance(fields, str):
                fields = [f.strip() for f in fields.split(",")]
        else:
            fields = None  # Use defaults

        try:
            # Generate export
            content = CertificateExporter.export(
                certificates,
                format=export_format,
                fields=fields,
                include_pem=include_pem,
                include_chain=include_chain,
            )
        except ImportError as e:
            raise serializers.ValidationError({"detail": str(e)})
        except Exception as e:
            raise serializers.ValidationError({"detail": f"Export failed: {str(e)}"})

        # Get content type and extension
        content_type = CertificateExporter.get_content_type(export_format)
        extension = CertificateExporter.get_file_extension(export_format)

        # Create response with file download
        response = HttpResponse(content, content_type=content_type)
        filename = f"certificates_export.{extension}"
        response["Content-Disposition"] = f'attachment; filename="{filename}"'

        return response

    @action(detail=True, methods=["get"], url_path="export")
    def export_single(self, request, pk=None):
        """
        Export a single certificate.

        GET parameters:
        - format: Export format (csv, json, yaml, pem). Default: json
        - include_pem: Include PEM content (json/yaml). Default: true
        - include_chain: Include certificate chain (pem). Default: true
        """
        certificate = self.get_object()

        export_format = request.query_params.get("format", "json")
        include_pem = request.query_params.get("include_pem", "true").lower() != "false"
        include_chain = request.query_params.get("include_chain", "true").lower() != "false"

        # Validate format
        valid_formats = [c[0] for c in ExportFormatChoices.get_choices()]
        if export_format.lower() not in valid_formats:
            raise serializers.ValidationError({"format": f"Invalid format. Choose from: {valid_formats}"})

        try:
            content = CertificateExporter.export(
                [certificate],
                format=export_format,
                include_pem=include_pem,
                include_chain=include_chain,
            )
        except ImportError as e:
            raise serializers.ValidationError({"detail": str(e)})

        content_type = CertificateExporter.get_content_type(export_format)
        extension = CertificateExporter.get_file_extension(export_format)

        response = HttpResponse(content, content_type=content_type)
        # Use common name in filename (sanitized)
        safe_name = "".join(c if c.isalnum() or c in ".-_" else "_" for c in certificate.common_name)
        filename = f"{safe_name}.{extension}"
        response["Content-Disposition"] = f'attachment; filename="{filename}"'

        return response


class CertificateAssignmentViewSet(NetBoxModelViewSet):
    """API viewset for CertificateAssignment model."""

    queryset = CertificateAssignment.objects.prefetch_related(
        "certificate",
        "assigned_object_type",
        "tags",
    )
    serializer_class = CertificateAssignmentSerializer
    filterset_class = CertificateAssignmentFilterSet
