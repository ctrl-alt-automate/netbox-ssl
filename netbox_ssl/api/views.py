"""
REST API views for NetBox SSL plugin.
"""

from django.conf import settings
from django.db import DatabaseError, IntegrityError, transaction
from django.db.models import Count
from django.http import HttpResponse
from netbox.api.viewsets import NetBoxModelViewSet
from rest_framework import serializers, status
from rest_framework.decorators import action
from rest_framework.response import Response

from ..filtersets import (
    CertificateAssignmentFilterSet,
    CertificateAuthorityFilterSet,
    CertificateFilterSet,
    CertificateSigningRequestFilterSet,
    ComplianceCheckFilterSet,
    CompliancePolicyFilterSet,
)
from ..models import (
    Certificate,
    CertificateAssignment,
    CertificateAuthority,
    CertificateSigningRequest,
    ComplianceCheck,
    CompliancePolicy,
)
from ..utils import CertificateExporter, ComplianceChecker, ExportFormatChoices
from .serializers import (
    BulkComplianceRunSerializer,
    CertificateAssignmentSerializer,
    CertificateAuthoritySerializer,
    CertificateImportSerializer,
    CertificateSerializer,
    CertificateSigningRequestSerializer,
    ComplianceCheckSerializer,
    CompliancePolicySerializer,
    ComplianceRunSerializer,
    CSRImportSerializer,
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

        # Get certificates to export with assignment count annotation to avoid N+1 queries
        if ids:
            try:
                ids = [int(i) for i in ids]
                certificates = Certificate.objects.filter(pk__in=ids).annotate(_assignment_count=Count("assignments"))
            except (ValueError, TypeError) as e:
                raise serializers.ValidationError(
                    {"ids": "Invalid certificate IDs. Must be a list of integers."}
                ) from e
        else:
            # Apply filters from query parameters
            certificates = self.filter_queryset(self.get_queryset()).annotate(_assignment_count=Count("assignments"))

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
            raise serializers.ValidationError({"detail": str(e)}) from e
        except Exception as e:
            raise serializers.ValidationError({"detail": f"Export failed: {str(e)}"}) from e

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
            raise serializers.ValidationError({"detail": str(e)}) from e

        content_type = CertificateExporter.get_content_type(export_format)
        extension = CertificateExporter.get_file_extension(export_format)

        response = HttpResponse(content, content_type=content_type)
        # Use common name in filename (sanitized)
        safe_name = "".join(c if c.isalnum() or c in ".-_" else "_" for c in certificate.common_name)
        filename = f"{safe_name}.{extension}"
        response["Content-Disposition"] = f'attachment; filename="{filename}"'

        return response

    @action(detail=True, methods=["post"], url_path="compliance-check")
    def compliance_check(self, request, pk=None):
        """
        Run compliance checks on a single certificate.

        Runs all enabled compliance policies against the certificate and
        returns detailed results. Optionally specify specific policy IDs.

        Example payload (optional):
        {
            "policy_ids": [1, 2, 3]
        }
        """
        certificate = self.get_object()
        serializer = ComplianceRunSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Get policies to check
        policy_ids = serializer.validated_data.get("policy_ids")
        policies = (
            CompliancePolicy.objects.filter(pk__in=policy_ids, enabled=True)
            if policy_ids
            else None  # Will use all enabled policies
        )

        # Run compliance checks
        results = ComplianceChecker.run_all_checks(certificate, policies)

        # Save results to database
        saved_checks = ComplianceChecker.save_check_results(certificate, results)

        # Calculate summary
        total = len(saved_checks)
        passed = sum(1 for c in saved_checks if c.is_passing)
        failed = total - passed
        score = (passed / total * 100) if total > 0 else 0

        # Serialize and return
        check_serializer = ComplianceCheckSerializer(saved_checks, many=True, context={"request": request})

        return Response(
            {
                "certificate_id": certificate.pk,
                "certificate_name": certificate.common_name,
                "total_checks": total,
                "passed": passed,
                "failed": failed,
                "compliance_score": round(score, 1),
                "checks": check_serializer.data,
            },
            status=status.HTTP_200_OK,
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

    @action(detail=False, methods=["post"], url_path="bulk-validate-chain")
    def bulk_validate_chain(self, request):
        """
        Validate certificate chains for multiple certificates.

        Accepts a list of certificate IDs and validates each one.

        Example payload:
        {
            "ids": [1, 2, 3, 4, 5]
        }
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

        certificates = list(Certificate.objects.filter(pk__in=certificate_ids))
        results = []
        certs_to_update = []

        for cert in certificates:
            if cert.pem_content:
                result = cert.validate_chain(save=False)
                certs_to_update.append(cert)
                results.append(
                    {
                        "id": cert.pk,
                        "common_name": cert.common_name,
                        "status": result.status.value if result else "error",
                        "is_valid": result.is_valid if result else False,
                        "message": result.message if result else "Validation error",
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

        # Bulk update all certificates at once
        if certs_to_update:
            Certificate.objects.bulk_update(
                certs_to_update,
                ["chain_status", "chain_validation_message", "chain_validated_at", "chain_depth"],
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

    @action(detail=False, methods=["post"], url_path="bulk-compliance-check")
    def bulk_compliance_check(self, request):
        """
        Run compliance checks on multiple certificates.

        Example payload:
        {
            "certificate_ids": [1, 2, 3, 4, 5],
            "policy_ids": [1, 2]  // optional
        }
        """
        serializer = BulkComplianceRunSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        certificate_ids = serializer.validated_data["certificate_ids"]
        policy_ids = serializer.validated_data.get("policy_ids")

        # Limit batch size
        plugin_settings = settings.PLUGINS_CONFIG.get("netbox_ssl", {})
        max_batch_size = plugin_settings.get("bulk_compliance_max_batch_size", 100)
        if len(certificate_ids) > max_batch_size:
            raise serializers.ValidationError(
                {"detail": f"Batch size exceeds maximum of {max_batch_size} certificates."}
            )

        # Get certificates with tenant prefetched to avoid N+1 queries
        certificates = Certificate.objects.filter(pk__in=certificate_ids).select_related("tenant")
        found_ids = set(certificates.values_list("pk", flat=True))
        missing_ids = set(certificate_ids) - found_ids

        # Get base policies queryset - fetch once, filter by tenant per certificate in run_all_checks
        if policy_ids:
            base_policies = CompliancePolicy.objects.filter(pk__in=policy_ids, enabled=True)
        else:
            base_policies = CompliancePolicy.objects.filter(enabled=True)

        # Prefetch all policies to avoid N+1 queries
        policies_list = list(base_policies)

        # Run checks for each certificate
        results_summary = {
            "total_certificates": len(certificate_ids),
            "processed": 0,
            "missing_ids": list(missing_ids),
            "overall_passed": 0,
            "overall_failed": 0,
            "reports": [],
        }

        for certificate in certificates:
            # Filter policies by tenant in Python to avoid N+1 queries
            if certificate.tenant:
                cert_policies = [p for p in policies_list if p.tenant is None or p.tenant_id == certificate.tenant_id]
            else:
                cert_policies = [p for p in policies_list if p.tenant is None]

            results = ComplianceChecker.run_all_checks(certificate, cert_policies)
            saved_checks = ComplianceChecker.save_check_results(certificate, results)

            total = len(saved_checks)
            passed = sum(1 for c in saved_checks if c.is_passing)
            failed = total - passed
            score = (passed / total * 100) if total > 0 else 0

            results_summary["processed"] += 1
            results_summary["overall_passed"] += passed
            results_summary["overall_failed"] += failed

            results_summary["reports"].append(
                {
                    "certificate_id": certificate.pk,
                    "certificate_name": certificate.common_name,
                    "total_checks": total,
                    "passed": passed,
                    "failed": failed,
                    "compliance_score": round(score, 1),
                }
            )

        # Calculate overall score
        total_checks = results_summary["overall_passed"] + results_summary["overall_failed"]
        results_summary["overall_score"] = (
            round(results_summary["overall_passed"] / total_checks * 100, 1) if total_checks > 0 else 0
        )

        return Response(results_summary, status=status.HTTP_200_OK)

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


class CertificateAuthorityViewSet(NetBoxModelViewSet):
    """API viewset for CertificateAuthority model."""

    queryset = CertificateAuthority.objects.prefetch_related(
        "certificates",
        "tags",
    )
    serializer_class = CertificateAuthoritySerializer
    filterset_class = CertificateAuthorityFilterSet


class CertificateSigningRequestViewSet(NetBoxModelViewSet):
    """API viewset for CertificateSigningRequest model."""

    queryset = CertificateSigningRequest.objects.prefetch_related(
        "tenant",
        "resulting_certificate",
        "tags",
    )
    serializer_class = CertificateSigningRequestSerializer
    filterset_class = CertificateSigningRequestFilterSet

    @action(detail=False, methods=["post"], url_path="import")
    def import_csr(self, request):
        """
        Import a CSR from PEM content.

        Accepts raw PEM content and automatically parses all CSR attributes.
        """
        serializer = CSRImportSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        csr = serializer.save()

        # Return the created CSR using the standard serializer
        output_serializer = CertificateSigningRequestSerializer(csr, context={"request": request})
        return Response(output_serializer.data, status=status.HTTP_201_CREATED)


class CompliancePolicyViewSet(NetBoxModelViewSet):
    """API viewset for CompliancePolicy model."""

    queryset = CompliancePolicy.objects.prefetch_related(
        "tenant",
        "tags",
    )
    serializer_class = CompliancePolicySerializer
    filterset_class = CompliancePolicyFilterSet


class ComplianceCheckViewSet(NetBoxModelViewSet):
    """API viewset for ComplianceCheck model."""

    queryset = ComplianceCheck.objects.select_related(
        "certificate",
        "policy",
    ).prefetch_related("tags")
    serializer_class = ComplianceCheckSerializer
    filterset_class = ComplianceCheckFilterSet
