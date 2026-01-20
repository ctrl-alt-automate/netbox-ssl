"""
REST API views for NetBox SSL plugin.
"""

from django.conf import settings
from django.db import DatabaseError, IntegrityError, transaction
from netbox.api.viewsets import NetBoxModelViewSet
from rest_framework import serializers, status
from rest_framework.decorators import action
from rest_framework.response import Response

from ..filtersets import (
    CertificateAssignmentFilterSet,
    CertificateFilterSet,
    ComplianceCheckFilterSet,
    CompliancePolicyFilterSet,
)
from ..models import Certificate, CertificateAssignment, ComplianceCheck, CompliancePolicy
from ..utils import ComplianceChecker
from .serializers import (
    BulkComplianceRunSerializer,
    CertificateAssignmentSerializer,
    CertificateImportSerializer,
    CertificateSerializer,
    ComplianceCheckSerializer,
    CompliancePolicySerializer,
    ComplianceRunSerializer,
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


class CertificateAssignmentViewSet(NetBoxModelViewSet):
    """API viewset for CertificateAssignment model."""

    queryset = CertificateAssignment.objects.prefetch_related(
        "certificate",
        "assigned_object_type",
        "tags",
    )
    serializer_class = CertificateAssignmentSerializer
    filterset_class = CertificateAssignmentFilterSet


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
