"""
REST API serializers for compliance reporting models.
"""

from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema_field
from netbox.api.serializers import NetBoxModelSerializer
from rest_framework import serializers
from tenancy.api.serializers import TenantSerializer

from ...models import (
    ComplianceCheck,
    CompliancePolicy,
    ComplianceTrendSnapshot,
)


class CompliancePolicySerializer(NetBoxModelSerializer):
    """Serializer for CompliancePolicy model."""

    url = serializers.HyperlinkedIdentityField(
        view_name="plugins-api:netbox_ssl-api:compliancepolicy-detail",
    )
    tenant = TenantSerializer(nested=True, required=False, allow_null=True)
    check_count = serializers.SerializerMethodField()

    class Meta:
        model = CompliancePolicy
        fields = [
            "id",
            "url",
            "display",
            "name",
            "description",
            "policy_type",
            "severity",
            "enabled",
            "parameters",
            "tenant",
            "tag_filter",
            "check_count",
            "tags",
            "custom_fields",
            "created",
            "last_updated",
        ]
        brief_fields = [
            "id",
            "url",
            "display",
            "name",
            "policy_type",
            "severity",
            "enabled",
        ]

    def get_check_count(self, obj) -> int:
        """Get the number of checks performed with this policy."""
        return obj.checks.count()


class ComplianceCheckSerializer(NetBoxModelSerializer):
    """Serializer for ComplianceCheck model."""

    url = serializers.HyperlinkedIdentityField(
        view_name="plugins-api:netbox_ssl-api:compliancecheck-detail",
    )
    certificate = serializers.SerializerMethodField()
    policy = CompliancePolicySerializer(nested=True, read_only=True)
    is_passing = serializers.BooleanField(read_only=True)
    is_failing = serializers.BooleanField(read_only=True)
    severity = serializers.CharField(read_only=True)

    class Meta:
        model = ComplianceCheck
        fields = [
            "id",
            "url",
            "display",
            "certificate",
            "policy",
            "result",
            "message",
            "checked_at",
            "checked_value",
            "expected_value",
            "is_passing",
            "is_failing",
            "severity",
            "tags",
            "custom_fields",
            "created",
            "last_updated",
        ]
        brief_fields = [
            "id",
            "url",
            "display",
            "result",
            "checked_at",
        ]

    @extend_schema_field(OpenApiTypes.OBJECT)
    def get_certificate(self, obj):
        """Get basic certificate information."""
        return {
            "id": obj.certificate.id,
            "common_name": obj.certificate.common_name,
            "serial_number": obj.certificate.serial_number,
        }


class ComplianceTrendSnapshotSerializer(NetBoxModelSerializer):
    """Serializer for ComplianceTrendSnapshot.

    Required because ComplianceTrendSnapshot is a NetBoxModel: saving it in a
    request context calls serialize_for_event → get_serializer_for_model, which
    raises SerializerNotFound on NetBox 4.4 without a registered serializer.
    """

    url = serializers.HyperlinkedIdentityField(
        view_name="plugins-api:netbox_ssl-api:compliancetrendsnapshot-detail",
    )
    tenant = TenantSerializer(nested=True, required=False, allow_null=True)

    class Meta:
        model = ComplianceTrendSnapshot
        fields = [
            "id",
            "url",
            "display",
            "tenant",
            "snapshot_date",
            "total_certificates",
            "total_checks",
            "passed_checks",
            "failed_checks",
            "compliance_score",
            "details",
            "tags",
            "custom_fields",
            "created",
            "last_updated",
        ]
        brief_fields = ["id", "url", "display", "snapshot_date", "compliance_score"]


class ComplianceRunSerializer(serializers.Serializer):
    """Serializer for running compliance checks."""

    policy_ids = serializers.ListField(
        child=serializers.IntegerField(),
        required=False,
        help_text="Optional list of specific policy IDs to check. If not provided, all enabled policies are used.",
    )


class BulkComplianceRunSerializer(serializers.Serializer):
    """Serializer for running bulk compliance checks."""

    certificate_ids = serializers.ListField(
        child=serializers.IntegerField(),
        required=True,
        help_text="List of certificate IDs to check.",
    )
    policy_ids = serializers.ListField(
        child=serializers.IntegerField(),
        required=False,
        help_text="Optional list of specific policy IDs to check.",
    )


class ComplianceReportSerializer(serializers.Serializer):
    """Serializer for compliance report response."""

    certificate_id = serializers.IntegerField()
    certificate_name = serializers.CharField()
    total_checks = serializers.IntegerField()
    passed = serializers.IntegerField()
    failed = serializers.IntegerField()
    compliance_score = serializers.FloatField()
    checks = ComplianceCheckSerializer(many=True)
