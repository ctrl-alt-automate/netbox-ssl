"""
REST API serializers for Certificate model.
"""

from rest_framework import serializers

from netbox.api.serializers import NetBoxModelSerializer
from tenancy.api.serializers import TenantSerializer

from ...models import Certificate


class CertificateSerializer(NetBoxModelSerializer):
    """Serializer for Certificate model."""

    url = serializers.HyperlinkedIdentityField(
        view_name="plugins-api:netbox_ssl-api:certificate-detail",
    )
    tenant = TenantSerializer(nested=True, required=False, allow_null=True)
    days_remaining = serializers.IntegerField(read_only=True)
    is_expired = serializers.BooleanField(read_only=True)
    is_expiring_soon = serializers.BooleanField(read_only=True)
    expiry_status = serializers.CharField(read_only=True)
    assignment_count = serializers.SerializerMethodField()

    class Meta:
        model = Certificate
        fields = [
            "id",
            "url",
            "display",
            "common_name",
            "serial_number",
            "fingerprint_sha256",
            "issuer",
            "issuer_chain",
            "valid_from",
            "valid_to",
            "days_remaining",
            "is_expired",
            "is_expiring_soon",
            "expiry_status",
            "sans",
            "key_size",
            "algorithm",
            "status",
            "private_key_location",
            "replaced_by",
            "tenant",
            "pem_content",
            "assignment_count",
            "tags",
            "custom_fields",
            "created",
            "last_updated",
        ]
        brief_fields = [
            "id",
            "url",
            "display",
            "common_name",
            "serial_number",
            "status",
            "valid_to",
            "days_remaining",
        ]

    def get_assignment_count(self, obj):
        """Get the number of assignments for this certificate."""
        return obj.assignments.count()
