"""
REST API serializers for Certificate model.
"""

from netbox.api.serializers import NetBoxModelSerializer
from rest_framework import serializers
from tenancy.api.serializers import TenantSerializer
from tenancy.models import Tenant

from ...models import Certificate, CertificateAuthority, CertificateStatusChoices
from .certificate_authorities import CertificateAuthoritySerializer
from ...utils import CertificateParseError, CertificateParser


class CertificateSerializer(NetBoxModelSerializer):
    """Serializer for Certificate model."""

    url = serializers.HyperlinkedIdentityField(
        view_name="plugins-api:netbox_ssl-api:certificate-detail",
    )
    tenant = TenantSerializer(nested=True, required=False, allow_null=True)
    issuing_ca = CertificateAuthoritySerializer(nested=True, required=False, allow_null=True)
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
            "issuing_ca",
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


class CertificateImportSerializer(serializers.Serializer):
    """Serializer for importing certificates from PEM content."""

    pem_content = serializers.CharField(
        help_text="Certificate in PEM format. May include certificate chain.",
        style={"base_template": "textarea.html"},
    )
    private_key_location = serializers.CharField(
        required=False,
        allow_blank=True,
        max_length=512,
        help_text="Optional hint for where the private key is stored.",
    )
    tenant = serializers.PrimaryKeyRelatedField(
        queryset=Tenant.objects.all(),
        required=False,
        allow_null=True,
        help_text="Optional tenant assignment.",
    )

    def validate_pem_content(self, value):
        """Validate PEM content and check for private keys."""
        if CertificateParser.contains_private_key(value):
            raise serializers.ValidationError(
                "Private key detected. For security reasons, private keys cannot be stored."
            )

        try:
            CertificateParser.parse(value)
        except CertificateParseError as e:
            raise serializers.ValidationError(str(e)) from e

        return value

    def validate(self, data):
        """Check for duplicate certificates."""
        pem_content = data.get("pem_content")
        if not pem_content:
            return data

        try:
            parsed = CertificateParser.parse(pem_content)
        except CertificateParseError:
            return data

        existing = Certificate.objects.filter(
            serial_number=parsed.serial_number,
            issuer=parsed.issuer,
        ).first()

        if existing:
            raise serializers.ValidationError(
                {
                    "pem_content": f"Certificate already exists: {existing.common_name} "
                    f"(ID: {existing.pk}, Serial: {existing.serial_number[:20]}...)"
                }
            )

        return data

    def create(self, validated_data):
        """Create a certificate from parsed PEM content."""
        pem_content = validated_data["pem_content"]
        parsed = CertificateParser.parse(pem_content)

        certificate = Certificate.objects.create(
            common_name=parsed.common_name,
            serial_number=parsed.serial_number,
            fingerprint_sha256=parsed.fingerprint_sha256,
            issuer=parsed.issuer,
            valid_from=parsed.valid_from,
            valid_to=parsed.valid_to,
            sans=parsed.sans,
            key_size=parsed.key_size,
            algorithm=parsed.algorithm,
            pem_content=parsed.pem_content,
            issuer_chain=parsed.issuer_chain,
            private_key_location=validated_data.get("private_key_location", ""),
            tenant=validated_data.get("tenant"),
            status=CertificateStatusChoices.STATUS_ACTIVE,
        )

        return certificate
