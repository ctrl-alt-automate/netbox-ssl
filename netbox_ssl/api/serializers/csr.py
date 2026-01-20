"""
REST API serializers for CertificateSigningRequest model.
"""

from netbox.api.serializers import NetBoxModelSerializer
from rest_framework import serializers
from tenancy.api.serializers import TenantSerializer
from tenancy.models import Tenant

from ...models import CertificateSigningRequest, CSRStatusChoices
from ...utils import CSRParseError, CSRParser


class CertificateSigningRequestSerializer(NetBoxModelSerializer):
    """Serializer for CertificateSigningRequest model."""

    url = serializers.HyperlinkedIdentityField(
        view_name="plugins-api:netbox_ssl-api:certificatesigningrequest-detail",
    )
    tenant = TenantSerializer(nested=True, required=False, allow_null=True)
    subject_string = serializers.CharField(read_only=True)

    class Meta:
        model = CertificateSigningRequest
        fields = [
            "id",
            "url",
            "display",
            "common_name",
            "organization",
            "organizational_unit",
            "locality",
            "state",
            "country",
            "subject_string",
            "sans",
            "key_size",
            "algorithm",
            "fingerprint_sha256",
            "pem_content",
            "status",
            "requested_date",
            "requested_by",
            "target_ca",
            "notes",
            "resulting_certificate",
            "tenant",
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
            "status",
            "requested_date",
        ]


class CSRImportSerializer(serializers.Serializer):
    """Serializer for importing CSRs from PEM content."""

    pem_content = serializers.CharField(
        help_text="CSR in PEM format.",
        style={"base_template": "textarea.html"},
    )
    requested_by = serializers.CharField(
        required=False,
        allow_blank=True,
        max_length=255,
        help_text="Who requested this certificate.",
    )
    target_ca = serializers.CharField(
        required=False,
        allow_blank=True,
        max_length=255,
        help_text="Intended Certificate Authority for signing.",
    )
    tenant = serializers.PrimaryKeyRelatedField(
        queryset=Tenant.objects.all(),
        required=False,
        allow_null=True,
        help_text="Optional tenant assignment.",
    )

    def validate_pem_content(self, value):
        """Validate PEM content."""
        try:
            CSRParser.parse(value)
        except CSRParseError as e:
            raise serializers.ValidationError(str(e)) from e

        return value

    def validate(self, data):
        """Check for duplicate CSRs."""
        pem_content = data.get("pem_content")
        if not pem_content:
            return data

        try:
            parsed = CSRParser.parse(pem_content)
        except CSRParseError:
            return data

        existing = CertificateSigningRequest.objects.filter(
            fingerprint_sha256=parsed.fingerprint_sha256,
        ).first()

        if existing:
            raise serializers.ValidationError(
                {
                    "pem_content": f"CSR already exists: {existing.common_name} "
                    f"(ID: {existing.pk})"
                }
            )

        return data

    def create(self, validated_data):
        """Create a CSR from parsed PEM content."""
        pem_content = validated_data["pem_content"]
        parsed = CSRParser.parse(pem_content)

        csr = CertificateSigningRequest.objects.create(
            common_name=parsed.common_name,
            organization=parsed.organization,
            organizational_unit=parsed.organizational_unit,
            locality=parsed.locality,
            state=parsed.state,
            country=parsed.country,
            sans=parsed.sans,
            key_size=parsed.key_size,
            algorithm=parsed.algorithm,
            fingerprint_sha256=parsed.fingerprint_sha256,
            pem_content=parsed.pem_content,
            requested_by=validated_data.get("requested_by", ""),
            target_ca=validated_data.get("target_ca", ""),
            tenant=validated_data.get("tenant"),
            status=CSRStatusChoices.STATUS_PENDING,
        )

        return csr
