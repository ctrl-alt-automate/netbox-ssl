"""
REST API serializers for Certificate model.
"""

from netbox.api.serializers import NetBoxModelSerializer
from rest_framework import serializers
from tenancy.api.serializers import TenantSerializer
from tenancy.models import Tenant

from ...models import Certificate, CertificateStatusChoices
from ...utils import CertificateParseError, CertificateParser, detect_issuing_ca
from .certificate_authorities import CertificateAuthoritySerializer
from .external_sources import ExternalSourceSerializer


class CertificateSerializer(NetBoxModelSerializer):
    """Serializer for Certificate model."""

    url = serializers.HyperlinkedIdentityField(
        view_name="plugins-api:netbox_ssl-api:certificate-detail",
    )
    tenant = TenantSerializer(nested=True, required=False, allow_null=True)
    issuing_ca = CertificateAuthoritySerializer(nested=True, required=False, allow_null=True)
    external_source = ExternalSourceSerializer(nested=True, required=False, allow_null=True, read_only=True)
    days_remaining = serializers.IntegerField(read_only=True)
    is_expired = serializers.BooleanField(read_only=True)
    is_expiring_soon = serializers.BooleanField(read_only=True)
    expiry_status = serializers.CharField(read_only=True)
    assignment_count = serializers.SerializerMethodField()
    chain_is_valid = serializers.BooleanField(read_only=True)
    chain_needs_validation = serializers.BooleanField(read_only=True)
    acme_renewal_due = serializers.BooleanField(read_only=True)
    acme_renewal_status = serializers.CharField(read_only=True)
    ari_window_active = serializers.BooleanField(read_only=True)
    ari_status = serializers.CharField(read_only=True)
    effective_renewal_instructions = serializers.SerializerMethodField()

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
            "renewal_note",
            "effective_renewal_instructions",
            "replaced_by",
            "tenant",
            "pem_content",
            "assignment_count",
            # Chain validation fields
            "chain_status",
            "chain_validation_message",
            "chain_validated_at",
            "chain_depth",
            "chain_is_valid",
            "chain_needs_validation",
            # ACME fields
            "is_acme",
            "acme_provider",
            "acme_account_email",
            "acme_challenge_type",
            "acme_server_url",
            "acme_auto_renewal",
            "acme_last_renewed",
            "acme_renewal_days",
            "acme_renewal_due",
            "acme_renewal_status",
            # ARI fields (RFC 9773)
            "ari_cert_id",
            "ari_suggested_start",
            "ari_suggested_end",
            "ari_explanation_url",
            "ari_last_checked",
            "ari_retry_after",
            "ari_window_active",
            "ari_status",
            # Archival fields
            "archive_pinned",
            "archived_at",
            # External source fields
            "external_source",
            "external_id",
            "source_removed",
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
            "chain_status",
            "is_acme",
        ]

    def get_assignment_count(self, obj):
        """Get the number of assignments for this certificate."""
        return obj.assignments.count()

    def get_effective_renewal_instructions(self, obj) -> str:
        """Get renewal instructions with fallback: cert note > CA instructions > empty."""
        if obj.renewal_note:
            return obj.renewal_note
        if obj.issuing_ca and hasattr(obj.issuing_ca, "renewal_instructions"):
            return obj.issuing_ca.renewal_instructions or ""
        return ""


class CertificateImportSerializer(serializers.Serializer):
    """Serializer for importing certificates from PEM content."""

    pem_content = serializers.CharField(
        max_length=65536,
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

        # Auto-detect issuing CA based on issuer string
        issuing_ca = detect_issuing_ca(parsed.issuer)

        certificate = Certificate.objects.create(
            common_name=parsed.common_name,
            serial_number=parsed.serial_number,
            fingerprint_sha256=parsed.fingerprint_sha256,
            issuer=parsed.issuer,
            issuing_ca=issuing_ca,
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

        # Auto-detect ACME provider
        certificate.auto_detect_acme(save=True)

        return certificate


class BulkStatusUpdateSerializer(serializers.Serializer):
    """Serializer for bulk status update."""

    ids = serializers.ListField(
        child=serializers.IntegerField(),
        allow_empty=False,
        help_text="List of certificate IDs to update.",
    )
    status = serializers.ChoiceField(
        choices=CertificateStatusChoices,
        help_text="New status to set.",
    )


class BulkAssignSerializer(serializers.Serializer):
    """Serializer for bulk certificate assignment."""

    certificate_ids = serializers.ListField(
        child=serializers.IntegerField(),
        allow_empty=False,
        help_text="List of certificate IDs to assign.",
    )
    assigned_object_type = serializers.CharField(
        help_text="Content type (e.g., 'dcim.device', 'dcim.service', 'virtualization.virtualmachine').",
    )
    assigned_object_id = serializers.IntegerField(
        help_text="ID of the object to assign certificates to.",
    )
    is_primary = serializers.BooleanField(
        default=True,
        help_text="Whether this is the primary certificate for the object.",
    )
