"""
REST API serializers for ExternalSource model.
"""

from netbox.api.serializers import NetBoxModelSerializer
from rest_framework import serializers
from tenancy.api.serializers import TenantSerializer

from ...models import ExternalSource
from ...models.external_source import ExternalSourceSyncLog


class ExternalSourceSerializer(NetBoxModelSerializer):
    """Serializer for ExternalSource model."""

    url = serializers.HyperlinkedIdentityField(
        view_name="plugins-api:netbox_ssl-api:externalsource-detail",
    )
    tenant = TenantSerializer(nested=True, required=False, allow_null=True)
    certificate_count = serializers.SerializerMethodField()
    has_credentials = serializers.SerializerMethodField()

    # Write-only: never expose credential references in API output
    auth_credentials_reference = serializers.CharField(
        write_only=True,
        required=False,
        allow_blank=True,
        max_length=512,
    )
    auth_credentials = serializers.JSONField(
        write_only=True,
        required=False,
        default=dict,
        help_text=(
            "Mapping of credential component name to env-var reference. See ExternalSource model help for format."
        ),
    )

    class Meta:
        model = ExternalSource
        fields = [
            "id",
            "url",
            "display",
            "name",
            "source_type",
            "base_url",
            "region",
            "auth_method",
            "auth_credentials",
            "auth_credentials_reference",
            "has_credentials",
            "field_mapping",
            "sync_interval_minutes",
            "enabled",
            "tenant",
            "sync_status",
            "last_synced",
            "last_sync_message",
            "verify_ssl",
            "certificate_count",
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
            "source_type",
            "enabled",
            "sync_status",
        ]

    def get_certificate_count(self, obj) -> int:
        """Get the number of certificates synced from this source."""
        return obj.certificates.count()

    def get_has_credentials(self, obj) -> bool:
        """Indicate whether the source is authorized to run.

        Role-based auth (e.g., AWS instance role, Azure Managed Identity)
        needs no stored credentials but still has valid auth. The set of
        role-based methods is declared per-adapter via IMPLICIT_AUTH_METHODS.
        """
        from ...adapters import get_adapter_class

        try:
            if obj.auth_method in get_adapter_class(obj.source_type).IMPLICIT_AUTH_METHODS:
                return True
        except KeyError:
            pass
        return bool(obj.auth_credentials or obj.auth_credentials_reference)

    def validate(self, attrs):
        """Validate credential payload against adapter schema + requirements."""
        from ...utils.external_source_validator import ExternalSourceSchemaValidator

        source_type = attrs.get("source_type")
        auth_method = attrs.get("auth_method")
        auth_credentials = attrs.get("auth_credentials") or {}
        base_url = attrs.get("base_url")
        region = attrs.get("region")

        # On PATCH, instance fields fill in missing attrs
        if self.instance is not None:
            source_type = source_type or self.instance.source_type
            auth_method = auth_method or self.instance.auth_method
            if base_url is None:
                base_url = self.instance.base_url
            if region is None:
                region = self.instance.region

        ExternalSourceSchemaValidator.validate(
            source_type=source_type,
            auth_method=auth_method,
            auth_credentials=auth_credentials,
            base_url=base_url or "",
            region=region or "",
        )
        return attrs


class ExternalSourceSyncLogSerializer(serializers.ModelSerializer):
    """Read-only serializer for ExternalSourceSyncLog."""

    class Meta:
        model = ExternalSourceSyncLog
        fields = [
            "id",
            "source",
            "started_at",
            "finished_at",
            "success",
            "dry_run",
            "message",
            "certificates_fetched",
            "certificates_created",
            "certificates_updated",
            "certificates_renewed",
            "certificates_removed",
            "certificates_unchanged",
            "errors",
        ]
        read_only_fields = fields
