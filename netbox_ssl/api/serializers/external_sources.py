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

    class Meta:
        model = ExternalSource
        fields = [
            "id",
            "url",
            "display",
            "name",
            "source_type",
            "base_url",
            "auth_method",
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
        """Check if the source has credential references configured."""
        return bool(obj.auth_credentials_reference)


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
