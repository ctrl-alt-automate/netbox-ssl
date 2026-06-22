"""REST API serializer for the MonitoredEndpoint model.

NetBox requires a registered serializer for every NetBoxModel: when an endpoint
is saved in a request context, the change-logging machinery calls
``serialize_for_event`` → ``get_serializer_for_model``. Without this serializer
that raises ``SerializerNotFound`` on NetBox 4.4.
"""

from netbox.api.serializers import NetBoxModelSerializer
from rest_framework import serializers
from tenancy.api.serializers import TenantSerializer

from ...models import MonitoredEndpoint


class MonitoredEndpointSerializer(NetBoxModelSerializer):
    """Serializer for the MonitoredEndpoint model."""

    url = serializers.HyperlinkedIdentityField(
        view_name="plugins-api:netbox_ssl-api:monitoredendpoint-detail",
    )
    # The model field is named ``url`` (the monitored website); ``url`` above is
    # the NetBox API self-link, so expose the website under ``target_url``.
    target_url = serializers.CharField(source="url", max_length=500)
    tenant = TenantSerializer(nested=True, required=False, allow_null=True)
    certificate = serializers.SerializerMethodField()
    days_remaining = serializers.IntegerField(read_only=True, allow_null=True)

    class Meta:
        model = MonitoredEndpoint
        fields = [
            "id",
            "url",
            "display",
            "name",
            "target_url",
            "sni",
            "certificate",
            "status",
            "last_checked",
            "last_seen",
            "tenant",
            "days_remaining",
            "tags",
            "custom_fields",
            "created",
            "last_updated",
        ]
        brief_fields = ["id", "url", "display", "name", "status"]

    def get_certificate(self, obj) -> dict | None:
        """Brief reference to the linked certificate (id + common name)."""
        if obj.certificate_id:
            return {"id": obj.certificate_id, "common_name": obj.certificate.common_name}
        return None
