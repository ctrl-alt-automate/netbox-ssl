"""
REST API serializers for CertificateAssignment model.
"""

from netbox.api.fields import ContentTypeField
from netbox.api.serializers import NetBoxModelSerializer
from rest_framework import serializers

from ...models import CertificateAssignment
from .certificates import CertificateSerializer


class CertificateAssignmentSerializer(NetBoxModelSerializer):
    """Serializer for CertificateAssignment model."""

    url = serializers.HyperlinkedIdentityField(
        view_name="plugins-api:netbox_ssl-api:certificateassignment-detail",
    )
    certificate = CertificateSerializer(nested=True)
    assigned_object_type = ContentTypeField(
        queryset=CertificateAssignment._meta.get_field("assigned_object_type").remote_field.model.objects.all(),
    )
    assigned_object = serializers.SerializerMethodField()

    class Meta:
        model = CertificateAssignment
        fields = [
            "id",
            "url",
            "display",
            "certificate",
            "assigned_object_type",
            "assigned_object_id",
            "assigned_object",
            "is_primary",
            "notes",
            "tags",
            "custom_fields",
            "created",
            "last_updated",
        ]
        brief_fields = [
            "id",
            "url",
            "display",
            "certificate",
            "assigned_object_type",
            "assigned_object_id",
            "is_primary",
        ]

    def get_assigned_object(self, obj):
        """Return basic info about the assigned object."""
        if obj.assigned_object:
            return {
                "id": obj.assigned_object_id,
                "name": str(obj.assigned_object),
                "url": obj.assigned_object.get_absolute_url()
                if hasattr(obj.assigned_object, "get_absolute_url")
                else None,
            }
        return None
