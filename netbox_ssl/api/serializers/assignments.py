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

    @staticmethod
    def _get_object_tenant(obj):
        if obj is None:
            return None
        if hasattr(obj, "parent") and obj.parent:
            return getattr(obj.parent, "tenant", None)
        if hasattr(obj, "device") and obj.device:
            return getattr(obj.device, "tenant", None)
        if hasattr(obj, "virtual_machine") and obj.virtual_machine:
            return getattr(obj.virtual_machine, "tenant", None)
        return getattr(obj, "tenant", None)

    def validate(self, data):
        """Validate tenant boundaries for assignments."""
        data = super().validate(data)

        certificate = data.get("certificate") or getattr(self.instance, "certificate", None)
        assigned_object_type = data.get("assigned_object_type") or getattr(self.instance, "assigned_object_type", None)
        assigned_object_id = data.get("assigned_object_id") or getattr(self.instance, "assigned_object_id", None)

        if not certificate or not assigned_object_type or not assigned_object_id:
            return data

        if certificate.tenant is None:
            return data

        model_class = assigned_object_type.model_class()
        if model_class is None:
            return data

        assigned_object = model_class.objects.filter(pk=assigned_object_id).first()
        obj_tenant = self._get_object_tenant(assigned_object)

        if obj_tenant and obj_tenant != certificate.tenant:
            raise serializers.ValidationError("Certificate and assignment target must belong to the same tenant.")

        return data

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
