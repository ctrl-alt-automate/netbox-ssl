"""
REST API serializers for CertificateAuthority model.
"""

from netbox.api.serializers import NetBoxModelSerializer
from rest_framework import serializers

from ...models import CertificateAuthority


class CertificateAuthoritySerializer(NetBoxModelSerializer):
    """Serializer for CertificateAuthority model."""

    url = serializers.HyperlinkedIdentityField(
        view_name="plugins-api:netbox_ssl-api:certificateauthority-detail",
    )
    certificate_count = serializers.SerializerMethodField()

    class Meta:
        model = CertificateAuthority
        fields = [
            "id",
            "url",
            "display",
            "name",
            "type",
            "description",
            "issuer_pattern",
            "website_url",
            "portal_url",
            "contact_email",
            "is_approved",
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
            "type",
            "is_approved",
        ]

    def get_certificate_count(self, obj):
        """Get the number of certificates issued by this CA."""
        return obj.certificates.count()
