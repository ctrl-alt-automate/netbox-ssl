"""
Template extensions for displaying certificates on Device, VM, and Service pages.

These extensions inject certificate information into the detail views of
related NetBox objects.
"""

from django.contrib.contenttypes.models import ContentType

from netbox.plugins import PluginTemplateExtension

from .models import CertificateAssignment


class CertificateExtensionMixin:
    """Mixin providing certificate lookup for template extensions."""

    def get_certificates(self):
        """Get certificate assignments for the current object."""
        obj = self.context.get("object")
        if not obj:
            return []

        content_type = ContentType.objects.get_for_model(obj)
        return CertificateAssignment.objects.filter(
            assigned_object_type=content_type,
            assigned_object_id=obj.pk,
        ).select_related("certificate")


class DeviceVMServiceCertificates(CertificateExtensionMixin, PluginTemplateExtension):
    """Show certificates assigned to Devices, Virtual Machines, and Services."""

    # NetBox 4.3+ requires 'models' (plural) instead of 'model'
    models = [
        "dcim.device",
        "virtualization.virtualmachine",
        "ipam.service",
    ]

    def right_page(self):
        assignments = self.get_certificates()
        if not assignments:
            return ""
        return self.render(
            "netbox_ssl/inc/certificate_panel.html",
            extra_context={"assignments": assignments},
        )


# List of template extensions to register
template_extensions = [
    DeviceVMServiceCertificates,
]
