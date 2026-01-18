"""
Template extensions for displaying certificates on Device, VM, and Service pages.

These extensions inject certificate information into the detail views of
related NetBox objects.
"""

from django.contrib.contenttypes.models import ContentType

from netbox.plugins import PluginTemplateExtension

from .models import CertificateAssignment


class DeviceCertificates(PluginTemplateExtension):
    """Show certificates assigned to a Device and its Services."""

    models = ["dcim.device"]

    def right_page(self):
        from dcim.models import Device
        from ipam.models import Service

        device = self.context.get("object")
        if not device:
            return ""

        # Get certificates directly assigned to the device
        device_ct = ContentType.objects.get_for_model(Device)
        direct_assignments = CertificateAssignment.objects.filter(
            assigned_object_type=device_ct,
            assigned_object_id=device.pk,
        ).select_related("certificate")

        # Get certificates assigned to services on this device
        # NetBox 4.5: Service uses GenericForeignKey 'parent'
        service_ct = ContentType.objects.get_for_model(Service)
        device_ct_for_service = ContentType.objects.get_for_model(Device)

        service_ids = Service.objects.filter(
            parent_object_type=device_ct_for_service,
            parent_object_id=device.pk,
        ).values_list("pk", flat=True)

        service_assignments = CertificateAssignment.objects.filter(
            assigned_object_type=service_ct,
            assigned_object_id__in=service_ids,
        ).select_related("certificate")

        # Combine and deduplicate
        all_assignments = list(direct_assignments) + list(service_assignments)

        if not all_assignments:
            return ""

        return self.render(
            "netbox_ssl/inc/certificate_panel.html",
            extra_context={"assignments": all_assignments},
        )


class VirtualMachineCertificates(PluginTemplateExtension):
    """Show certificates assigned to a VM and its Services."""

    models = ["virtualization.virtualmachine"]

    def right_page(self):
        from virtualization.models import VirtualMachine
        from ipam.models import Service

        vm = self.context.get("object")
        if not vm:
            return ""

        # Get certificates directly assigned to the VM
        vm_ct = ContentType.objects.get_for_model(VirtualMachine)
        direct_assignments = CertificateAssignment.objects.filter(
            assigned_object_type=vm_ct,
            assigned_object_id=vm.pk,
        ).select_related("certificate")

        # Get certificates assigned to services on this VM
        service_ct = ContentType.objects.get_for_model(Service)
        vm_ct_for_service = ContentType.objects.get_for_model(VirtualMachine)

        service_ids = Service.objects.filter(
            parent_object_type=vm_ct_for_service,
            parent_object_id=vm.pk,
        ).values_list("pk", flat=True)

        service_assignments = CertificateAssignment.objects.filter(
            assigned_object_type=service_ct,
            assigned_object_id__in=service_ids,
        ).select_related("certificate")

        # Combine
        all_assignments = list(direct_assignments) + list(service_assignments)

        if not all_assignments:
            return ""

        return self.render(
            "netbox_ssl/inc/certificate_panel.html",
            extra_context={"assignments": all_assignments},
        )


class ServiceCertificates(PluginTemplateExtension):
    """Show certificates assigned to a Service."""

    models = ["ipam.service"]

    def right_page(self):
        from ipam.models import Service

        service = self.context.get("object")
        if not service:
            return ""

        service_ct = ContentType.objects.get_for_model(Service)
        assignments = CertificateAssignment.objects.filter(
            assigned_object_type=service_ct,
            assigned_object_id=service.pk,
        ).select_related("certificate")

        if not assignments:
            return ""

        return self.render(
            "netbox_ssl/inc/certificate_panel.html",
            extra_context={"assignments": assignments},
        )


# List of template extensions to register
template_extensions = [
    DeviceCertificates,
    VirtualMachineCertificates,
    ServiceCertificates,
]
