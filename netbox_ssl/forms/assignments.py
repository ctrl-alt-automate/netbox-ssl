"""
Forms for CertificateAssignment model.

Implements the two-step assignment workflow:
1. Select Device or VM
2. Select Service (filtered by selected device/VM)
"""

from django import forms
from django.contrib.contenttypes.models import ContentType
from django.utils.translation import gettext_lazy as _

from dcim.models import Device
from ipam.models import Service
from virtualization.models import VirtualMachine

from netbox.forms import NetBoxModelForm, NetBoxModelFilterSetForm
from utilities.forms.fields import DynamicModelChoiceField, ContentTypeChoiceField
from utilities.forms.rendering import FieldSet

from ..models import Certificate, CertificateAssignment


class CertificateAssignmentForm(NetBoxModelForm):
    """
    Form for creating/editing certificate assignments.

    Simplified two-step workflow:
    1. Select Device or VM (services are automatically shown)
    2. Select Service for port-level assignment, or leave empty for device/VM-level

    Assignment type is automatically determined based on selection.
    """

    certificate = DynamicModelChoiceField(
        queryset=Certificate.objects.all(),
        label=_("Certificate"),
    )

    # Device selection - services are automatically filtered
    device = DynamicModelChoiceField(
        queryset=Device.objects.all(),
        required=False,
        label=_("Device"),
        help_text=_("Select a device to see its services"),
        query_params={
            "tenant_id": "$tenant",
        },
    )

    # VM selection - services are automatically filtered
    virtual_machine = DynamicModelChoiceField(
        queryset=VirtualMachine.objects.all(),
        required=False,
        label=_("Virtual Machine"),
        help_text=_("Select a VM to see its services"),
        query_params={
            "tenant_id": "$tenant",
        },
    )

    # Service selection (filtered by device/VM via HTMX)
    service = DynamicModelChoiceField(
        queryset=Service.objects.all(),
        required=False,
        label=_("Service"),
        help_text=_("Select a service for port-level assignment (recommended), or leave empty for device/VM-level"),
        query_params={
            "device_id": "$device",
            "virtual_machine_id": "$virtual_machine",
        },
    )

    fieldsets = (
        FieldSet(
            "certificate",
            name=_("Certificate"),
        ),
        FieldSet(
            "device",
            "virtual_machine",
            "service",
            name=_("Assignment Target"),
        ),
        FieldSet(
            "is_primary",
            "notes",
            name=_("Options"),
        ),
        FieldSet(
            "tags",
            name=_("Tags"),
        ),
    )

    class Meta:
        model = CertificateAssignment
        fields = [
            "certificate",
            "is_primary",
            "notes",
            "tags",
        ]
        widgets = {
            "notes": forms.Textarea(attrs={"rows": 3}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # If editing, populate the device/VM/service fields
        if self.instance.pk and self.instance.assigned_object:
            obj = self.instance.assigned_object
            model_name = self.instance.assigned_object_type.model

            if model_name == "service":
                self.fields["service"].initial = obj
                if obj.device:
                    self.fields["device"].initial = obj.device
                elif obj.virtual_machine:
                    self.fields["virtual_machine"].initial = obj.virtual_machine
            elif model_name == "device":
                self.fields["device"].initial = obj
            elif model_name == "virtualmachine":
                self.fields["virtual_machine"].initial = obj

    def clean(self):
        """Validate and automatically determine assignment type based on selections."""
        cleaned_data = super().clean()

        service = cleaned_data.get("service")
        device = cleaned_data.get("device")
        vm = cleaned_data.get("virtual_machine")

        # Determine assignment type automatically based on what's selected
        if service:
            # Service-level assignment (most specific, recommended)
            content_type = ContentType.objects.get_for_model(Service)
            self.instance.assigned_object_id = service.pk
            self.instance.assigned_object_type = content_type

        elif device:
            # Device-level assignment
            content_type = ContentType.objects.get_for_model(Device)
            self.instance.assigned_object_id = device.pk
            self.instance.assigned_object_type = content_type

        elif vm:
            # VM-level assignment
            content_type = ContentType.objects.get_for_model(VirtualMachine)
            self.instance.assigned_object_id = vm.pk
            self.instance.assigned_object_type = content_type

        else:
            raise forms.ValidationError(
                _("Please select a Device, Virtual Machine, or Service to assign the certificate to.")
            )

        return cleaned_data


class CertificateAssignmentFilterForm(NetBoxModelFilterSetForm):
    """Filter form for certificate assignment list view."""

    model = CertificateAssignment

    fieldsets = (
        FieldSet(
            "q",
            "filter_id",
            "tag",
        ),
        FieldSet(
            "certificate_id",
            "assigned_object_type_id",
            "is_primary",
            name=_("Assignment"),
        ),
    )

    certificate_id = DynamicModelChoiceField(
        queryset=Certificate.objects.all(),
        required=False,
        label=_("Certificate"),
    )
    assigned_object_type_id = ContentTypeChoiceField(
        queryset=ContentType.objects.filter(
            model__in=["service", "device", "virtualmachine"]
        ),
        required=False,
        label=_("Object Type"),
    )
    is_primary = forms.NullBooleanField(
        required=False,
        label=_("Is Primary"),
        widget=forms.Select(
            choices=[
                ("", "---------"),
                ("true", _("Yes")),
                ("false", _("No")),
            ]
        ),
    )
