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

    Supports assignment to Services, Devices, and VirtualMachines.
    Service is the recommended (most granular) assignment type.
    """

    certificate = DynamicModelChoiceField(
        queryset=Certificate.objects.all(),
        label=_("Certificate"),
    )

    # Target type selector
    assigned_object_type = ContentTypeChoiceField(
        queryset=ContentType.objects.filter(
            model__in=["service", "device", "virtualmachine"]
        ),
        label=_("Assignment Type"),
        help_text=_("Select the type of object to assign this certificate to."),
    )

    # Device selection (for filtering services or direct assignment)
    device = DynamicModelChoiceField(
        queryset=Device.objects.all(),
        required=False,
        label=_("Device"),
        help_text=_("Select a device (required for service assignment)"),
    )

    # VM selection (for filtering services or direct assignment)
    virtual_machine = DynamicModelChoiceField(
        queryset=VirtualMachine.objects.all(),
        required=False,
        label=_("Virtual Machine"),
        help_text=_("Select a VM (required for service assignment)"),
    )

    # Service selection (filtered by device/VM via HTMX)
    service = DynamicModelChoiceField(
        queryset=Service.objects.all(),
        required=False,
        label=_("Service"),
        help_text=_("Select a service (recommended for port-level granularity)"),
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
            "assigned_object_type",
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
            "assigned_object_type",
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
        """Validate and set the assigned object based on selections."""
        cleaned_data = super().clean()

        object_type = cleaned_data.get("assigned_object_type")
        if not object_type:
            raise forms.ValidationError(_("Please select an assignment type."))

        model_name = object_type.model

        # Determine the assigned object based on type
        if model_name == "service":
            service = cleaned_data.get("service")
            if not service:
                raise forms.ValidationError(
                    _("Please select a service for service-level assignment.")
                )
            self.instance.assigned_object_id = service.pk
            self.instance.assigned_object_type = object_type

        elif model_name == "device":
            device = cleaned_data.get("device")
            if not device:
                raise forms.ValidationError(
                    _("Please select a device for device-level assignment.")
                )
            self.instance.assigned_object_id = device.pk
            self.instance.assigned_object_type = object_type

        elif model_name == "virtualmachine":
            vm = cleaned_data.get("virtual_machine")
            if not vm:
                raise forms.ValidationError(
                    _("Please select a virtual machine for VM-level assignment.")
                )
            self.instance.assigned_object_id = vm.pk
            self.instance.assigned_object_type = object_type

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
