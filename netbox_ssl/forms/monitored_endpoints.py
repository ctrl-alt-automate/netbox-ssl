"""
Forms for MonitoredEndpoint model.
"""

from dcim.models import Device
from django import forms
from django.contrib.contenttypes.models import ContentType
from django.utils.translation import gettext_lazy as _
from ipam.models import Service
from netbox.forms import NetBoxModelFilterSetForm, NetBoxModelForm
from utilities.forms.fields import DynamicModelChoiceField, TagFilterField
from utilities.forms.rendering import FieldSet
from virtualization.models import VirtualMachine

from ..models import MonitoredEndpoint, MonitoredEndpointStatusChoices


class MonitoredEndpointForm(NetBoxModelForm):
    """Form for creating/editing Monitored Endpoints."""

    # Device selection
    device = DynamicModelChoiceField(
        queryset=Device.objects.all(),
        required=False,
        label=_("Device"),
        help_text=_("Select a device to see its services"),
    )

    # VM selection
    virtual_machine = DynamicModelChoiceField(
        queryset=VirtualMachine.objects.all(),
        required=False,
        label=_("Virtual Machine"),
        help_text=_("Select a VM to see its services"),
    )

    # Service selection
    service = DynamicModelChoiceField(
        queryset=Service.objects.all(),
        required=False,
        label=_("Service"),
        help_text=_("Select a service for port-level assignment (optional)"),
        query_params={
            "device_id": "$device",
            "virtual_machine_id": "$virtual_machine",
        },
    )

    fieldsets = (
        FieldSet(
            "name",
            "url",
            "sni",
            name=_("Endpoint"),
        ),
        FieldSet(
            "device",
            "virtual_machine",
            "service",
            name=_("Assignment Target"),
        ),
        FieldSet(
            "certificate",
            "tenant",
            name=_("Links"),
        ),
        FieldSet(
            "tags",
            name=_("Tags"),
        ),
    )

    class Meta:
        model = MonitoredEndpoint
        fields = [
            "name",
            "url",
            "sni",
            "certificate",
            "tenant",
            "tags",
        ]
        widgets = {
            "url": forms.TextInput(attrs={"placeholder": "https://host:443"}),
            "sni": forms.TextInput(attrs={"placeholder": "Optional SNI override"}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # If editing, populate the device/VM/service fields from the GenericFK.
        if self.instance.pk and self.instance.assigned_object:
            obj = self.instance.assigned_object
            model_name = self.instance.assigned_object_type.model

            if model_name == "service":
                self.fields["service"].initial = obj
                if hasattr(obj, "parent") and obj.parent:
                    parent = obj.parent
                    if hasattr(parent, "_meta"):
                        if parent._meta.model_name == "device":
                            self.fields["device"].initial = parent
                        elif parent._meta.model_name == "virtualmachine":
                            self.fields["virtual_machine"].initial = parent
            elif model_name == "device":
                self.fields["device"].initial = obj
            elif model_name == "virtualmachine":
                self.fields["virtual_machine"].initial = obj

    def clean_url(self):
        """Reject non-HTTPS URLs at form validation time (XSS / javascript: URI defence)."""
        url = self.cleaned_data.get("url", "")
        if not url.lower().startswith("https://"):
            raise forms.ValidationError(_("Only HTTPS URLs are allowed (must start with https://)."))
        return url

    def save(self, commit=True):
        """Save the endpoint, resolving the GenericFK from device/vm/service fields."""
        instance = super().save(commit=False)

        service = self.cleaned_data.get("service")
        device = self.cleaned_data.get("device")
        vm = self.cleaned_data.get("virtual_machine")

        if service:
            instance.assigned_object_type = ContentType.objects.get_for_model(Service)
            instance.assigned_object_id = service.pk
        elif device:
            instance.assigned_object_type = ContentType.objects.get_for_model(Device)
            instance.assigned_object_id = device.pk
        elif vm:
            instance.assigned_object_type = ContentType.objects.get_for_model(VirtualMachine)
            instance.assigned_object_id = vm.pk
        # else: keep existing assigned_object if not changed

        if commit:
            instance.save()
            self.save_m2m()

        return instance


class MonitoredEndpointFilterForm(NetBoxModelFilterSetForm):
    """Filter form for Monitored Endpoint list view."""

    model = MonitoredEndpoint

    fieldsets = (
        FieldSet(
            "q",
            "filter_id",
            "tag",
        ),
        FieldSet(
            "status",
            name=_("Monitored Endpoint"),
        ),
    )

    status = forms.MultipleChoiceField(
        choices=MonitoredEndpointStatusChoices,
        required=False,
        label=_("Status"),
    )
    tag = TagFilterField(model)


class MonitoredEndpointImportForm(forms.Form):
    """Form for bulk-importing Monitored Endpoints from a CSV of URLs."""

    csv_text = forms.CharField(
        label=_("CSV Data"),
        widget=forms.Textarea(
            attrs={
                "rows": 20,
                "class": "font-monospace",
                "placeholder": "url,name,sni\nhttps://host1.example.com,,\nhttps://host2.example.com,,",
            }
        ),
        required=False,
        help_text=_(
            "Paste CSV rows with a required 'url' column. "
            "Optional columns: name, sni, tenant, assigned_device, assigned_vm, assigned_service."
        ),
    )
    csv_file = forms.FileField(
        label=_("CSV File"),
        required=False,
        help_text=_("Upload a CSV file instead of pasting."),
    )

    def clean(self):
        cleaned = super().clean()
        if not cleaned.get("csv_text") and not cleaned.get("csv_file"):
            raise forms.ValidationError(_("Provide either pasted CSV data or upload a CSV file."))
        return cleaned
