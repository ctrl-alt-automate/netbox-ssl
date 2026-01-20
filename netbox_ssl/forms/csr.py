"""
Forms for CertificateSigningRequest model.
"""

from django import forms
from django.utils.translation import gettext_lazy as _
from netbox.forms import NetBoxModelBulkEditForm, NetBoxModelFilterSetForm, NetBoxModelForm
from tenancy.models import Tenant
from utilities.forms.fields import CommentField, DynamicModelChoiceField, TagFilterField
from utilities.forms.rendering import FieldSet

from ..models import CertificateSigningRequest, CSRStatusChoices
from ..utils import CSRParseError, CSRParser


class CertificateSigningRequestForm(NetBoxModelForm):
    """Form for creating/editing CSRs manually."""

    tenant = DynamicModelChoiceField(
        queryset=Tenant.objects.all(),
        required=False,
    )
    comments = CommentField()

    fieldsets = (
        FieldSet(
            "common_name",
            "status",
            "tenant",
            name=_("CSR"),
        ),
        FieldSet(
            "organization",
            "organizational_unit",
            "locality",
            "state",
            "country",
            name=_("Subject"),
        ),
        FieldSet(
            "algorithm",
            "key_size",
            name=_("Key Information"),
        ),
        FieldSet(
            "requested_by",
            "target_ca",
            name=_("Request Details"),
        ),
        FieldSet(
            "pem_content",
            name=_("CSR Data"),
        ),
        FieldSet(
            "notes",
            "tags",
            name=_("Additional"),
        ),
    )

    class Meta:
        model = CertificateSigningRequest
        fields = [
            "common_name",
            "organization",
            "organizational_unit",
            "locality",
            "state",
            "country",
            "sans",
            "algorithm",
            "key_size",
            "fingerprint_sha256",
            "pem_content",
            "status",
            "requested_by",
            "target_ca",
            "notes",
            "tenant",
            "tags",
            "comments",
        ]
        widgets = {
            "pem_content": forms.Textarea(
                attrs={"rows": 10, "class": "font-monospace"},
            ),
            "notes": forms.Textarea(
                attrs={"rows": 5},
            ),
        }


class CSRImportForm(forms.Form):
    """
    Import form for PEM CSRs.

    This form handles the "paste & parse" workflow for CSRs.
    """

    pem_content = forms.CharField(
        widget=forms.Textarea(
            attrs={
                "rows": 15,
                "class": "font-monospace",
                "placeholder": "-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----",
            }
        ),
        label=_("CSR (PEM format)"),
        help_text=_("Paste your Certificate Signing Request in PEM format."),
    )

    requested_by = forms.CharField(
        max_length=255,
        required=False,
        label=_("Requested By"),
        help_text=_("Person, team, or system that requested this certificate."),
    )

    target_ca = forms.CharField(
        max_length=255,
        required=False,
        label=_("Target CA"),
        help_text=_("Intended Certificate Authority for signing."),
    )

    tenant = DynamicModelChoiceField(
        queryset=Tenant.objects.all(),
        required=False,
        label=_("Tenant"),
    )

    def clean_pem_content(self):
        """Validate PEM content."""
        pem_content = self.cleaned_data["pem_content"]

        try:
            CSRParser.parse(pem_content)
        except CSRParseError as e:
            raise forms.ValidationError(str(e)) from e

        return pem_content


class CertificateSigningRequestFilterForm(NetBoxModelFilterSetForm):
    """Filter form for CSR list view."""

    model = CertificateSigningRequest

    fieldsets = (
        FieldSet(
            "q",
            "filter_id",
            "tag",
        ),
        FieldSet(
            "common_name",
            "organization",
            "status",
            name=_("CSR"),
        ),
        FieldSet(
            "requested_by",
            "target_ca",
            name=_("Request Details"),
        ),
        FieldSet(
            "tenant_id",
            name=_("Tenant"),
        ),
    )

    common_name = forms.CharField(
        required=False,
        label=_("Common Name"),
    )
    organization = forms.CharField(
        required=False,
        label=_("Organization"),
    )
    status = forms.MultipleChoiceField(
        choices=CSRStatusChoices,
        required=False,
        label=_("Status"),
    )
    requested_by = forms.CharField(
        required=False,
        label=_("Requested By"),
    )
    target_ca = forms.CharField(
        required=False,
        label=_("Target CA"),
    )
    tenant_id = DynamicModelChoiceField(
        queryset=Tenant.objects.all(),
        required=False,
        label=_("Tenant"),
    )
    tag = TagFilterField(model)


class CertificateSigningRequestBulkEditForm(NetBoxModelBulkEditForm):
    """Bulk edit form for CSRs."""

    model = CertificateSigningRequest

    status = forms.ChoiceField(
        choices=CSRStatusChoices,
        required=False,
        label=_("Status"),
    )
    tenant = DynamicModelChoiceField(
        queryset=Tenant.objects.all(),
        required=False,
        label=_("Tenant"),
    )
    target_ca = forms.CharField(
        max_length=255,
        required=False,
        label=_("Target CA"),
    )

    fieldsets = (
        FieldSet(
            "status",
            "tenant",
            "target_ca",
        ),
    )

    nullable_fields = ["tenant", "target_ca", "requested_by"]
