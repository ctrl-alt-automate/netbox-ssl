"""
Forms for Certificate model.

Includes the Smart Paste import form for PEM certificate parsing.
"""

from django import forms
from django.utils.translation import gettext_lazy as _

from netbox.forms import NetBoxModelForm, NetBoxModelFilterSetForm, NetBoxModelBulkEditForm
from tenancy.models import Tenant
from utilities.forms.fields import CommentField, DynamicModelChoiceField, TagFilterField
from utilities.forms.rendering import FieldSet

from ..models import Certificate, CertificateStatusChoices, CertificateAlgorithmChoices


class CertificateForm(NetBoxModelForm):
    """Form for creating/editing certificates manually."""

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
            name=_("Certificate"),
        ),
        FieldSet(
            "serial_number",
            "fingerprint_sha256",
            "issuer",
            name=_("Identity"),
        ),
        FieldSet(
            "valid_from",
            "valid_to",
            name=_("Validity"),
        ),
        FieldSet(
            "algorithm",
            "key_size",
            name=_("Key Information"),
        ),
        FieldSet(
            "private_key_location",
            name=_("Key Location"),
        ),
        FieldSet(
            "pem_content",
            "issuer_chain",
            name=_("Certificate Data"),
        ),
        FieldSet(
            "tags",
            name=_("Tags"),
        ),
    )

    class Meta:
        model = Certificate
        fields = [
            "common_name",
            "serial_number",
            "fingerprint_sha256",
            "issuer",
            "issuer_chain",
            "valid_from",
            "valid_to",
            "sans",
            "key_size",
            "algorithm",
            "status",
            "private_key_location",
            "tenant",
            "pem_content",
            "tags",
            "comments",
        ]
        widgets = {
            "valid_from": forms.DateTimeInput(
                attrs={"type": "datetime-local"},
            ),
            "valid_to": forms.DateTimeInput(
                attrs={"type": "datetime-local"},
            ),
            "pem_content": forms.Textarea(
                attrs={"rows": 10, "class": "font-monospace"},
            ),
            "issuer_chain": forms.Textarea(
                attrs={"rows": 10, "class": "font-monospace"},
            ),
        }


class CertificateImportForm(forms.Form):
    """
    Smart Paste import form for PEM certificates.

    This form handles the "paste & parse" workflow:
    1. User pastes PEM content
    2. Backend parses and extracts all fields
    3. Private keys are rejected for security
    """

    pem_content = forms.CharField(
        widget=forms.Textarea(
            attrs={
                "rows": 15,
                "class": "font-monospace",
                "placeholder": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
            }
        ),
        label=_("Certificate (PEM format)"),
        help_text=_(
            "Paste your certificate in PEM format. You may include the full "
            "chain (intermediates and root). Private keys will be rejected."
        ),
    )

    private_key_location = forms.CharField(
        max_length=512,
        required=False,
        label=_("Private Key Location"),
        help_text=_(
            "Optional hint for where the private key is stored "
            "(e.g., 'Vault: /secret/prod/web/'). Never paste actual keys!"
        ),
    )

    tenant = DynamicModelChoiceField(
        queryset=Tenant.objects.all(),
        required=False,
        label=_("Tenant"),
    )

    def clean_pem_content(self):
        """Validate PEM content and check for private keys."""
        from ..utils import CertificateParser, PrivateKeyDetectedError, CertificateParseError

        pem_content = self.cleaned_data["pem_content"]

        # Check for private keys
        if CertificateParser.contains_private_key(pem_content):
            raise forms.ValidationError(
                _("Private key detected! For security reasons, private keys "
                  "cannot be stored. Please remove the private key and try again.")
            )

        # Validate certificate can be parsed
        try:
            CertificateParser.parse(pem_content)
        except CertificateParseError as e:
            raise forms.ValidationError(str(e))

        return pem_content


class CertificateFilterForm(NetBoxModelFilterSetForm):
    """Filter form for certificate list view."""

    model = Certificate

    fieldsets = (
        FieldSet(
            "q",
            "filter_id",
            "tag",
        ),
        FieldSet(
            "common_name",
            "issuer",
            "status",
            name=_("Certificate"),
        ),
        FieldSet(
            "algorithm",
            "key_size",
            name=_("Key"),
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
    issuer = forms.CharField(
        required=False,
        label=_("Issuer"),
    )
    status = forms.MultipleChoiceField(
        choices=CertificateStatusChoices,
        required=False,
        label=_("Status"),
    )
    algorithm = forms.MultipleChoiceField(
        choices=CertificateAlgorithmChoices,
        required=False,
        label=_("Algorithm"),
    )
    key_size = forms.IntegerField(
        required=False,
        label=_("Key Size"),
    )
    tenant_id = DynamicModelChoiceField(
        queryset=Tenant.objects.all(),
        required=False,
        label=_("Tenant"),
    )
    tag = TagFilterField(model)


class CertificateBulkEditForm(NetBoxModelBulkEditForm):
    """Bulk edit form for certificates."""

    model = Certificate

    status = forms.ChoiceField(
        choices=CertificateStatusChoices,
        required=False,
        label=_("Status"),
    )
    tenant = DynamicModelChoiceField(
        queryset=Tenant.objects.all(),
        required=False,
        label=_("Tenant"),
    )
    private_key_location = forms.CharField(
        max_length=512,
        required=False,
        label=_("Private Key Location"),
    )

    fieldsets = (
        FieldSet(
            "status",
            "tenant",
            "private_key_location",
        ),
    )

    nullable_fields = ["tenant", "private_key_location"]
