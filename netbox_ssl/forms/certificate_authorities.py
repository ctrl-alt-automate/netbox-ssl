"""
Forms for CertificateAuthority model.
"""

from django import forms
from django.utils.translation import gettext_lazy as _
from netbox.forms import NetBoxModelBulkEditForm, NetBoxModelFilterSetForm, NetBoxModelForm
from utilities.forms.fields import CommentField, TagFilterField
from utilities.forms.rendering import FieldSet

from ..models import CATypeChoices, CertificateAuthority


class CertificateAuthorityForm(NetBoxModelForm):
    """Form for creating/editing Certificate Authorities."""

    comments = CommentField()

    fieldsets = (
        FieldSet(
            "name",
            "type",
            "is_approved",
            name=_("Certificate Authority"),
        ),
        FieldSet(
            "description",
            name=_("Description"),
        ),
        FieldSet(
            "issuer_pattern",
            name=_("Auto-Detection"),
        ),
        FieldSet(
            "website_url",
            "portal_url",
            "contact_email",
            name=_("Contact Information"),
        ),
        FieldSet(
            "tags",
            name=_("Tags"),
        ),
    )

    class Meta:
        model = CertificateAuthority
        fields = [
            "name",
            "type",
            "description",
            "issuer_pattern",
            "website_url",
            "portal_url",
            "contact_email",
            "is_approved",
            "tags",
            "comments",
        ]
        widgets = {
            "description": forms.Textarea(
                attrs={"rows": 5},
            ),
        }


class CertificateAuthorityFilterForm(NetBoxModelFilterSetForm):
    """Filter form for Certificate Authority list view."""

    model = CertificateAuthority

    fieldsets = (
        FieldSet(
            "q",
            "filter_id",
            "tag",
        ),
        FieldSet(
            "name",
            "type",
            "is_approved",
            name=_("Certificate Authority"),
        ),
    )

    name = forms.CharField(
        required=False,
        label=_("Name"),
    )
    type = forms.MultipleChoiceField(
        choices=CATypeChoices,
        required=False,
        label=_("Type"),
    )
    is_approved = forms.NullBooleanField(
        required=False,
        label=_("Is Approved"),
        widget=forms.Select(
            choices=[
                ("", "---------"),
                ("true", "Yes"),
                ("false", "No"),
            ]
        ),
    )
    tag = TagFilterField(model)


class CertificateAuthorityBulkEditForm(NetBoxModelBulkEditForm):
    """Bulk edit form for Certificate Authorities."""

    model = CertificateAuthority

    type = forms.ChoiceField(
        choices=CATypeChoices,
        required=False,
        label=_("Type"),
    )
    is_approved = forms.NullBooleanField(
        required=False,
        label=_("Is Approved"),
        widget=forms.Select(
            choices=[
                ("", "---------"),
                ("true", "Yes"),
                ("false", "No"),
            ]
        ),
    )
    contact_email = forms.EmailField(
        required=False,
        label=_("Contact Email"),
    )

    fieldsets = (
        FieldSet(
            "type",
            "is_approved",
            "contact_email",
        ),
    )

    nullable_fields = ["contact_email", "website_url", "portal_url"]
