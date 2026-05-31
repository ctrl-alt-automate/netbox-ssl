"""
Form for the URL Certificate Import feature (#106).

A plain ``forms.Form`` (not a NetBoxModelForm) for the upload step of the
CSV-driven URL import flow. The heavy lifting (parsing, preview, scanning) lives
in the view + scan script; this form just collects the CSV (file or pasted text)
and an optional default tenant.
"""

from django import forms
from django.utils.translation import gettext_lazy as _
from tenancy.models import Tenant
from utilities.forms.fields import DynamicModelChoiceField


class UrlImportForm(forms.Form):
    """Upload or paste a CSV of URLs to scrape via TLS handshake."""

    csv_file = forms.FileField(
        required=False,
        label=_("CSV file"),
        help_text=_(
            "Upload a .csv file of URLs to scan. Columns: url (required), "
            "assigned_device, assigned_vm, assigned_service, tenant, verify_chain, sni."
        ),
        widget=forms.ClearableFileInput(attrs={"accept": ".csv,.txt"}),
    )

    csv_text = forms.CharField(
        required=False,
        label=_("Or paste CSV"),
        widget=forms.Textarea(
            attrs={
                "rows": 10,
                "class": "font-monospace",
                "placeholder": "url,assigned_device,tenant,verify_chain\nhttps://web.internal.example.com:8443,web01,acme,true",
            }
        ),
        help_text=_("Paste CSV rows directly instead of uploading a file."),
    )

    default_tenant = DynamicModelChoiceField(
        queryset=Tenant.objects.all(),
        required=False,
        label=_("Default tenant"),
        help_text=_("Applied to rows that do not specify their own tenant column."),
    )

    def clean(self):
        cleaned = super().clean()
        if not cleaned.get("csv_file") and not cleaned.get("csv_text", "").strip():
            raise forms.ValidationError(_("Provide a CSV file or paste CSV text."))
        return cleaned
