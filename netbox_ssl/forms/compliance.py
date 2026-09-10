"""
Forms for CompliancePolicy and ComplianceCheck models.
"""

from django import forms
from django.utils.translation import gettext_lazy as _
from netbox.forms import NetBoxModelFilterSetForm, NetBoxModelForm
from tenancy.models import Tenant
from utilities.forms.fields import DynamicModelChoiceField, DynamicModelMultipleChoiceField, TagFilterField
from utilities.forms.rendering import FieldSet

from ..models import (
    Certificate,
    ComplianceCheck,
    CompliancePolicy,
    CompliancePolicyTypeChoices,
    ComplianceResultChoices,
    ComplianceSeverityChoices,
)

# Shown under the parameters field so operators do not have to consult the docs
# to learn the JSON shape each policy type expects.
_PARAMETER_EXAMPLES = """Examples by policy type:
min_key_size: {"min_bits": 2048}
algorithm_allowed: {"algorithms": ["rsa", "ecdsa"]}
algorithm_forbidden: {"algorithms": ["rsa"]}
max_validity_days: {"max_days": 397}
expiry_warning: {"warning_days": 30}
issuer_allowed: {"issuers": ["DigiCert", "Let's Encrypt"]}
issuer_forbidden: {"issuers": ["Unknown CA"]}"""


class CompliancePolicyForm(NetBoxModelForm):
    """Form for creating and editing compliance policies."""

    tenant = DynamicModelChoiceField(
        queryset=Tenant.objects.all(),
        required=False,
        label=_("Tenant"),
        help_text=_("Limit the policy to one tenant. Leave empty to apply globally."),
    )
    parameters = forms.JSONField(
        required=False,
        label=_("Parameters"),
        help_text=_PARAMETER_EXAMPLES,
        widget=forms.Textarea(attrs={"rows": 6, "class": "font-monospace"}),
    )

    fieldsets = (
        FieldSet("name", "description", "policy_type", "severity", "enabled", name=_("Policy")),
        FieldSet("parameters", name=_("Parameters")),
        FieldSet("tenant", "tag_filter", name=_("Scope")),
        FieldSet("tags", name=_("Tags")),
    )

    class Meta:
        model = CompliancePolicy
        fields = (
            "name",
            "description",
            "policy_type",
            "severity",
            "enabled",
            "parameters",
            "tenant",
            "tag_filter",
            "tags",
        )

    def clean_parameters(self):
        """Default to an empty object and reject anything that is not a mapping.

        ``parameters`` is consumed as ``policy.parameters.get(key)`` by
        ComplianceChecker, so a list or scalar would raise at check time rather
        than at entry time.
        """
        parameters = self.cleaned_data.get("parameters")
        if parameters in (None, ""):
            return {}
        if not isinstance(parameters, dict):
            raise forms.ValidationError(_('Parameters must be a JSON object, e.g. {"min_bits": 2048}.'))
        return parameters


class CompliancePolicyFilterForm(NetBoxModelFilterSetForm):
    """Filter form for the compliance policy list."""

    model = CompliancePolicy

    policy_type = forms.MultipleChoiceField(
        choices=CompliancePolicyTypeChoices,
        required=False,
        label=_("Policy type"),
    )
    severity = forms.MultipleChoiceField(
        choices=ComplianceSeverityChoices,
        required=False,
        label=_("Severity"),
    )
    enabled = forms.NullBooleanField(
        required=False,
        label=_("Enabled"),
        widget=forms.Select(choices=[("", "---------"), (True, _("Yes")), (False, _("No"))]),
    )
    tenant_id = DynamicModelMultipleChoiceField(
        queryset=Tenant.objects.all(),
        required=False,
        label=_("Tenant"),
    )
    tag = TagFilterField(model)


class ComplianceCheckFilterForm(NetBoxModelFilterSetForm):
    """Filter form for the compliance check results list."""

    model = ComplianceCheck

    certificate_id = DynamicModelMultipleChoiceField(
        queryset=Certificate.objects.all(),
        required=False,
        label=_("Certificate"),
    )
    policy_id = DynamicModelMultipleChoiceField(
        queryset=CompliancePolicy.objects.all(),
        required=False,
        label=_("Policy"),
    )
    result = forms.MultipleChoiceField(
        choices=ComplianceResultChoices,
        required=False,
        label=_("Result"),
    )
    tag = TagFilterField(model)
