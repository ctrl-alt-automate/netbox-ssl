"""
Forms for ExternalSource model.
"""

from django import forms
from django.utils.translation import gettext_lazy as _
from netbox.forms import NetBoxModelBulkEditForm, NetBoxModelFilterSetForm, NetBoxModelForm
from utilities.forms.fields import CommentField, TagFilterField
from utilities.forms.rendering import FieldSet

from ..models import (
    ExternalSource,
    ExternalSourceTypeChoices,
    SyncStatusChoices,
)


class ExternalSourceForm(NetBoxModelForm):
    """Form for creating/editing External Sources."""

    comments = CommentField()

    fieldsets = (
        FieldSet(
            "name",
            "source_type",
            "base_url",
            "enabled",
            "verify_ssl",
            name=_("Source"),
        ),
        FieldSet(
            "auth_method",
            "auth_credentials_reference",
            name=_("Authentication"),
        ),
        FieldSet(
            "sync_interval_minutes",
            "tenant",
            "field_mapping",
            name=_("Sync Configuration"),
        ),
        FieldSet(
            "tags",
            name=_("Tags"),
        ),
    )

    class Meta:
        model = ExternalSource
        fields = [
            "name",
            "source_type",
            "base_url",
            "auth_method",
            "auth_credentials_reference",
            "field_mapping",
            "sync_interval_minutes",
            "enabled",
            "tenant",
            "verify_ssl",
            "tags",
            "comments",
        ]
        widgets = {
            "auth_credentials_reference": forms.PasswordInput(
                attrs={"placeholder": "env:MY_API_TOKEN"},
            ),
        }


class ExternalSourceFilterForm(NetBoxModelFilterSetForm):
    """Filter form for External Source list view."""

    model = ExternalSource

    fieldsets = (
        FieldSet(
            "q",
            "filter_id",
            "tag",
        ),
        FieldSet(
            "source_type",
            "enabled",
            "sync_status",
            name=_("External Source"),
        ),
    )

    source_type = forms.MultipleChoiceField(
        choices=ExternalSourceTypeChoices,
        required=False,
        label=_("Source Type"),
    )
    enabled = forms.NullBooleanField(
        required=False,
        label=_("Enabled"),
        widget=forms.Select(
            choices=[
                ("", "---------"),
                ("true", "Yes"),
                ("false", "No"),
            ]
        ),
    )
    sync_status = forms.MultipleChoiceField(
        choices=SyncStatusChoices,
        required=False,
        label=_("Sync Status"),
    )
    tag = TagFilterField(model)


class ExternalSourceBulkEditForm(NetBoxModelBulkEditForm):
    """Bulk edit form for External Sources."""

    model = ExternalSource

    enabled = forms.NullBooleanField(
        required=False,
        label=_("Enabled"),
        widget=forms.Select(
            choices=[
                ("", "---------"),
                ("true", "Yes"),
                ("false", "No"),
            ]
        ),
    )
    sync_interval_minutes = forms.IntegerField(
        required=False,
        label=_("Sync Interval (minutes)"),
        min_value=0,
    )

    fieldsets = (
        FieldSet(
            "enabled",
            "sync_interval_minutes",
        ),
    )

    nullable_fields = []
