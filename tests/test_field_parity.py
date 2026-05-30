"""
Generic model<->form field-parity guard — generalizes issue #112.

#112 shipped because the certificate edit form declared ``comments =
CommentField()`` but the model (a ``NetBoxModel``, not ``PrimaryModel``) had no
``comments`` column. Django ModelForms allow *declared* (class-attribute)
fields that don't map to the model — they are simply dropped on save. So the
field rendered, accepted input, and silently lost it.

``test_comments_field.py`` covers the four models that had the bug by name.
This test generalizes the guard: for EVERY plugin ``ModelForm``, every declared
field must resolve to a real model field (or be an allow-listed virtual field).
The next phantom field on any model is then caught automatically.

Requires a real NetBox/Django environment; runs in the Docker integration job.
"""

import contextlib
import inspect
import os
import sys
from pathlib import Path

import pytest

_root = Path(__file__).parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

import importlib.util

try:
    _spec = importlib.util.find_spec("netbox")
    NETBOX_AVAILABLE = _spec is not None and _spec.origin is not None
except (ValueError, ModuleNotFoundError):
    NETBOX_AVAILABLE = False

if NETBOX_AVAILABLE:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "netbox.settings")
    import django

    with contextlib.suppress(Exception):
        django.setup()

requires_netbox = pytest.mark.skipif(
    not NETBOX_AVAILABLE,
    reason="NetBox not available - run these tests inside the Docker container",
)

# Declared form fields that legitimately do NOT map to a concrete model field.
# Keep this list short and documented — every entry is a deliberate exception,
# and the whole point of the test is that NEW unexplained entries are bugs.
ALLOWED_NON_MODEL_FORM_FIELDS = {
    "tags",  # NetBox TagField — virtual, persisted via the tagging framework, not a column
    "_init_time",  # injected by NetBox's NetBoxModelForm (concurrency/timing); not a model field
    "changelog_message",  # injected by NetBox's NetBoxModelForm (changelog note); not a model field
    # CertificateAssignmentForm's GenericForeignKey target selectors. These are
    # intentional virtual fields resolved to assigned_object_type/id in the
    # form's clean()/save(); they deliberately have no own column.
    "device",
    "virtual_machine",
    "service",
}


def _plugin_modelforms():
    from django.forms import ModelForm

    import netbox_ssl.forms as forms_mod

    return [
        cls
        for _, cls in inspect.getmembers(forms_mod, inspect.isclass)
        if issubclass(cls, ModelForm)
        and (cls.__module__ or "").startswith("netbox_ssl")
        and getattr(getattr(cls, "_meta", None), "model", None) is not None
    ]


@requires_netbox
def test_every_modelform_declared_field_backs_onto_a_model_field():
    """No plugin ModelForm may declare a field with no backing model column (#112)."""
    forms = _plugin_modelforms()
    assert forms, "no plugin ModelForms were discovered"

    phantom = []
    for form_cls in forms:
        model = form_cls._meta.model
        model_field_names = {f.name for f in model._meta.get_fields()}
        for field_name, field in form_cls.declared_fields.items():
            if field_name in model_field_names or field_name in ALLOWED_NON_MODEL_FORM_FIELDS:
                continue
            phantom.append(f"{form_cls.__name__}.{field_name} ({type(field).__name__})")

    assert not phantom, (
        "Form fields with no backing model column will be silently dropped on save (#112). "
        "Add the field to the model (+ migration) or to ALLOWED_NON_MODEL_FORM_FIELDS with a "
        "comment if it is a genuine virtual field. Offenders: " + "; ".join(phantom)
    )
