"""
Regression tests for the ``comments`` field — issue #112.

The edit forms for Certificate, CertificateAuthority, CertificateSigningRequest
and ExternalSource declared ``comments = CommentField()`` and listed
``"comments"`` in their fieldsets, but the models inherit ``NetBoxModel`` —
which (unlike ``PrimaryModel``) does NOT provide a ``comments`` column. So the
field rendered and accepted input, but the value was silently discarded on
save ("comments are not retained after save").

These tests assert the field now exists on every affected model, that each
form's ``comments`` maps onto a real model field (so it persists), and that the
API serializers expose it. They require a real NetBox/Django environment and
run inside the Docker integration job; they skip elsewhere.
"""

import contextlib
import os
import sys
from pathlib import Path

import pytest

_project_root = Path(__file__).parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

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

# Model import path, form class name, serializer class name for each affected model.
_AFFECTED = [
    ("Certificate", "CertificateForm", "CertificateSerializer"),
    ("CertificateAuthority", "CertificateAuthorityForm", "CertificateAuthoritySerializer"),
    ("CertificateSigningRequest", "CertificateSigningRequestForm", "CertificateSigningRequestSerializer"),
    ("ExternalSource", "ExternalSourceForm", "ExternalSourceSerializer"),
]


@requires_netbox
@pytest.mark.parametrize("model_name", [m for m, _, _ in _AFFECTED])
def test_model_has_comments_field(model_name):
    """Every affected model must define a real ``comments`` column (#112)."""
    import netbox_ssl.models as models_mod

    model = getattr(models_mod, model_name)
    field_names = {f.name for f in model._meta.get_fields()}
    assert "comments" in field_names, f"{model_name} is missing a 'comments' model field (#112)"


@pytest.mark.django_db
@requires_netbox
@pytest.mark.parametrize("model_name,form_name", [(m, f) for m, f, _ in _AFFECTED])
def test_form_comments_maps_to_model(model_name, form_name):
    """The form's ``comments`` field must map onto a model field so it persists.

    This is the exact #112 failure mode: ``comments`` was present in the form
    but absent from the model, so it never saved.
    """
    import netbox_ssl.forms as forms_mod

    form_cls = getattr(forms_mod, form_name)
    form = form_cls()
    assert "comments" in form.fields, f"{form_name} does not expose a comments field"
    model_field_names = {f.name for f in form._meta.model._meta.get_fields()}
    assert "comments" in model_field_names, (
        f"{form_name}.comments has no backing model field — it will not persist (#112)"
    )


@requires_netbox
@pytest.mark.parametrize("serializer_name", [s for _, _, s in _AFFECTED])
def test_serializer_exposes_comments(serializer_name):
    """The REST API serializers must expose ``comments`` for read/write parity."""
    import netbox_ssl.api.serializers as serializers_mod

    serializer_cls = getattr(serializers_mod, serializer_name)
    assert "comments" in serializer_cls().fields, f"{serializer_name} does not expose 'comments'"
