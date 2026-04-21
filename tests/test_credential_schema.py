"""Unit tests for CredentialField dataclass and per-adapter credential schemas."""

import importlib.util
import sys
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Mock Django/NetBox before importing plugin code
# ---------------------------------------------------------------------------
try:
    _spec = importlib.util.find_spec("netbox")
    _NETBOX_AVAILABLE = _spec is not None and _spec.origin is not None
except (ValueError, ModuleNotFoundError):
    _NETBOX_AVAILABLE = False

if not _NETBOX_AVAILABLE:
    for _mod in [
        "django",
        "django.conf",
        "django.db",
        "django.db.models",
        "django.utils",
        "django.utils.translation",
        "netbox",
        "netbox.plugins",
    ]:
        sys.modules.setdefault(_mod, MagicMock())

from netbox_ssl.adapters.base import CredentialField  # noqa: E402

pytestmark = pytest.mark.unit


def test_credential_field_is_frozen():
    """Assignment to a frozen-dataclass field must raise with the dataclasses
    message, narrowing the catch so an accidental AttributeError elsewhere
    cannot silently pass this test."""
    field = CredentialField(required=True, label="API Token")
    with pytest.raises(Exception, match="cannot assign to field"):
        field.required = False  # type: ignore[misc]


def test_credential_field_defaults():
    field = CredentialField()
    assert field.required is True
    assert field.label == ""
    assert field.secret is False
    assert field.help_text == ""


def test_credential_field_all_attributes():
    field = CredentialField(
        required=False,
        label="Session Token",
        secret=True,
        help_text="Only for temporary credentials",
    )
    assert field.required is False
    assert field.label == "Session Token"
    assert field.secret is True
    assert field.help_text == "Only for temporary credentials"
