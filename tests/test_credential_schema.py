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


def test_prohibited_sync_fields_includes_cloud_aliases():
    """v1.1 extends the safe-list with AWS/Azure key-material aliases."""
    from netbox_ssl.adapters.base import PROHIBITED_SYNC_FIELDS

    # Pre-existing entries — must stay.
    assert "private_key" in PROHIBITED_SYNC_FIELDS
    assert "key_material" in PROHIBITED_SYNC_FIELDS
    assert "p12" in PROHIBITED_SYNC_FIELDS
    assert "pfx" in PROHIBITED_SYNC_FIELDS
    assert "pkcs12" in PROHIBITED_SYNC_FIELDS

    # v1.1 additions — Azure Key Vault + AWS ACM aliases.
    assert "pem_bundle" in PROHIBITED_SYNC_FIELDS
    assert "secret_value" in PROHIBITED_SYNC_FIELDS
    assert "key" in PROHIBITED_SYNC_FIELDS


def test_base_adapter_has_empty_supported_auth_methods():
    from netbox_ssl.adapters.base import BaseAdapter

    assert BaseAdapter.SUPPORTED_AUTH_METHODS == ()


def test_base_adapter_default_requires_base_url():
    from netbox_ssl.adapters.base import BaseAdapter

    assert BaseAdapter.REQUIRES_BASE_URL is True
    assert BaseAdapter.REQUIRES_REGION is False


def test_base_adapter_credential_schema_rejects_unknown_auth_method():
    from netbox_ssl.adapters.base import BaseAdapter

    with pytest.raises(ValueError, match="does not support"):
        BaseAdapter.credential_schema("anything")
