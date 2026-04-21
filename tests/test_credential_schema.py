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
        "django.db.models.functions",
        "django.utils",
        "django.utils.timezone",
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


def test_lemur_supports_bearer_only():
    from netbox_ssl.adapters.lemur import LemurAdapter

    assert LemurAdapter.SUPPORTED_AUTH_METHODS == ("bearer",)


def test_lemur_credential_schema_has_single_token_field():
    from netbox_ssl.adapters.lemur import LemurAdapter

    schema = LemurAdapter.credential_schema("bearer")
    assert set(schema.keys()) == {"token"}
    assert schema["token"].required is True
    assert schema["token"].secret is True
    assert schema["token"].label == "API Token"


def test_lemur_credential_schema_rejects_non_bearer():
    from netbox_ssl.adapters.lemur import LemurAdapter

    with pytest.raises(ValueError, match="does not support"):
        LemurAdapter.credential_schema("api_key")


def test_generic_rest_supports_bearer_and_api_key():
    from netbox_ssl.adapters.generic_rest import GenericRESTAdapter

    assert GenericRESTAdapter.SUPPORTED_AUTH_METHODS == ("bearer", "api_key")


def test_generic_rest_schema_is_single_token_for_both_methods():
    from netbox_ssl.adapters.generic_rest import GenericRESTAdapter

    for method in ("bearer", "api_key"):
        schema = GenericRESTAdapter.credential_schema(method)
        assert set(schema.keys()) == {"token"}
        assert schema["token"].required is True
        assert schema["token"].secret is True


def test_generic_rest_schema_rejects_cloud_methods():
    from netbox_ssl.adapters.generic_rest import GenericRESTAdapter

    for method in ("aws_explicit", "azure_managed_identity"):
        with pytest.raises(ValueError, match="does not support"):
            GenericRESTAdapter.credential_schema(method)


def test_base_adapter_resolve_credentials_returns_dict():
    """resolve_credentials must return dict[str, str] for multi-cred support."""
    import os
    from unittest.mock import MagicMock, patch

    from netbox_ssl.adapters.lemur import LemurAdapter

    source = MagicMock()
    source.auth_credentials = {"token": "env:LEMUR_TEST_TOKEN"}
    adapter = LemurAdapter(source)

    with patch.dict(os.environ, {"LEMUR_TEST_TOKEN": "t0ken"}):
        result = adapter.resolve_credentials()

    assert isinstance(result, dict)
    assert result == {"token": "t0ken"}


def test_get_headers_bearer_reads_token_from_dict():
    import os
    from unittest.mock import MagicMock, patch

    from netbox_ssl.adapters.lemur import LemurAdapter

    source = MagicMock()
    source.auth_credentials = {"token": "env:MY_TOKEN"}
    source.auth_method = "bearer"
    adapter = LemurAdapter(source)

    with patch.dict(os.environ, {"MY_TOKEN": "bearer_value"}):
        headers = adapter._get_headers()

    assert headers["Authorization"] == "Bearer bearer_value"
    assert headers["Accept"] == "application/json"


def test_get_headers_api_key_reads_token_from_dict():
    import os
    from unittest.mock import MagicMock, patch

    from netbox_ssl.adapters.generic_rest import GenericRESTAdapter

    source = MagicMock()
    source.auth_credentials = {"token": "env:MY_KEY"}
    source.auth_method = "api_key"
    adapter = GenericRESTAdapter(source)

    with patch.dict(os.environ, {"MY_KEY": "apikey_value"}):
        headers = adapter._get_headers()

    assert headers["X-API-Key"] == "apikey_value"


def test_get_adapter_class_returns_correct_class():
    from netbox_ssl.adapters import get_adapter_class
    from netbox_ssl.adapters.generic_rest import GenericRESTAdapter
    from netbox_ssl.adapters.lemur import LemurAdapter

    assert get_adapter_class("lemur") is LemurAdapter
    assert get_adapter_class("generic_rest") is GenericRESTAdapter


def test_get_adapter_class_raises_for_unknown():
    from netbox_ssl.adapters import get_adapter_class

    with pytest.raises(KeyError, match="No adapter registered"):
        get_adapter_class("nonexistent")


def test_get_supported_auth_methods():
    from netbox_ssl.adapters import get_supported_auth_methods

    assert get_supported_auth_methods("lemur") == ("bearer",)
    assert get_supported_auth_methods("generic_rest") == ("bearer", "api_key")


def test_get_credential_schema_for_lemur():
    from netbox_ssl.adapters import get_credential_schema

    schema = get_credential_schema("lemur", "bearer")
    assert "token" in schema
    assert schema["token"].required is True


def test_base_adapter_default_implicit_auth_methods_is_empty():
    from netbox_ssl.adapters.base import BaseAdapter

    assert BaseAdapter.IMPLICIT_AUTH_METHODS == ()


def test_lemur_does_not_declare_implicit_auth():
    from netbox_ssl.adapters.lemur import LemurAdapter

    assert LemurAdapter.IMPLICIT_AUTH_METHODS == ()


def test_generic_rest_does_not_declare_implicit_auth():
    from netbox_ssl.adapters.generic_rest import GenericRESTAdapter

    assert GenericRESTAdapter.IMPLICIT_AUTH_METHODS == ()
