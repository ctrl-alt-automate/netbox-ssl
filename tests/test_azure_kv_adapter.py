"""Unit tests for AzureKvAdapter (#101). The Azure SDK is mocked throughout."""

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.unit

_project_root = Path(__file__).parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

_tests_dir = Path(__file__).parent
if str(_tests_dir) not in sys.path:
    sys.path.insert(0, str(_tests_dir))

try:
    _spec = importlib.util.find_spec("netbox")
    _NETBOX_AVAILABLE = _spec is not None and _spec.origin is not None
except (ValueError, ModuleNotFoundError):
    _NETBOX_AVAILABLE = False

if not _NETBOX_AVAILABLE and "netbox" not in sys.modules:
    sys.modules["netbox"] = MagicMock()
    sys.modules["netbox.plugins"] = MagicMock()


class TestAdapterShape:
    def test_adapter_class_exists(self):
        from netbox_ssl.adapters.azure_kv import AzureKvAdapter

        assert AzureKvAdapter.__name__ == "AzureKvAdapter"

    def test_declares_both_auth_methods_implicit_first(self):
        from netbox_ssl.adapters.azure_kv import AzureKvAdapter

        assert AzureKvAdapter.SUPPORTED_AUTH_METHODS == (
            "azure_managed_identity",
            "azure_explicit",
        )
        assert AzureKvAdapter.IMPLICIT_AUTH_METHODS == ("azure_managed_identity",)

    def test_requires_a_vault_url_not_a_region(self):
        from netbox_ssl.adapters.azure_kv import AzureKvAdapter

        assert AzureKvAdapter.REQUIRES_BASE_URL is True
        assert AzureKvAdapter.REQUIRES_REGION is False


class TestCredentialSchema:
    def test_managed_identity_needs_no_credentials(self):
        from netbox_ssl.adapters.azure_kv import AzureKvAdapter

        assert AzureKvAdapter.credential_schema("azure_managed_identity") == {}

    def test_explicit_declares_three_components(self):
        from netbox_ssl.adapters.azure_kv import AzureKvAdapter

        schema = AzureKvAdapter.credential_schema("azure_explicit")
        assert set(schema) == {"tenant_id", "client_id", "client_secret"}
        assert all(field.required for field in schema.values())

    def test_only_the_client_secret_is_marked_secret(self):
        from netbox_ssl.adapters.azure_kv import AzureKvAdapter

        schema = AzureKvAdapter.credential_schema("azure_explicit")
        assert schema["client_secret"].secret is True
        assert schema["tenant_id"].secret is False
        assert schema["client_id"].secret is False

    def test_unknown_auth_method_raises(self):
        from netbox_ssl.adapters.azure_kv import AzureKvAdapter

        with pytest.raises(ValueError, match="does not support auth_method"):
            AzureKvAdapter.credential_schema("bearer")


class TestRegistration:
    def test_registered_under_azure_kv(self):
        from netbox_ssl.adapters import get_adapter_class
        from netbox_ssl.adapters.azure_kv import AzureKvAdapter

        assert get_adapter_class("azure_kv") is AzureKvAdapter
