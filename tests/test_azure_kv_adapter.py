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


def _source(**overrides):
    """A stub ExternalSource good enough for adapter unit tests."""
    source = MagicMock()
    source.base_url = overrides.get("base_url", "https://kv-nbssl-test-2609.vault.azure.net/")
    source.auth_method = overrides.get("auth_method", "azure_managed_identity")
    source.auth_credentials = overrides.get("auth_credentials", {})
    source.sync_tags = overrides.get("sync_tags", False)
    source.name = "azure-test"
    return source


class TestVaultUrlValidation:
    @pytest.mark.parametrize(
        "url",
        [
            "https://kv.vault.azure.net/",
            "https://kv.vault.azure.cn/",
            "https://kv.vault.usgovcloudapi.net/",
            "https://kv.vault.microsoftazure.de/",
        ],
    )
    def test_accepts_every_sovereign_cloud_suffix(self, url):
        from netbox_ssl.adapters.azure_kv import AzureKvAdapter

        AzureKvAdapter(_source(base_url=url))._validate_vault_url(url)

    @pytest.mark.parametrize(
        "url",
        [
            "https://evil.example.com/",
            "https://kv.vault.azure.net.evil.com/",
            "http://kv.vault.azure.net/",
        ],
    )
    def test_rejects_non_vault_hosts_and_plaintext(self, url):
        from netbox_ssl.adapters.azure_kv import AzureKvAdapter

        with pytest.raises(ValueError):
            AzureKvAdapter(_source(base_url=url))._validate_vault_url(url)


class TestTestConnection:
    def test_success_reports_the_certificate_count(self, monkeypatch):
        from netbox_ssl.adapters import azure_kv

        client = MagicMock()
        client.list_properties_of_certificates.return_value = iter([MagicMock(name="a"), MagicMock(name="b")])
        monkeypatch.setattr(azure_kv, "CertificateClient", lambda **kw: client)

        ok, message = azure_kv.AzureKvAdapter(_source()).test_connection()
        assert ok is True
        assert "2" in message

    def test_auth_failure_is_reported_without_leaking_the_credential(self, monkeypatch):
        from azure.core.exceptions import ClientAuthenticationError

        from netbox_ssl.adapters import azure_kv

        def _boom(**kwargs):
            raise ClientAuthenticationError("secret-value-should-never-surface")

        monkeypatch.setattr(azure_kv, "CertificateClient", _boom)

        ok, message = azure_kv.AzureKvAdapter(_source()).test_connection()
        assert ok is False
        assert "secret-value-should-never-surface" not in message
        assert "authentication" in message.lower()

    def test_permission_denied_names_the_required_role(self, monkeypatch):
        from azure.core.exceptions import HttpResponseError

        from netbox_ssl.adapters import azure_kv

        error = HttpResponseError("Forbidden")
        error.status_code = 403
        client = MagicMock()
        client.list_properties_of_certificates.side_effect = error
        monkeypatch.setattr(azure_kv, "CertificateClient", lambda **kw: client)

        ok, message = azure_kv.AzureKvAdapter(_source()).test_connection()
        assert ok is False
        assert "Key Vault Reader" in message
