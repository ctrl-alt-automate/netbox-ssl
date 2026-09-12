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


def _kv_cert(name="test-webserver", der=b"", enabled=True, tags=None, expires=None):
    """Build a stub KeyVaultCertificate."""
    from datetime import datetime, timedelta, timezone

    cert = MagicMock()
    cert.cer = der
    cert.name = name
    cert.properties.id = f"https://kv.vault.azure.net/certificates/{name}"
    cert.properties.enabled = enabled
    cert.properties.tags = tags or {}
    cert.properties.expires_on = expires or datetime.now(timezone.utc) + timedelta(days=365)
    return cert


class TestFetchCertificates:
    def _der(self, cn="www.netbox-ssl-demo.test"):
        from cert_factory import CertFactory
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        pem = CertFactory.create(cn=cn, extended_key_usage=["server"])
        return x509.load_pem_x509_certificate(pem.encode()).public_bytes(serialization.Encoding.DER)

    def test_maps_a_certificate_through_the_plugin_parser(self, monkeypatch):
        from netbox_ssl.adapters import azure_kv

        kv_cert = _kv_cert(der=self._der())
        client = MagicMock()
        client.list_properties_of_certificates.return_value = iter([kv_cert.properties])
        client.get_certificate.return_value = kv_cert
        monkeypatch.setattr(azure_kv, "CertificateClient", lambda **kw: client)

        results = azure_kv.AzureKvAdapter(_source()).fetch_certificates()

        assert len(results) == 1
        fetched = results[0]
        assert fetched.common_name == "www.netbox-ssl-demo.test"
        assert fetched.external_id == "https://kv.vault.azure.net/certificates/test-webserver"
        assert fetched.pem_content.startswith("-----BEGIN CERTIFICATE-----")
        assert ":" in fetched.fingerprint_sha256  # canonical colon-separated form
        assert fetched.certificate_type == "server"  # from EKU, via the parser

    def test_certificate_without_cer_is_skipped_not_fatal(self, monkeypatch):
        """A certificate still being issued has no public part yet."""
        from netbox_ssl.adapters import azure_kv

        pending = _kv_cert(name="pending", der=None)
        good = _kv_cert(name="good", der=self._der("api.netbox-ssl-demo.test"))
        client = MagicMock()
        client.list_properties_of_certificates.return_value = iter([pending.properties, good.properties])
        client.get_certificate.side_effect = [pending, good]
        monkeypatch.setattr(azure_kv, "CertificateClient", lambda **kw: client)

        results = azure_kv.AzureKvAdapter(_source()).fetch_certificates()

        assert [r.common_name for r in results] == ["api.netbox-ssl-demo.test"]

    def test_one_failing_certificate_does_not_abort_the_run(self, monkeypatch):
        from netbox_ssl.adapters import azure_kv

        good = _kv_cert(name="good", der=self._der("api.netbox-ssl-demo.test"))
        client = MagicMock()
        client.list_properties_of_certificates.return_value = iter([MagicMock(name="broken"), good.properties])
        client.get_certificate.side_effect = [RuntimeError("transient"), good]
        monkeypatch.setattr(azure_kv, "CertificateClient", lambda **kw: client)

        results = azure_kv.AzureKvAdapter(_source()).fetch_certificates()

        assert len(results) == 1
