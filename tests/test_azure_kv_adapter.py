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

# WHY this file installs its own Django stub instead of leaning on another
# test file's: `azure_kv._to_fetched` lazily imports `..utils.parser`, which
# pulls netbox_ssl/utils/__init__.py -> assignments.py ->
# django.contrib.contenttypes.models. On the host lane Django's app registry is
# never populated, so that import raises AppRegistryNotReady. These tests used
# to pass only because test_adapters.py -- imported earlier by alphabetical
# collection -- happens to `setdefault` the same stub into sys.modules
# globally. Borrowed state like that is collection-order luck: renaming the
# donor, or splitting the suite, silently reds 13 real-behaviour tests (#101
# review M3). Probing with a real import means the stub is installed ONLY when
# the genuine module is unusable -- in the container lane, where Django is
# fully configured, nothing is replaced.
try:  # pragma: no cover - exercised by which lane runs this file
    import django.contrib.contenttypes.models  # noqa: F401
except Exception:  # AppRegistryNotReady / ImproperlyConfigured / ImportError
    sys.modules.setdefault("django.contrib.contenttypes.models", MagicMock())


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


_NON_VAULT_URLS = [
    "https://evil.example.com/",
    "https://kv.vault.azure.net.evil.com/",
    "http://kv.vault.azure.net/",
]


class TestVaultUrlValidation:
    """The host allowlist is a security control, so test it through the public API.

    WHY not call `_validate_vault_url` directly (as this class used to): that
    proves the validator works, not that the adapter uses it. Deleting the
    `self._validate_vault_url(...)` call from `_get_client` left the whole
    suite green, because every other test supplies a valid URL (#101 review
    M7). These tests drive `test_connection()` and `fetch_certificates()` --
    the only two ways an operator reaches the vault -- and additionally assert
    that no `CertificateClient` was ever constructed, i.e. that not one request
    left for the rejected host.
    """

    @staticmethod
    def _spy_client(monkeypatch) -> list[dict]:
        """Patch CertificateClient with a spy recording every construction."""
        from netbox_ssl.adapters import azure_kv

        constructed: list[dict] = []
        client = MagicMock()
        client.list_properties_of_certificates.return_value = iter([])

        def _factory(**kwargs):
            constructed.append(kwargs)
            return client

        monkeypatch.setattr(azure_kv, "CertificateClient", _factory)
        return constructed

    @pytest.mark.parametrize(
        "url",
        [
            "https://kv.vault.azure.net/",
            "https://kv.vault.azure.cn/",
            "https://kv.vault.usgovcloudapi.net/",
            "https://kv.vault.microsoftazure.de/",
        ],
    )
    def test_accepts_every_sovereign_cloud_suffix(self, url, monkeypatch):
        """A legitimate vault in any sovereign cloud must still be reachable."""
        from netbox_ssl.adapters import azure_kv

        constructed = self._spy_client(monkeypatch)

        ok, message = azure_kv.AzureKvAdapter(_source(base_url=url)).test_connection()

        assert ok is True, message
        assert [c["vault_url"] for c in constructed] == [url]

    @pytest.mark.parametrize("url", _NON_VAULT_URLS)
    def test_test_connection_refuses_a_non_vault_host(self, url, monkeypatch):
        from netbox_ssl.adapters import azure_kv

        constructed = self._spy_client(monkeypatch)

        ok, message = azure_kv.AzureKvAdapter(_source(base_url=url)).test_connection()

        assert ok is False, f"test_connection accepted {url}"
        assert "Key Vault" in message, f"the refusal does not explain itself: {message!r}"
        assert constructed == [], f"a client was built for {url}; the SSRF guard is not wired in"

    @pytest.mark.parametrize("url", _NON_VAULT_URLS)
    def test_fetch_certificates_refuses_a_non_vault_host(self, url, monkeypatch):
        """The sync path must refuse too -- test_connection is optional, syncing is not."""
        from netbox_ssl.adapters import azure_kv

        constructed = self._spy_client(monkeypatch)

        with pytest.raises(ValueError, match="Key Vault"):
            azure_kv.AzureKvAdapter(_source(base_url=url)).fetch_certificates()

        assert constructed == [], f"a client was built for {url}; the SSRF guard is not wired in"


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


def _kv_cert(name="test-webserver", der=b"", enabled=True, tags=None, expires=None, version="a1b2c3d4e5f6"):
    """Build a stub KeyVaultCertificate.

    `properties.id` is deliberately version-pinned, matching what the real
    Azure SDK returns (".../certificates/<name>/<version>") — a stub that
    hardcodes the unversioned form can't catch a mapping that accidentally
    trusts `props.id` as-is.
    """
    from datetime import datetime, timedelta, timezone

    cert = MagicMock()
    cert.cer = der
    cert.name = name
    cert.properties.name = name
    cert.properties.id = f"https://kv.vault.azure.net/certificates/{name}/{version}"
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
        # Version-independent, NOT the version-pinned props.id the stub
        # carries ("https://kv.vault.azure.net/certificates/test-webserver/a1b2c3d4e5f6") --
        # renewals must not change external_id or the sync engine's diff
        # would treat every renewal as a brand-new certificate.
        assert fetched.external_id == "https://kv-nbssl-test-2609.vault.azure.net/certificates/test-webserver"
        assert fetched.external_id != str(kv_cert.properties.id)
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


class TestGetCertificateDetail:
    def _der(self, cn="detail.netbox-ssl-demo.test"):
        from cert_factory import CertFactory
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        pem = CertFactory.create(cn=cn, extended_key_usage=["server"])
        return x509.load_pem_x509_certificate(pem.encode()).public_bytes(serialization.Encoding.DER)

    def test_unversioned_id_resolves_to_the_right_name(self, monkeypatch):
        from netbox_ssl.adapters import azure_kv

        kv_cert = _kv_cert(name="detail-cert", der=self._der())
        client = MagicMock()
        client.get_certificate.return_value = kv_cert
        monkeypatch.setattr(azure_kv, "CertificateClient", lambda **kw: client)

        result = azure_kv.AzureKvAdapter(_source()).get_certificate_detail(
            "https://kv.vault.azure.net/certificates/detail-cert"
        )

        client.get_certificate.assert_called_once_with("detail-cert")
        assert result is not None
        assert result.common_name == "detail.netbox-ssl-demo.test"

    def test_version_pinned_id_resolves_to_the_same_name(self, monkeypatch):
        from netbox_ssl.adapters import azure_kv

        kv_cert = _kv_cert(name="detail-cert", der=self._der())
        client = MagicMock()
        client.get_certificate.return_value = kv_cert
        monkeypatch.setattr(azure_kv, "CertificateClient", lambda **kw: client)

        result = azure_kv.AzureKvAdapter(_source()).get_certificate_detail(
            "https://kv.vault.azure.net/certificates/detail-cert/a1b2c3d4e5f6"
        )

        # The version segment must never be mistaken for the certificate name.
        client.get_certificate.assert_called_once_with("detail-cert")
        assert result is not None
        assert result.common_name == "detail.netbox-ssl-demo.test"

    def test_not_found_returns_none(self, monkeypatch):
        from azure.core.exceptions import ResourceNotFoundError

        from netbox_ssl.adapters import azure_kv

        client = MagicMock()
        client.get_certificate.side_effect = ResourceNotFoundError("gone")
        monkeypatch.setattr(azure_kv, "CertificateClient", lambda **kw: client)

        result = azure_kv.AzureKvAdapter(_source()).get_certificate_detail(
            "https://kv.vault.azure.net/certificates/detail-cert"
        )

        assert result is None


class TestStatusMapping:
    def _fetch_one(self, monkeypatch, **cert_kwargs):
        from cert_factory import CertFactory
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        from netbox_ssl.adapters import azure_kv

        pem = CertFactory.create(cn="status.example.com", extended_key_usage=["server"])
        der = x509.load_pem_x509_certificate(pem.encode()).public_bytes(serialization.Encoding.DER)
        kv_cert = _kv_cert(der=der, **cert_kwargs)
        client = MagicMock()
        client.list_properties_of_certificates.return_value = iter([kv_cert.properties])
        client.get_certificate.return_value = kv_cert
        monkeypatch.setattr(azure_kv, "CertificateClient", lambda **kw: client)
        return azure_kv.AzureKvAdapter(_source()).fetch_certificates()[0]

    def test_disabled_certificate_maps_to_archived(self, monkeypatch):
        assert self._fetch_one(monkeypatch, enabled=False).status == "archived"

    def test_valid_enabled_certificate_maps_to_active(self, monkeypatch):
        assert self._fetch_one(monkeypatch, enabled=True).status == "active"

    def test_expired_certificate_maps_to_expired(self, monkeypatch):
        """Expiry is judged on the parsed X.509 validity, not Azure metadata."""
        from cert_factory import CertFactory
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        from netbox_ssl.adapters import azure_kv

        pem = CertFactory.create(cn="old.example.com", expired=True, extended_key_usage=["server"])
        der = x509.load_pem_x509_certificate(pem.encode()).public_bytes(serialization.Encoding.DER)
        kv_cert = _kv_cert(der=der, enabled=True)
        client = MagicMock()
        client.list_properties_of_certificates.return_value = iter([kv_cert.properties])
        client.get_certificate.return_value = kv_cert
        monkeypatch.setattr(azure_kv, "CertificateClient", lambda **kw: client)

        assert azure_kv.AzureKvAdapter(_source()).fetch_certificates()[0].status == "expired"

    def test_disabled_beats_expired(self, monkeypatch):
        """An operator disabling a certificate is a stronger signal than expiry."""
        assert self._fetch_one(monkeypatch, enabled=False).status == "archived"

    @pytest.mark.django_db
    @pytest.mark.skipif(
        not _NETBOX_AVAILABLE,
        reason="requires real netbox/Django - runs in the Docker container lane",
    )
    def test_status_literals_match_the_real_choice_set(self):
        """_map_status returns literals, so guard them against drift in BOTH directions.

        The adapter cannot import CertificateStatusChoices at module level — a
        sys.modules mock from another test file would replace it — so it holds
        its own string constants. This test reads those constants and checks
        each is a real member of the ChoiceSet, which catches a renamed choice
        value AND a typo introduced in the adapter's own literal.
        """
        from netbox_ssl.adapters.azure_kv import AzureKvAdapter
        from netbox_ssl.models import CertificateStatusChoices

        valid = {value for value, *_ in CertificateStatusChoices.CHOICES}
        adapter_literals = {
            AzureKvAdapter._STATUS_ACTIVE,
            AzureKvAdapter._STATUS_EXPIRED,
            AzureKvAdapter._STATUS_ARCHIVED,
        }
        unknown = adapter_literals - valid
        assert not unknown, f"AzureKvAdapter emits status value(s) the model does not define: {sorted(unknown)}"


class TestTagMapping:
    def _fetch_with_tags(self, monkeypatch, tags, sync_tags):
        from cert_factory import CertFactory
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        from netbox_ssl.adapters import azure_kv

        pem = CertFactory.create(cn="tagged.example.com", extended_key_usage=["server"])
        der = x509.load_pem_x509_certificate(pem.encode()).public_bytes(serialization.Encoding.DER)
        kv_cert = _kv_cert(der=der, tags=tags)
        client = MagicMock()
        client.list_properties_of_certificates.return_value = iter([kv_cert.properties])
        client.get_certificate.return_value = kv_cert
        monkeypatch.setattr(azure_kv, "CertificateClient", lambda **kw: client)
        return azure_kv.AzureKvAdapter(_source(sync_tags=sync_tags)).fetch_certificates()[0]

    def test_key_value_pairs_become_key_equals_value(self, monkeypatch):
        fetched = self._fetch_with_tags(monkeypatch, {"env": "prod", "owner": "team-a"}, True)
        assert set(fetched.tags) == {"env=prod", "owner=team-a"}

    def test_valueless_tag_keeps_only_the_key(self, monkeypatch):
        fetched = self._fetch_with_tags(monkeypatch, {"reviewed": ""}, True)
        assert fetched.tags == ("reviewed",)

    def test_tags_are_not_collected_when_sync_tags_is_off(self, monkeypatch):
        fetched = self._fetch_with_tags(monkeypatch, {"env": "prod"}, False)
        assert fetched.tags == ()

    def test_tag_order_is_deterministic(self, monkeypatch):
        fetched = self._fetch_with_tags(monkeypatch, {"z": "1", "a": "2"}, True)
        assert fetched.tags == ("a=2", "z=1")
