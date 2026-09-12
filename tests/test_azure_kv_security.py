"""Security invariants for the Azure Key Vault adapter (#101).

Layer 1 is Azure RBAC: `Key Vault Reader` grants certificates/read but not
secrets/getSecret, so the PFX is unreachable whatever the code does. These tests
cover the code-side layers, which exist so a future role change cannot silently
turn a metadata reader into a key exporter.
"""

import ast
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

# Importing the adapter pulls netbox_ssl/__init__.py, which imports
# netbox.plugins. NetBox is absent on the host lane, so mock it — the repo's
# established pattern, also used by test_credential_schema.py and test_adapters.py.
import importlib.util  # noqa: E402

from .conftest import get_plugin_source_dir  # noqa: E402

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
# globally. Borrowed state like that is collection-order luck (#101 review M3).
# Here the cost was subtler than a red test: without the stub, the good
# certificate in TestProhibitedFieldAbortsTheWholeRun never got as far as being
# parsed -- the per-certificate handler swallowed AppRegistryNotReady -- so the
# control case passed while exercising nothing.
# Probing with a real import means the stub is installed ONLY when
# the genuine module is unusable -- in the container lane, where Django is
# fully configured, nothing is replaced.
try:  # pragma: no cover - exercised by which lane runs this file
    import django.contrib.contenttypes.models  # noqa: F401
except Exception:  # AppRegistryNotReady / ImproperlyConfigured / ImportError
    sys.modules.setdefault("django.contrib.contenttypes.models", MagicMock())

# get_plugin_source_dir(), not Path(__file__).parent.parent: in the container
# lane these tests live at /tmp/plugin_tests/ while the plugin is mounted at
# /opt/netbox/netbox/netbox_ssl/, so the hand-rolled form resolved to
# /tmp/netbox_ssl/... and these key-material tripwires died with
# FileNotFoundError instead of guarding anything (#101 review C3).
ADAPTER = get_plugin_source_dir() / "adapters" / "azure_kv.py"


def _source():
    source = MagicMock()
    source.base_url = "https://kv.vault.azure.net/"
    source.auth_method = "azure_managed_identity"
    source.auth_credentials = {}
    source.sync_tags = False
    source.name = "azure-test"
    return source


class TestAdapterNeverTouchesKeyMaterial:
    def test_module_never_imports_secret_or_key_clients(self):
        """A SecretClient is the only way to reach the PFX; it must not appear."""
        tree = ast.parse(ADAPTER.read_text())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.ImportFrom, ast.Import)):
                imported.update(alias.name for alias in node.names)

        forbidden = {"SecretClient", "KeyClient"}
        assert not (imported & forbidden), (
            f"azure_kv.py imports {imported & forbidden}; a certificate's private key "
            "is reachable only through those clients"
        )

    def test_module_never_calls_key_or_secret_getters(self):
        source = ADAPTER.read_text()
        for forbidden in ("get_secret(", "get_key(", "backup_key(", "download_secret("):
            assert forbidden not in source, f"azure_kv.py calls {forbidden}"

    def test_module_never_dereferences_the_sid_or_kid_reference(self):
        """A certificate response carries sid/kid; they are metadata, never followed."""
        source = ADAPTER.read_text()
        for forbidden in (".sid", ".kid"):
            assert forbidden not in source, f"azure_kv.py touches {forbidden}, which points at key/secret material"


class TestProhibitedFieldAssertion:
    def test_response_carrying_key_material_fails_hard(self):
        from netbox_ssl.adapters.azure_kv import AzureKvAdapter, ProhibitedFieldError

        adapter = AzureKvAdapter(_source())

        poisoned = {"cer": b"x", "secret_value": "-----BEGIN PRIVATE KEY-----"}
        with pytest.raises(ProhibitedFieldError, match="prohibited"):
            adapter._assert_no_prohibited_keys(poisoned)

    def test_clean_response_passes(self):
        from netbox_ssl.adapters.azure_kv import AzureKvAdapter

        adapter = AzureKvAdapter(_source())

        adapter._assert_no_prohibited_keys({"cer": b"x", "name": "ok"})


class TestProhibitedFieldAbortsTheWholeRun:
    """The tripwire must stop the sync, not just skip the offending certificate.

    fetch_certificates wraps each certificate in a broad `except Exception` so
    one bad entry never costs the whole run — that handler must NOT catch
    ProhibitedFieldError. If it did, a vault returning key material would
    silently lose one certificate from the result instead of halting the sync
    where an operator will see it.
    """

    @staticmethod
    def _real_der(cn="www.netbox-ssl-demo.test"):
        from cert_factory import CertFactory
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        pem = CertFactory.create(cn=cn, extended_key_usage=["server"])
        return x509.load_pem_x509_certificate(pem.encode()).public_bytes(serialization.Encoding.DER)

    def test_a_poisoned_certificate_aborts_instead_of_being_skipped(self, monkeypatch):
        from netbox_ssl.adapters import azure_kv

        good_props = MagicMock(name="good-props")
        good_props.name = "good"
        poisoned_props = MagicMock(name="poisoned-props")
        poisoned_props.name = "poisoned"

        # A real, parseable certificate: if the tripwire were ever widened to
        # be caught by the per-certificate handler, this one would sail
        # through and fetch_certificates would return it instead of raising —
        # which is exactly the regression this test must catch.
        good_cert = MagicMock()
        good_cert.cer = self._real_der("good.netbox-ssl-demo.test")
        good_cert.name = "good"
        good_cert.properties.name = "good"
        good_cert.properties.id = "https://kv.vault.azure.net/certificates/good/v1"
        good_cert.properties.enabled = True
        good_cert.properties.tags = {}

        # A response object carrying a prohibited field name as a real
        # attribute, so dir() picks it up just like it would for the real
        # Azure SDK object.
        poisoned_cert = MagicMock()
        poisoned_cert.cer = b"x"
        poisoned_cert.name = "poisoned"
        poisoned_cert.secret_value = "-----BEGIN PRIVATE KEY-----"

        client = MagicMock()
        client.list_properties_of_certificates.return_value = iter([good_props, poisoned_props])
        client.get_certificate.side_effect = lambda name: {
            "good": good_cert,
            "poisoned": poisoned_cert,
        }[name]
        monkeypatch.setattr(azure_kv, "CertificateClient", lambda **kw: client)

        adapter = azure_kv.AzureKvAdapter(_source())

        # Must raise — NOT return a one-item list containing only "good".
        with pytest.raises(azure_kv.ProhibitedFieldError):
            adapter.fetch_certificates()

    def test_the_general_handler_would_have_swallowed_a_plain_exception(self, monkeypatch):
        """Control case: proves the per-certificate handler is still in effect
        for ordinary failures, so the test above is exercising the carve-out
        for ProhibitedFieldError specifically, not a handler that aborts on
        everything.
        """
        from netbox_ssl.adapters import azure_kv

        broken_props = MagicMock(name="broken-props")
        broken_props.name = "broken"
        good_props = MagicMock(name="good-props")
        good_props.name = "good"

        good_cert = MagicMock()
        good_cert.cer = b"irrelevant-for-this-test"
        good_cert.name = "good"

        client = MagicMock()
        client.list_properties_of_certificates.return_value = iter([broken_props, good_props])

        def _get_certificate(name):
            if name == "broken":
                raise RuntimeError("transient Azure error")
            return good_cert

        client.get_certificate.side_effect = _get_certificate
        monkeypatch.setattr(azure_kv, "CertificateClient", lambda **kw: client)
        # _to_fetched will still run the real parser on good_cert; that is
        # exercised elsewhere, so stub it out to isolate the control flow
        # under test here.
        monkeypatch.setattr(
            azure_kv.AzureKvAdapter,
            "_to_fetched",
            lambda self, kv_cert: kv_cert.name,
        )

        adapter = azure_kv.AzureKvAdapter(_source())

        # Should not raise: the ordinary per-certificate handler still
        # catches RuntimeError and continues.
        results = adapter.fetch_certificates()
        assert results == ["good"]
