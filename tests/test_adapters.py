"""
Unit tests for external source adapters.

Tests the adapter framework, registry, and individual adapter logic
without requiring a running NetBox instance or external connections.
"""

import importlib.util
import sys
from datetime import datetime, timezone
from types import SimpleNamespace
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

if not _NETBOX_AVAILABLE and "netbox" not in sys.modules:
    _django_utils_timezone = MagicMock()
    _django_utils_timezone.now.return_value = datetime(2026, 3, 22, 12, 0, 0, tzinfo=timezone.utc)

    for mod in [
        "django",
        "django.conf",
        "django.db",
        "django.db.models",
        "django.db.models.functions",
        "django.utils",
        "django.utils.timezone",
        "django.utils.translation",
        "django.contrib",
        "django.contrib.contenttypes",
        "django.contrib.contenttypes.fields",
        "django.contrib.contenttypes.models",
        "django.contrib.postgres",
        "django.contrib.postgres.fields",
        "django.contrib.postgres.indexes",
        "django.core",
        "django.core.exceptions",
        "django.urls",
        "netbox",
        "netbox.models",
        "netbox.plugins",
        "utilities",
        "utilities.choices",
    ]:
        sys.modules.setdefault(mod, MagicMock())
    sys.modules["django.utils.timezone"] = _django_utils_timezone

from netbox_ssl.adapters import _REGISTRY, get_adapter_for_source
from netbox_ssl.adapters.base import (
    PROHIBITED_SYNC_FIELDS,
    BaseAdapter,
    FetchedCertificate,
)
from netbox_ssl.adapters.generic_rest import (
    REQUIRED_MAPPING_KEYS,
    GenericRESTAdapter,
    resolve_dotted_path,
)
from netbox_ssl.adapters.lemur import LemurAdapter


@pytest.mark.unit
class TestBaseAdapter:
    """Test BaseAdapter abstract class."""

    def test_base_adapter_is_abstract(self):
        """Test that BaseAdapter cannot be instantiated directly."""
        with pytest.raises(TypeError):
            BaseAdapter(MagicMock())

    def test_fetched_certificate_is_frozen(self):
        """Test that FetchedCertificate is a frozen dataclass."""
        cert = FetchedCertificate(
            external_id="1",
            common_name="example.com",
            serial_number="AABB",
            fingerprint_sha256="AA:BB",
            issuer="Test CA",
            valid_from=datetime(2026, 1, 1, tzinfo=timezone.utc),
            valid_to=datetime(2027, 1, 1, tzinfo=timezone.utc),
        )
        with pytest.raises(AttributeError):
            cert.common_name = "changed.com"

    def test_fetched_certificate_defaults(self):
        """Test FetchedCertificate default values."""
        cert = FetchedCertificate(
            external_id="1",
            common_name="example.com",
            serial_number="AABB",
            fingerprint_sha256="AA:BB",
            issuer="Test CA",
            valid_from=datetime(2026, 1, 1, tzinfo=timezone.utc),
            valid_to=datetime(2027, 1, 1, tzinfo=timezone.utc),
        )
        assert cert.sans == []
        assert cert.key_size is None
        assert cert.algorithm == "unknown"
        assert cert.pem_content == ""
        assert cert.issuer_chain == ""

    def test_prohibited_sync_fields(self):
        """Test that PROHIBITED_SYNC_FIELDS contains key entries."""
        assert "private_key" in PROHIBITED_SYNC_FIELDS
        assert "key_material" in PROHIBITED_SYNC_FIELDS
        assert "p12" in PROHIBITED_SYNC_FIELDS
        assert "pfx" in PROHIBITED_SYNC_FIELDS
        assert "pkcs12" in PROHIBITED_SYNC_FIELDS
        assert isinstance(PROHIBITED_SYNC_FIELDS, frozenset)


@pytest.mark.unit
class TestAdapterRegistry:
    """Test adapter registry and factory function."""

    def test_registry_contains_lemur(self):
        """Test that the registry contains the Lemur adapter."""
        assert "lemur" in _REGISTRY
        assert _REGISTRY["lemur"] is LemurAdapter

    def test_registry_contains_generic_rest(self):
        """Test that the registry contains the Generic REST adapter."""
        assert "generic_rest" in _REGISTRY
        assert _REGISTRY["generic_rest"] is GenericRESTAdapter

    def test_get_adapter_for_source_lemur(self):
        """Test getting a Lemur adapter from a source."""
        source = SimpleNamespace(
            source_type="lemur",
            auth_credentials_reference="env:TOKEN",
            auth_method="bearer",
            base_url="https://lemur.example.com",
            verify_ssl=True,
            field_mapping={},
        )
        adapter = get_adapter_for_source(source)
        assert isinstance(adapter, LemurAdapter)

    def test_get_adapter_for_source_generic_rest(self):
        """Test getting a Generic REST adapter from a source."""
        source = SimpleNamespace(
            source_type="generic_rest",
            auth_credentials_reference="env:TOKEN",
            auth_method="api_key",
            base_url="https://api.example.com",
            verify_ssl=True,
            field_mapping={"list_endpoint": "/certs"},
        )
        adapter = get_adapter_for_source(source)
        assert isinstance(adapter, GenericRESTAdapter)

    def test_get_adapter_for_unknown_type_raises(self):
        """Test that unknown source type raises ValueError."""
        source = SimpleNamespace(source_type="unknown_type")
        with pytest.raises(ValueError, match="No adapter registered"):
            get_adapter_for_source(source)


@pytest.mark.unit
class TestLemurAdapter:
    """Test LemurAdapter parsing logic."""

    def _make_source(self) -> SimpleNamespace:
        return SimpleNamespace(
            name="test-lemur",
            source_type="lemur",
            auth_credentials_reference="env:LEMUR_TOKEN",
            auth_method="bearer",
            base_url="https://lemur.example.com",
            verify_ssl=True,
            field_mapping={},
        )

    def test_parse_lemur_certificate(self):
        """Test parsing a Lemur API certificate response."""
        data = {
            "id": 42,
            "cn": "example.com",
            "serialNumber": "AABB",
            "fingerprint": "AA:BB:CC:DD",
            "issuer": "CN=Test CA",
            "notBefore": "2026-01-01T00:00:00+00:00",
            "notAfter": "2027-01-01T00:00:00+00:00",
            "body": "-----BEGIN CERTIFICATE-----\nMIIB...",
            "chain": "-----BEGIN CERTIFICATE-----\nMIIC...",
            "keyType": "RSA2048",
            "bits": 2048,
            "extensions": {
                "subAltNames": {
                    "names": [
                        {"value": "example.com"},
                        {"value": "www.example.com"},
                    ]
                }
            },
        }
        cert = LemurAdapter._parse_lemur_certificate(data)
        assert cert is not None
        assert cert.external_id == "42"
        assert cert.common_name == "example.com"
        assert cert.serial_number == "AABB"
        assert cert.fingerprint_sha256 == "AA:BB:CC:DD"
        assert cert.issuer == "CN=Test CA"
        assert cert.algorithm == "rsa"
        assert cert.key_size == 2048
        assert "example.com" in cert.sans
        assert "www.example.com" in cert.sans
        assert cert.pem_content.startswith("-----BEGIN")

    def test_parse_lemur_certificate_missing_id(self):
        """Test that missing ID returns None."""
        data = {"cn": "example.com"}
        cert = LemurAdapter._parse_lemur_certificate(data)
        assert cert is None

    def test_parse_lemur_certificate_missing_dates(self):
        """Test that missing dates returns None."""
        data = {"id": 1, "cn": "example.com"}
        cert = LemurAdapter._parse_lemur_certificate(data)
        assert cert is None

    def test_parse_lemur_ecdsa_key_type(self):
        """Test ECDSA key type detection."""
        data = {
            "id": 1,
            "cn": "example.com",
            "serialNumber": "AABB",
            "fingerprint": "AA:BB",
            "issuer": "Test CA",
            "notBefore": "2026-01-01",
            "notAfter": "2027-01-01",
            "keyType": "ECDSA256",
        }
        cert = LemurAdapter._parse_lemur_certificate(data)
        assert cert is not None
        assert cert.algorithm == "ecdsa"


@pytest.mark.unit
class TestGenericRESTAdapter:
    """Test GenericRESTAdapter field mapping and parsing."""

    def _make_source(self, field_mapping: dict | None = None) -> SimpleNamespace:
        default_mapping = {
            "list_endpoint": "/api/certificates",
            "external_id": "id",
            "common_name": "cn",
            "serial_number": "serial",
            "fingerprint_sha256": "fingerprint",
            "issuer": "issuer",
            "valid_from": "not_before",
            "valid_to": "not_after",
        }
        return SimpleNamespace(
            name="test-generic",
            source_type="generic_rest",
            auth_credentials_reference="env:API_TOKEN",
            auth_method="api_key",
            base_url="https://api.example.com",
            verify_ssl=True,
            field_mapping=field_mapping or default_mapping,
        )

    def test_dotted_path_simple(self):
        """Test simple dotted path resolution."""
        data = {"name": "test"}
        assert resolve_dotted_path(data, "name") == "test"

    def test_dotted_path_nested(self):
        """Test nested dotted path resolution."""
        data = {"certificate": {"cn": "example.com"}}
        assert resolve_dotted_path(data, "certificate.cn") == "example.com"

    def test_dotted_path_deep_nested(self):
        """Test deeply nested dotted path resolution."""
        data = {"level1": {"level2": {"level3": "deep-value"}}}
        assert resolve_dotted_path(data, "level1.level2.level3") == "deep-value"

    def test_dotted_path_list_index(self):
        """Test dotted path with list index."""
        data = {"items": [{"name": "first"}, {"name": "second"}]}
        assert resolve_dotted_path(data, "items.0.name") == "first"
        assert resolve_dotted_path(data, "items.1.name") == "second"

    def test_dotted_path_missing_returns_none(self):
        """Test that missing path returns None."""
        data = {"name": "test"}
        assert resolve_dotted_path(data, "missing.field") is None

    def test_dotted_path_none_data(self):
        """Test that None data returns None."""
        assert resolve_dotted_path(None, "field") is None

    def test_validate_mapping_complete(self):
        """Test that complete mapping passes validation."""
        source = self._make_source()
        adapter = GenericRESTAdapter(source)
        missing = adapter._validate_mapping()
        assert missing == []

    def test_validate_mapping_missing_keys(self):
        """Test that missing mapping keys are reported."""
        source = self._make_source(field_mapping={"list_endpoint": "/api/certs"})
        adapter = GenericRESTAdapter(source)
        missing = adapter._validate_mapping()
        assert len(missing) > 0
        assert "common_name" in missing

    def test_parse_item_with_mapping(self):
        """Test parsing an API response item using field mapping."""
        source = self._make_source()
        adapter = GenericRESTAdapter(source)

        item = {
            "id": "cert-42",
            "cn": "example.com",
            "serial": "AABBCCDD",
            "fingerprint": "AA:BB:CC:DD:EE",
            "issuer": "CN=Test CA",
            "not_before": "2026-01-01T00:00:00Z",
            "not_after": "2027-01-01T00:00:00Z",
        }
        cert = adapter._parse_item(item)
        assert cert is not None
        assert cert.external_id == "cert-42"
        assert cert.common_name == "example.com"
        assert cert.serial_number == "AABBCCDD"
        assert cert.fingerprint_sha256 == "AA:BB:CC:DD:EE"
        assert cert.issuer == "CN=Test CA"

    def test_parse_item_with_optional_fields(self):
        """Test parsing with optional field mappings."""
        mapping = {
            "list_endpoint": "/api/certs",
            "external_id": "id",
            "common_name": "cn",
            "serial_number": "serial",
            "fingerprint_sha256": "fp",
            "issuer": "issuer",
            "valid_from": "start",
            "valid_to": "end",
            "sans": "alt_names",
            "key_size": "key.size",
            "algorithm": "key.type",
        }
        source = self._make_source(field_mapping=mapping)
        adapter = GenericRESTAdapter(source)

        item = {
            "id": "1",
            "cn": "test.com",
            "serial": "AABB",
            "fp": "AA:BB",
            "issuer": "CA",
            "start": "2026-01-01",
            "end": "2027-01-01",
            "alt_names": ["test.com", "www.test.com"],
            "key": {"size": 4096, "type": "RSA"},
        }
        cert = adapter._parse_item(item)
        assert cert is not None
        assert cert.sans == ["test.com", "www.test.com"]
        assert cert.key_size == 4096
        assert cert.algorithm == "rsa"

    def test_parse_item_missing_required_returns_none(self):
        """Test that missing required fields returns None."""
        source = self._make_source()
        adapter = GenericRESTAdapter(source)

        item = {"id": "1"}  # Missing most required fields
        cert = adapter._parse_item(item)
        assert cert is None

    def test_required_mapping_keys(self):
        """Test that REQUIRED_MAPPING_KEYS contains expected entries."""
        assert "list_endpoint" in REQUIRED_MAPPING_KEYS
        assert "external_id" in REQUIRED_MAPPING_KEYS
        assert "common_name" in REQUIRED_MAPPING_KEYS
        assert "serial_number" in REQUIRED_MAPPING_KEYS
        assert "fingerprint_sha256" in REQUIRED_MAPPING_KEYS
        assert "issuer" in REQUIRED_MAPPING_KEYS
        assert "valid_from" in REQUIRED_MAPPING_KEYS
        assert "valid_to" in REQUIRED_MAPPING_KEYS
