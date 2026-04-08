"""
Unit tests for import/export extensions.

Tests format auto-detection, DER/PKCS#7 parsing, assignment export, and diff.
"""

import importlib.util
import sys
from datetime import datetime
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# ---------------------------------------------------------------------------
# Mock Django/NetBox before importing plugin code
# ---------------------------------------------------------------------------
try:
    _spec = importlib.util.find_spec("netbox")
    _NETBOX_AVAILABLE = _spec is not None and _spec.origin is not None
except (ValueError, ModuleNotFoundError):
    _NETBOX_AVAILABLE = False

if not _NETBOX_AVAILABLE and "netbox" not in sys.modules:
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
        "django.views",
        "django.views.generic",
        "django.http",
        "netbox",
        "netbox.models",
        "netbox.plugins",
        "utilities",
        "utilities.choices",
    ]:
        if mod not in sys.modules:
            sys.modules[mod] = MagicMock()

from netbox_ssl.utils.diff import ExportDiffer
from netbox_ssl.utils.parser import CertificateParseError, CertificateParser

# Mark all tests in this module as unit tests
pytestmark = pytest.mark.unit


def _generate_self_signed_cert():
    """Generate a self-signed certificate for testing."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2024, 1, 1))
        .not_valid_after(datetime(2025, 1, 1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("test.example.com")]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


@pytest.fixture
def test_cert():
    """Fixture providing a test certificate and its key."""
    cert, key = _generate_self_signed_cert()
    return cert, key


@pytest.fixture
def cert_pem(test_cert):
    """Certificate in PEM format."""
    cert, _ = test_cert
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def cert_der(test_cert):
    """Certificate in DER format."""
    cert, _ = test_cert
    return cert.public_bytes(serialization.Encoding.DER)


# ─────────────────────────────────────────────
# Format detection tests
# ─────────────────────────────────────────────


class TestFormatDetection:
    """Test auto-detection of certificate formats."""

    def test_detect_pem(self, cert_pem):
        assert CertificateParser.detect_format(cert_pem) == "pem"

    def test_detect_der(self, cert_der):
        assert CertificateParser.detect_format(cert_der) == "der"

    def test_detect_unknown_for_random_bytes(self):
        assert CertificateParser.detect_format(b"not a certificate") == "unknown"

    def test_detect_pem_text(self):
        pem_text = b"-----BEGIN CERTIFICATE-----\nMIIBxx...\n-----END CERTIFICATE-----"
        assert CertificateParser.detect_format(pem_text) == "pem"

    def test_detect_pkcs7_pem(self):
        pkcs7_text = b"-----BEGIN PKCS7-----\nMIIBxx...\n-----END PKCS7-----"
        assert CertificateParser.detect_format(pkcs7_text) == "pkcs7_pem"


# ─────────────────────────────────────────────
# DER parsing tests
# ─────────────────────────────────────────────


class TestDERParsing:
    """Test DER format certificate parsing."""

    def test_parse_der_returns_parsed_certificate(self, cert_der):
        result = CertificateParser.parse_der(cert_der)
        assert result.common_name == "test.example.com"
        assert result.algorithm == "rsa"
        assert result.key_size == 2048

    def test_parse_der_generates_pem_content(self, cert_der):
        result = CertificateParser.parse_der(cert_der)
        assert "-----BEGIN CERTIFICATE-----" in result.pem_content

    def test_parse_der_round_trip(self, cert_pem, cert_der):
        """DER and PEM parsing produce the same fingerprint."""
        pem_result = CertificateParser.parse(cert_pem.decode("utf-8"))
        der_result = CertificateParser.parse_der(cert_der)
        assert pem_result.fingerprint_sha256 == der_result.fingerprint_sha256

    def test_parse_der_invalid_data(self):
        with pytest.raises(CertificateParseError, match="Failed to parse DER"):
            CertificateParser.parse_der(b"\x30\x00invalid")

    def test_parse_der_rejects_oversized(self):
        oversized = b"\x30" + b"\x00" * (CertificateParser.MAX_PEM_INPUT_BYTES + 1)
        with pytest.raises(CertificateParseError, match="Input too large"):
            CertificateParser.parse_der(oversized)


# ─────────────────────────────────────────────
# Auto-parse tests
# ─────────────────────────────────────────────


class TestAutoparse:
    """Test unified auto-detection + parse entry point."""

    def test_parse_auto_pem(self, cert_pem):
        results = CertificateParser.parse_auto(cert_pem)
        assert len(results) == 1
        assert results[0].common_name == "test.example.com"

    def test_parse_auto_der(self, cert_der):
        results = CertificateParser.parse_auto(cert_der)
        assert len(results) == 1
        assert results[0].common_name == "test.example.com"

    def test_parse_auto_unknown_raises(self):
        with pytest.raises(CertificateParseError, match="Unrecognized"):
            CertificateParser.parse_auto(b"not a certificate at all")


# ─────────────────────────────────────────────
# Export diff tests
# ─────────────────────────────────────────────


class TestExportDiff:
    """Test export snapshot comparison."""

    def test_no_changes(self):
        snapshot = [{"fingerprint_sha256": "AA:BB", "status": "active", "common_name": "a.com"}]
        result = ExportDiffer.compare(snapshot, snapshot)
        assert result["summary"]["added_count"] == 0
        assert result["summary"]["removed_count"] == 0
        assert result["summary"]["changed_count"] == 0

    def test_added_certificates(self):
        old = [{"fingerprint_sha256": "AA:BB", "status": "active"}]
        new = [
            {"fingerprint_sha256": "AA:BB", "status": "active"},
            {"fingerprint_sha256": "CC:DD", "status": "active"},
        ]
        result = ExportDiffer.compare(old, new)
        assert result["summary"]["added_count"] == 1
        assert result["added"][0]["fingerprint_sha256"] == "CC:DD"

    def test_removed_certificates(self):
        old = [
            {"fingerprint_sha256": "AA:BB", "status": "active"},
            {"fingerprint_sha256": "CC:DD", "status": "active"},
        ]
        new = [{"fingerprint_sha256": "AA:BB", "status": "active"}]
        result = ExportDiffer.compare(old, new)
        assert result["summary"]["removed_count"] == 1

    def test_changed_certificates(self):
        old = [{"fingerprint_sha256": "AA:BB", "status": "active", "common_name": "a.com"}]
        new = [{"fingerprint_sha256": "AA:BB", "status": "expired", "common_name": "a.com"}]
        result = ExportDiffer.compare(old, new)
        assert result["summary"]["changed_count"] == 1
        assert result["changed"][0]["changes"][0]["field"] == "status"
        assert result["changed"][0]["changes"][0]["old"] == "active"
        assert result["changed"][0]["changes"][0]["new"] == "expired"

    def test_mixed_changes(self):
        old = [
            {"fingerprint_sha256": "AA:BB", "status": "active", "common_name": "a.com"},
            {"fingerprint_sha256": "CC:DD", "status": "active", "common_name": "b.com"},
        ]
        new = [
            {"fingerprint_sha256": "AA:BB", "status": "expired", "common_name": "a.com"},
            {"fingerprint_sha256": "EE:FF", "status": "active", "common_name": "c.com"},
        ]
        result = ExportDiffer.compare(old, new)
        assert result["summary"]["added_count"] == 1
        assert result["summary"]["removed_count"] == 1
        assert result["summary"]["changed_count"] == 1

    def test_empty_snapshots(self):
        result = ExportDiffer.compare([], [])
        assert result["summary"]["added_count"] == 0
        assert result["summary"]["removed_count"] == 0

    def test_custom_key_field(self):
        """Diff using a different key field."""
        old = [{"serial_number": "01:02", "status": "active"}]
        new = [{"serial_number": "01:02", "status": "expired"}]
        result = ExportDiffer.compare(old, new, key_field="serial_number")
        assert result["summary"]["changed_count"] == 1
        assert result["summary"]["added_count"] == 0


# ─────────────────────────────────────────────
# API endpoint source verification tests
# ─────────────────────────────────────────────


class TestAPIEndpoints:
    """Verify import-file and diff API endpoints exist in source."""

    @pytest.fixture(autouse=True)
    def _load_source(self):
        import pathlib

        self.source = (pathlib.Path(__file__).parent.parent / "netbox_ssl" / "api" / "views.py").read_text()

    def test_import_file_endpoint_exists(self):
        assert 'url_path="import-file"' in self.source
        assert "def import_file" in self.source

    def test_import_file_uses_parse_auto(self):
        """import_file endpoint uses parse_auto for format auto-detection."""
        assert "parse_auto" in self.source

    def test_import_file_has_permission_check(self):
        assert "import_certificate" in self.source

    def test_import_file_has_size_guard(self):
        assert "MAX_PEM_INPUT_BYTES" in self.source

    def test_import_file_handles_private_key(self):
        assert "PrivateKeyDetectedError" in self.source

    def test_diff_endpoint_exists(self):
        assert 'url_path="diff"' in self.source
        assert "def diff_snapshots" in self.source

    def test_diff_uses_export_differ(self):
        assert "ExportDiffer" in self.source

    def test_diff_validates_input(self):
        """diff endpoint validates old and new are lists."""
        assert "isinstance(old_snapshot, list)" in self.source

    def test_diff_has_size_limit(self):
        assert "max_export_size" in self.source


class TestScheduledExportScript:
    """Verify the scheduled export script exists and is registered."""

    @pytest.fixture(autouse=True)
    def _load_sources(self):
        import pathlib

        plugin_dir = pathlib.Path(__file__).parent.parent / "netbox_ssl"
        self.script_source = (plugin_dir / "scripts" / "scheduled_export.py").read_text()
        self.init_source = (plugin_dir / "scripts" / "__init__.py").read_text()

    def test_script_file_exists(self):
        assert "class ScheduledCertificateExport" in self.script_source

    def test_script_extends_netbox_script(self):
        assert "Script" in self.script_source

    def test_script_has_format_choice(self):
        assert "export_format" in self.script_source

    def test_script_has_tenant_filter(self):
        assert "tenant" in self.script_source

    def test_script_respects_max_export_size(self):
        assert "max_export_size" in self.script_source

    def test_script_registered_in_init(self):
        assert "ScheduledCertificateExport" in self.init_source
