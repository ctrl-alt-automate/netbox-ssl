"""
Unit tests for ACME Renewal Information (ARI) utilities — RFC 9773.

Tests CertID construction, ARI response parsing, URL validation,
and Retry-After header handling.
"""

import base64
import importlib.util
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID, NameOID

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

from netbox_ssl.utils.ari import (
    ARIError,
    _parse_retry_after,
    _parse_rfc3339,
    build_cert_id,
)

# Mark all tests in this module as unit tests
pytestmark = pytest.mark.unit


def _generate_cert_with_aki():
    """Generate a self-signed certificate with Authority Key Identifier."""
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
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


@pytest.fixture
def cert_pem_with_aki():
    """Fixture providing a PEM certificate with AKI extension."""
    cert, _ = _generate_cert_with_aki()
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


@pytest.fixture
def test_cert_with_aki():
    """Fixture providing certificate object and key."""
    return _generate_cert_with_aki()


# ─────────────────────────────────────────────
# CertID construction tests
# ─────────────────────────────────────────────


class TestBuildCertId:
    """Test ARI CertID construction from certificate PEM."""

    def test_cert_id_format(self, cert_pem_with_aki):
        """CertID should be 'base64url(AKI).base64url(serial)'."""
        cert_id = build_cert_id(cert_pem_with_aki)
        assert "." in cert_id
        parts = cert_id.split(".")
        assert len(parts) == 2

    def test_cert_id_base64url_encoding(self, cert_pem_with_aki):
        """Both parts should be valid base64url (no padding)."""
        cert_id = build_cert_id(cert_pem_with_aki)
        aki_part, serial_part = cert_id.split(".")

        # Should not contain padding
        assert "=" not in aki_part
        assert "=" not in serial_part

        # Should decode without error (add padding back)
        def _decode(s):
            padded = s + "=" * (4 - len(s) % 4)
            return base64.urlsafe_b64decode(padded)

        aki_bytes = _decode(aki_part)
        serial_bytes = _decode(serial_part)
        assert len(aki_bytes) > 0
        assert len(serial_bytes) > 0

    def test_cert_id_consistent(self, cert_pem_with_aki):
        """Same certificate should always produce the same CertID."""
        id1 = build_cert_id(cert_pem_with_aki)
        id2 = build_cert_id(cert_pem_with_aki)
        assert id1 == id2

    def test_cert_id_aki_matches_extension(self, test_cert_with_aki):
        """AKI part of CertID should match the certificate's AKI extension."""
        cert, _ = test_cert_with_aki
        pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        cert_id = build_cert_id(pem)

        # Extract actual AKI from certificate
        aki_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        aki_bytes = aki_ext.value.key_identifier

        # Decode AKI part from CertID
        aki_part = cert_id.split(".")[0]
        padded = aki_part + "=" * (4 - len(aki_part) % 4)
        decoded_aki = base64.urlsafe_b64decode(padded)

        assert decoded_aki == aki_bytes

    def test_cert_without_aki_raises(self):
        """Certificate without AKI should raise ARIError."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "no-aki.example.com")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(12345)
            .not_valid_before(datetime(2024, 1, 1))
            .not_valid_after(datetime(2025, 1, 1))
            .sign(key, hashes.SHA256())
        )
        pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

        with pytest.raises(ARIError, match="Authority Key Identifier"):
            build_cert_id(pem)


# ─────────────────────────────────────────────
# RFC 3339 timestamp parsing tests
# ─────────────────────────────────────────────


class TestTimestampParsing:
    """Test RFC 3339 timestamp and Retry-After parsing."""

    def test_parse_rfc3339_with_z(self):
        dt = _parse_rfc3339("2025-01-02T04:00:00Z")
        assert dt.year == 2025
        assert dt.month == 1
        assert dt.day == 2
        assert dt.hour == 4
        assert dt.tzinfo is not None

    def test_parse_rfc3339_with_offset(self):
        dt = _parse_rfc3339("2025-06-15T12:30:00+02:00")
        assert dt.year == 2025
        assert dt.month == 6

    def test_parse_retry_after_seconds(self):
        before = datetime.now(tz=timezone.utc)
        dt = _parse_retry_after("21600")  # 6 hours
        after = datetime.now(tz=timezone.utc) + timedelta(seconds=21600)
        assert before + timedelta(seconds=21600) <= dt <= after + timedelta(seconds=1)

    def test_parse_retry_after_http_date(self):
        dt = _parse_retry_after("Wed, 21 Oct 2025 07:28:00 GMT")
        assert dt.year == 2025
        assert dt.month == 10


# ─────────────────────────────────────────────
# ARI directories tests
# ─────────────────────────────────────────────


class TestARIDirectories:
    """Test known ARI directory configuration."""

    def test_letsencrypt_directory_defined(self):
        from netbox_ssl.utils.ari import ARI_DIRECTORIES

        assert "letsencrypt" in ARI_DIRECTORIES
        assert "acme-v02.api.letsencrypt.org" in ARI_DIRECTORIES["letsencrypt"]

    def test_google_directory_defined(self):
        from netbox_ssl.utils.ari import ARI_DIRECTORIES

        assert "google" in ARI_DIRECTORIES


# ─────────────────────────────────────────────
# Model property tests (source inspection)
# ─────────────────────────────────────────────


class TestModelARIProperties:
    """Test ARI-related properties on Certificate model via source inspection."""

    def test_ari_fields_in_model(self):
        import pathlib

        source = (pathlib.Path(__file__).parent.parent / "netbox_ssl" / "models" / "certificates.py").read_text()
        assert "ari_cert_id" in source
        assert "ari_suggested_start" in source
        assert "ari_suggested_end" in source
        assert "ari_explanation_url" in source
        assert "ari_last_checked" in source
        assert "ari_retry_after" in source

    def test_ari_properties_in_model(self):
        import pathlib

        source = (pathlib.Path(__file__).parent.parent / "netbox_ssl" / "models" / "certificates.py").read_text()
        assert "def ari_window_active" in source
        assert "def ari_status" in source

    def test_migration_exists(self):
        import pathlib

        migration = pathlib.Path(__file__).parent.parent / "netbox_ssl" / "migrations" / "0018_ari_fields.py"
        assert migration.exists()
        source = migration.read_text()
        assert "ari_cert_id" in source
        assert "ari_suggested_start" in source
