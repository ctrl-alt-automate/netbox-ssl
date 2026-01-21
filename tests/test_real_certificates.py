"""
Tests using real-world certificates from public CAs.

These tests verify that our parser and validators work correctly
with actual certificates from Let's Encrypt, DigiCert, and Sectigo.
"""

import sys
from pathlib import Path

import pytest

# Allow importing parser module directly without loading the full netbox_ssl package
# This enables running tests locally without NetBox installed
_project_root = Path(__file__).parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

# Mock netbox.plugins if not available (for local testing without NetBox)
if "netbox" not in sys.modules:
    from unittest.mock import MagicMock

    sys.modules["netbox"] = MagicMock()
    sys.modules["netbox.plugins"] = MagicMock()

from netbox_ssl.utils.parser import CertificateParser, ParsedCertificate

# Get the fixtures directory
FIXTURES_DIR = Path(__file__).parent / "fixtures" / "real_world"


def read_pem_file(filename: str) -> str:
    """Read a PEM file from the real_world fixtures directory."""
    filepath = FIXTURES_DIR / filename
    if not filepath.exists():
        pytest.skip(f"Fixture file {filename} not found - run certificate fetch script")
    return filepath.read_text()


class TestRealCertificateParsing:
    """Test parsing of real-world certificates."""

    @pytest.mark.unit
    def test_parse_letsencrypt_certificate(self):
        """Test parsing a real Let's Encrypt certificate."""
        pem_content = read_pem_file("letsencrypt_leaf.pem")
        result = CertificateParser.parse(pem_content)

        assert isinstance(result, ParsedCertificate)
        assert "letsencrypt.org" in result.common_name.lower()
        assert "Let's Encrypt" in result.issuer
        assert result.algorithm in ["rsa", "ecdsa", "ed25519"]
        assert result.serial_number is not None
        assert result.fingerprint_sha256 is not None

    @pytest.mark.unit
    def test_parse_digicert_certificate(self):
        """Test parsing a real DigiCert EV certificate."""
        pem_content = read_pem_file("digicert_leaf.pem")
        result = CertificateParser.parse(pem_content)

        assert isinstance(result, ParsedCertificate)
        assert "digicert" in result.common_name.lower()
        assert "DigiCert" in result.issuer
        assert result.algorithm == "rsa"
        assert result.key_size >= 2048

    @pytest.mark.unit
    def test_parse_sectigo_certificate(self):
        """Test parsing a real Sectigo certificate."""
        pem_content = read_pem_file("sectigo_leaf.pem")
        result = CertificateParser.parse(pem_content)

        assert isinstance(result, ParsedCertificate)
        assert "sectigo" in result.common_name.lower()
        assert "Sectigo" in result.issuer
        assert result.algorithm == "rsa"


class TestRealCertificateChains:
    """Test certificate chain parsing with real chains."""

    @pytest.mark.unit
    def test_letsencrypt_chain_has_multiple_certs(self):
        """Test that Let's Encrypt chain contains multiple certificates."""
        pem_content = read_pem_file("letsencrypt_chain.pem")

        # Count certificates in chain
        cert_count = pem_content.count("-----BEGIN CERTIFICATE-----")
        assert cert_count >= 2, "Chain should have leaf + at least one intermediate"

    @pytest.mark.unit
    def test_digicert_chain_has_multiple_certs(self):
        """Test that DigiCert chain contains multiple certificates."""
        pem_content = read_pem_file("digicert_chain.pem")

        cert_count = pem_content.count("-----BEGIN CERTIFICATE-----")
        assert cert_count >= 2, "Chain should have leaf + at least one intermediate"

    @pytest.mark.unit
    def test_sectigo_chain_has_multiple_certs(self):
        """Test that Sectigo chain contains multiple certificates."""
        pem_content = read_pem_file("sectigo_chain.pem")

        cert_count = pem_content.count("-----BEGIN CERTIFICATE-----")
        assert cert_count >= 2, "Chain should have leaf + at least one intermediate"


class TestCAAutoDetection:
    """Test CA auto-detection with real issuer strings."""

    @pytest.mark.unit
    def test_detect_letsencrypt_issuer(self):
        """Test that Let's Encrypt issuer pattern matches."""
        pem_content = read_pem_file("letsencrypt_leaf.pem")
        result = CertificateParser.parse(pem_content)

        issuer = result.issuer.lower()
        # Common Let's Encrypt patterns
        assert any(
            pattern in issuer for pattern in ["let's encrypt", "letsencrypt", "isrg"]
        ), f"Let's Encrypt pattern not found in issuer: {result.issuer}"

    @pytest.mark.unit
    def test_detect_digicert_issuer(self):
        """Test that DigiCert issuer pattern matches."""
        pem_content = read_pem_file("digicert_leaf.pem")
        result = CertificateParser.parse(pem_content)

        issuer = result.issuer.lower()
        assert "digicert" in issuer, f"DigiCert pattern not found in issuer: {result.issuer}"

    @pytest.mark.unit
    def test_detect_sectigo_issuer(self):
        """Test that Sectigo issuer pattern matches."""
        pem_content = read_pem_file("sectigo_leaf.pem")
        result = CertificateParser.parse(pem_content)

        issuer = result.issuer.lower()
        assert "sectigo" in issuer, f"Sectigo pattern not found in issuer: {result.issuer}"


class TestRealSANs:
    """Test SAN parsing with real certificates that have multiple SANs."""

    @pytest.mark.unit
    def test_letsencrypt_has_sans(self):
        """Test that Let's Encrypt certificate has SANs."""
        pem_content = read_pem_file("letsencrypt_leaf.pem")
        result = CertificateParser.parse(pem_content)

        assert result.sans is not None
        assert len(result.sans) > 0
        # letsencrypt.org should be in SANs
        assert any("letsencrypt" in san.lower() for san in result.sans)

    @pytest.mark.unit
    def test_digicert_has_sans(self):
        """Test that DigiCert certificate has SANs."""
        pem_content = read_pem_file("digicert_leaf.pem")
        result = CertificateParser.parse(pem_content)

        assert result.sans is not None
        assert len(result.sans) > 0


class TestRealCertificateMetadata:
    """Test that all expected metadata is extracted from real certificates."""

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "cert_file",
        ["letsencrypt_leaf.pem", "digicert_leaf.pem", "sectigo_leaf.pem"],
    )
    def test_all_required_fields_present(self, cert_file):
        """Test that all required fields are extracted from real certificates."""
        pem_content = read_pem_file(cert_file)
        result = CertificateParser.parse(pem_content)

        # All required fields should be present and not None
        assert result.common_name is not None
        assert result.serial_number is not None
        assert result.fingerprint_sha256 is not None
        assert result.issuer is not None
        assert result.valid_from is not None
        assert result.valid_to is not None
        assert result.algorithm is not None

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "cert_file",
        ["letsencrypt_leaf.pem", "digicert_leaf.pem", "sectigo_leaf.pem"],
    )
    def test_fingerprint_format(self, cert_file):
        """Test that fingerprint has correct format (colon-separated hex)."""
        pem_content = read_pem_file(cert_file)
        result = CertificateParser.parse(pem_content)

        fingerprint = result.fingerprint_sha256
        # Should be colon-separated hex pairs
        assert ":" in fingerprint
        parts = fingerprint.split(":")
        assert len(parts) == 32, "SHA256 fingerprint should have 32 hex pairs"
        for part in parts:
            assert len(part) == 2, "Each fingerprint part should be 2 hex chars"
            int(part, 16)  # Should be valid hex

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "cert_file",
        ["letsencrypt_leaf.pem", "digicert_leaf.pem", "sectigo_leaf.pem"],
    )
    def test_validity_dates_are_datetime(self, cert_file):
        """Test that validity dates are proper datetime objects."""
        from datetime import datetime

        pem_content = read_pem_file(cert_file)
        result = CertificateParser.parse(pem_content)

        assert isinstance(result.valid_from, datetime)
        assert isinstance(result.valid_to, datetime)
        # valid_to should be after valid_from
        assert result.valid_to > result.valid_from
