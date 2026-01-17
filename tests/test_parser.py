"""
Unit tests for the certificate parser utility.

These tests verify PEM parsing, private key detection, and X.509 extraction.
"""

import pytest
import sys
from datetime import datetime
from pathlib import Path

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

from netbox_ssl.utils.parser import (
    CertificateParser,
    CertificateParseError,
    PrivateKeyDetectedError,
    ParsedCertificate,
)


# Test certificate data - a self-signed test certificate
TEST_CERTIFICATE_PEM = """-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJANrHhzLqL0CXMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAk5MMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjBF
MQswCQYDVQQGEwJOTDETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHJSQBPn4qMZfCbLjT8vFJISxlKy
MrAJHGwSjQL/FZVqYwTR3FNS8OXHE0NVKv/sYJ2gB4q8JHr6qmQxqeT9bXD6lk7A
g0UpAsHmJgyC0xZHYuYLfBG1jxR/5qLKpCBjG1Fv0JbSU4A8b1G56Qb/SHHQx8NY
f6w7Kdbf4bN0jWH7nkG4iYJhHpmCbNv/z8THNQ5j7+kqFy0jkYFIhHJ3C8uKVBTN
cD3N8FVPq0WF3sHTHKz1PMHSFknPfR3pXXKK0k3beBi6L1cM7M3AeVvyLvGfPtJ5
aCc/4o4TLYsvLSDP8xhJzEfWfqlyqwIDAQABo1AwTjAdBgNVHQ4EFgQUBZ5GZaZL
SXdxiKzp/k1MHQ0Q0nswHwYDVR0jBBgwFoAUBZ5GZaZLSXdxiKzp/k1MHQ0Q0nsw
DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAimG8F1gHHINl7y0I+B5q
Hzq8LmRGdFiQzGYaCZqO9gBqMXy3C+G0xZV3t8ry4ZB3dKwFBz9/T9Dl8k0CCXSZ
QMGBr4MYqYAaH/C2vGkLKvdQEJMaztJMgG2DWQAL3HrmWg8A9SYz0FSD9LqCTU5U
VyHExK1C+PJm0bHJKK9Kfuqk8EHR6mZYCwgITdCG0xJB8lqpIkNyFMVIfNcPrnvQ
m0zSLGL7fWkQBJCZrM5ypmJVsRmkLC4MYN8N+5qNrWYXkXlSjp+xYX0k8qZpxC0D
VTy17f7Ke7oq5NXPG2Q7K/1LPpgjW0Fzbvy5RAKDRnF5fNzJvRMn+6Mqfz9hM7Eg
pQ==
-----END CERTIFICATE-----"""

# Sample private key (RSA) - for rejection tests only
TEST_PRIVATE_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDRndVLkklx2zfF
+f/KBbIXw9ucbLQAclJAE+fioxl8JsuNPy8UkhLGUrIysAkcbBKNAv8VlWpjBNHc
U1Lw5ccTQ1Uq/+xgnaAHirwkevqqZDGp5P1tcPqWTsCDRSkCweYmDILTFkdi5gt8
EbWPFH/mosqkIGMbUW/QltJTgDxvUbnpBv9IcdDHw1h/rDsp1t/hs3SNYfueQbiJ
gmEemYJs2//PxMc1DmPv6SoXLSORgUiEcncLy4pUFM1wPc3wVU+rRYXewdMcrPU8
wdIWSc99HeldcorSTdt4GLovVwzszcB5W/Iu8Z8+0nloJz/ijhMtiy8tIM/zGEnM
R9Z+qXKrAgMBAAECggEAAtest
-----END PRIVATE KEY-----"""

# RSA Private key pattern
TEST_RSA_PRIVATE_KEY_PEM = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHJSQBPn4qMZfCbLjT8v
FJISxlKyMrAJHGwSjQL/FZVqYwTR3FNS8OXHE0NVKv/sYJ2gB4q8JHr6qmQxqeT9
-----END RSA PRIVATE KEY-----"""

# EC Private key pattern
TEST_EC_PRIVATE_KEY_PEM = """-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIIWLpM7VKMYrqKxhAAtest
-----END EC PRIVATE KEY-----"""


class TestPrivateKeyDetection:
    """Tests for private key detection."""

    @pytest.mark.unit
    def test_detects_generic_private_key(self):
        """Test detection of generic PRIVATE KEY block."""
        assert CertificateParser.contains_private_key(TEST_PRIVATE_KEY_PEM) is True

    @pytest.mark.unit
    def test_detects_rsa_private_key(self):
        """Test detection of RSA PRIVATE KEY block."""
        assert CertificateParser.contains_private_key(TEST_RSA_PRIVATE_KEY_PEM) is True

    @pytest.mark.unit
    def test_detects_ec_private_key(self):
        """Test detection of EC PRIVATE KEY block."""
        assert CertificateParser.contains_private_key(TEST_EC_PRIVATE_KEY_PEM) is True

    @pytest.mark.unit
    def test_detects_encrypted_private_key(self):
        """Test detection of encrypted private key."""
        encrypted_key = """-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQI
-----END ENCRYPTED PRIVATE KEY-----"""
        assert CertificateParser.contains_private_key(encrypted_key) is True

    @pytest.mark.unit
    def test_no_private_key_in_certificate(self):
        """Test that certificates without private keys pass."""
        assert CertificateParser.contains_private_key(TEST_CERTIFICATE_PEM) is False

    @pytest.mark.unit
    def test_detects_mixed_content(self):
        """Test detection when certificate and private key are mixed."""
        mixed_content = TEST_CERTIFICATE_PEM + "\n\n" + TEST_PRIVATE_KEY_PEM
        assert CertificateParser.contains_private_key(mixed_content) is True


class TestCertificateExtraction:
    """Tests for certificate block extraction."""

    @pytest.mark.unit
    def test_extract_single_certificate(self):
        """Test extraction of a single certificate."""
        certs = CertificateParser.extract_certificates(TEST_CERTIFICATE_PEM)
        assert len(certs) == 1

    @pytest.mark.unit
    def test_extract_certificate_chain(self):
        """Test extraction of multiple certificates (chain)."""
        chain = TEST_CERTIFICATE_PEM + "\n" + TEST_CERTIFICATE_PEM
        certs = CertificateParser.extract_certificates(chain)
        assert len(certs) == 2

    @pytest.mark.unit
    def test_extract_no_certificates(self):
        """Test extraction with no valid certificates."""
        certs = CertificateParser.extract_certificates("just some random text")
        assert len(certs) == 0

    @pytest.mark.unit
    def test_extract_with_extra_whitespace(self):
        """Test extraction with extra whitespace around certificate."""
        padded = "\n\n  " + TEST_CERTIFICATE_PEM + "  \n\n"
        certs = CertificateParser.extract_certificates(padded)
        assert len(certs) == 1


class TestCertificateParsing:
    """Tests for full certificate parsing."""

    @pytest.mark.unit
    def test_parse_valid_certificate(self):
        """Test parsing a valid certificate."""
        result = CertificateParser.parse(TEST_CERTIFICATE_PEM)

        assert isinstance(result, ParsedCertificate)
        assert result.common_name  # Has a CN
        assert result.serial_number  # Has serial
        assert result.fingerprint_sha256  # Has fingerprint
        assert result.issuer  # Has issuer
        assert result.valid_from  # Has validity dates
        assert result.valid_to
        assert result.algorithm in ["rsa", "ecdsa", "ed25519", "unknown"]
        assert result.pem_content  # Has the PEM

    @pytest.mark.unit
    def test_parse_rejects_private_key(self):
        """Test that parsing rejects input with private key."""
        mixed = TEST_CERTIFICATE_PEM + "\n" + TEST_PRIVATE_KEY_PEM

        with pytest.raises(PrivateKeyDetectedError) as exc_info:
            CertificateParser.parse(mixed)

        assert "Private key detected" in str(exc_info.value)

    @pytest.mark.unit
    def test_parse_no_certificate_raises_error(self):
        """Test that parsing raises error when no certificate found."""
        with pytest.raises(CertificateParseError) as exc_info:
            CertificateParser.parse("not a certificate")

        assert "No valid certificate found" in str(exc_info.value)

    @pytest.mark.unit
    def test_parse_invalid_certificate_raises_error(self):
        """Test that parsing raises error for invalid certificate data."""
        invalid_cert = """-----BEGIN CERTIFICATE-----
        not valid base64 data here !@#$%
        -----END CERTIFICATE-----"""

        with pytest.raises(CertificateParseError) as exc_info:
            CertificateParser.parse(invalid_cert)

        assert "Failed to parse certificate" in str(exc_info.value)

    @pytest.mark.unit
    def test_fingerprint_format(self):
        """Test that fingerprint is in correct format with colons."""
        result = CertificateParser.parse(TEST_CERTIFICATE_PEM)

        # Should be SHA256 with colons: XX:XX:XX:...
        parts = result.fingerprint_sha256.split(":")
        assert len(parts) == 32  # SHA256 = 32 bytes
        for part in parts:
            assert len(part) == 2
            assert all(c in "0123456789ABCDEF" for c in part)

    @pytest.mark.unit
    def test_serial_number_format(self):
        """Test that serial number is in hex format with colons."""
        result = CertificateParser.parse(TEST_CERTIFICATE_PEM)

        # Serial should contain colons and hex chars
        parts = result.serial_number.split(":")
        for part in parts:
            assert len(part) == 2
            assert all(c in "0123456789ABCDEF" for c in part)


class TestKeyInfoExtraction:
    """Tests for key algorithm and size extraction."""

    @pytest.mark.unit
    def test_rsa_key_detection(self):
        """Test that RSA keys are correctly identified."""
        result = CertificateParser.parse(TEST_CERTIFICATE_PEM)

        # Our test cert uses RSA
        assert result.algorithm == "rsa"
        assert result.key_size is not None
        assert result.key_size >= 1024  # Reasonable RSA key size


class TestChainHandling:
    """Tests for certificate chain handling."""

    @pytest.mark.unit
    def test_chain_extraction(self):
        """Test that certificate chain is extracted separately."""
        # Create a "chain" with the same cert twice
        chain = TEST_CERTIFICATE_PEM + "\n" + TEST_CERTIFICATE_PEM

        result = CertificateParser.parse(chain)

        # Leaf cert should be first one
        assert result.pem_content == TEST_CERTIFICATE_PEM.strip()
        # Chain should contain the second cert
        assert result.issuer_chain  # Not empty
        assert "BEGIN CERTIFICATE" in result.issuer_chain

    @pytest.mark.unit
    def test_single_cert_no_chain(self):
        """Test that single certificate has empty chain."""
        result = CertificateParser.parse(TEST_CERTIFICATE_PEM)

        assert result.issuer_chain == ""


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    @pytest.mark.unit
    def test_empty_input(self):
        """Test parsing empty input."""
        with pytest.raises(CertificateParseError):
            CertificateParser.parse("")

    @pytest.mark.unit
    def test_whitespace_only_input(self):
        """Test parsing whitespace-only input."""
        with pytest.raises(CertificateParseError):
            CertificateParser.parse("   \n\t  ")

    @pytest.mark.unit
    def test_case_insensitive_private_key_detection(self):
        """Test that private key detection is case insensitive."""
        # Unlikely but possible variant
        lower_case_key = """-----begin private key-----
        MIIEvgIBADANtest
        -----end private key-----"""
        assert CertificateParser.contains_private_key(lower_case_key) is True
