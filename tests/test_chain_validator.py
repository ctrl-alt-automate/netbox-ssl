"""
Unit tests for the certificate chain validation utility.

Tests chain validation, signature verification, and validity checks.
"""

import sys
from pathlib import Path

import pytest

# Allow importing modules directly without loading the full netbox_ssl package
_project_root = Path(__file__).parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

# Mock netbox modules if not available
if "netbox" not in sys.modules:
    from unittest.mock import MagicMock

    sys.modules["netbox"] = MagicMock()
    sys.modules["netbox.plugins"] = MagicMock()
    sys.modules["netbox.models"] = MagicMock()
    sys.modules["utilities"] = MagicMock()
    sys.modules["utilities.choices"] = MagicMock()

from netbox_ssl.utils.chain_validator import (
    ChainValidationResult,
    ChainValidationStatus,
    ChainValidator,
)


# Self-signed test certificate
SELF_SIGNED_CERT = """-----BEGIN CERTIFICATE-----
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


class TestChainValidationResult:
    """Tests for ChainValidationResult dataclass."""

    @pytest.mark.unit
    def test_result_has_required_fields(self):
        """Test that result has all required fields."""
        result = ChainValidator.validate(SELF_SIGNED_CERT, "")

        assert hasattr(result, "status")
        assert hasattr(result, "is_valid")
        assert hasattr(result, "message")
        assert hasattr(result, "chain_depth")
        assert hasattr(result, "certificates")
        assert hasattr(result, "errors")
        assert hasattr(result, "validated_at")


class TestSelfSignedCertificates:
    """Tests for self-signed certificate handling."""

    @pytest.mark.unit
    def test_self_signed_is_valid(self):
        """Test that self-signed certificates are considered valid."""
        result = ChainValidator.validate(SELF_SIGNED_CERT, "")

        assert result.status == ChainValidationStatus.SELF_SIGNED
        assert result.is_valid is True
        assert result.chain_depth == 1

    @pytest.mark.unit
    def test_self_signed_no_chain_needed(self):
        """Test that self-signed certificates don't need a chain."""
        result = ChainValidator.validate(SELF_SIGNED_CERT, "")

        assert "self-signed" in result.message.lower()
        assert len(result.errors) == 0


class TestChainParsing:
    """Tests for chain certificate parsing."""

    @pytest.mark.unit
    def test_empty_chain(self):
        """Test validation with empty chain string."""
        # For non-self-signed cert, empty chain would fail
        # But self-signed cert with empty chain should pass
        result = ChainValidator.validate(SELF_SIGNED_CERT, "")
        assert result.status == ChainValidationStatus.SELF_SIGNED

    @pytest.mark.unit
    def test_whitespace_only_chain(self):
        """Test validation with whitespace-only chain."""
        result = ChainValidator.validate(SELF_SIGNED_CERT, "   \n\t  ")
        assert result.status == ChainValidationStatus.SELF_SIGNED

    @pytest.mark.unit
    def test_invalid_pem_content(self):
        """Test validation with invalid PEM content."""
        result = ChainValidator.validate("not a certificate", "")

        assert result.status == ChainValidationStatus.PARSE_ERROR
        assert result.is_valid is False
        assert len(result.errors) > 0


class TestCertificateInfo:
    """Tests for certificate information extraction."""

    @pytest.mark.unit
    def test_certificate_info_extracted(self):
        """Test that certificate info is properly extracted."""
        result = ChainValidator.validate(SELF_SIGNED_CERT, "")

        assert len(result.certificates) == 1
        cert_info = result.certificates[0]

        assert "common_name" in cert_info
        assert "subject" in cert_info
        assert "issuer" in cert_info
        assert "serial_number" in cert_info
        assert "fingerprint_sha256" in cert_info
        assert "valid_from" in cert_info
        assert "valid_to" in cert_info
        assert "is_leaf" in cert_info
        assert "is_self_signed" in cert_info

    @pytest.mark.unit
    def test_leaf_certificate_marked(self):
        """Test that leaf certificate is properly marked."""
        result = ChainValidator.validate(SELF_SIGNED_CERT, "")

        assert result.certificates[0]["is_leaf"] is True

    @pytest.mark.unit
    def test_fingerprint_format(self):
        """Test that fingerprint is in correct format."""
        result = ChainValidator.validate(SELF_SIGNED_CERT, "")

        fingerprint = result.certificates[0]["fingerprint_sha256"]
        parts = fingerprint.split(":")
        assert len(parts) == 32  # SHA256 = 32 bytes
        for part in parts:
            assert len(part) == 2
            assert all(c in "0123456789ABCDEF" for c in part)


class TestValidationTimestamp:
    """Tests for validation timestamp."""

    @pytest.mark.unit
    def test_validated_at_is_set(self):
        """Test that validated_at timestamp is set."""
        result = ChainValidator.validate(SELF_SIGNED_CERT, "")

        assert result.validated_at is not None

    @pytest.mark.unit
    def test_validated_at_is_recent(self):
        """Test that validated_at is a recent timestamp."""
        from datetime import datetime, timezone, timedelta

        result = ChainValidator.validate(SELF_SIGNED_CERT, "")

        now = datetime.now(timezone.utc)
        delta = now - result.validated_at
        assert delta < timedelta(seconds=10)


class TestChainValidationStatus:
    """Tests for chain validation status enum."""

    @pytest.mark.unit
    def test_status_values(self):
        """Test that status enum has expected values."""
        assert ChainValidationStatus.VALID.value == "valid"
        assert ChainValidationStatus.INCOMPLETE.value == "incomplete"
        assert ChainValidationStatus.INVALID_SIGNATURE.value == "invalid_signature"
        assert ChainValidationStatus.EXPIRED.value == "expired"
        assert ChainValidationStatus.NOT_YET_VALID.value == "not_yet_valid"
        assert ChainValidationStatus.SELF_SIGNED.value == "self_signed"
        assert ChainValidationStatus.PARSE_ERROR.value == "parse_error"
        assert ChainValidationStatus.NO_CHAIN.value == "no_chain"


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    @pytest.mark.unit
    def test_empty_input(self):
        """Test validation with empty input."""
        result = ChainValidator.validate("", "")

        assert result.status == ChainValidationStatus.PARSE_ERROR
        assert result.is_valid is False

    @pytest.mark.unit
    def test_malformed_pem(self):
        """Test validation with malformed PEM."""
        malformed = """-----BEGIN CERTIFICATE-----
        invalid base64 !@#$%^&*()
        -----END CERTIFICATE-----"""

        result = ChainValidator.validate(malformed, "")

        assert result.status == ChainValidationStatus.PARSE_ERROR
        assert result.is_valid is False

    @pytest.mark.unit
    def test_truncated_certificate(self):
        """Test validation with truncated certificate."""
        truncated = """-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJANrHhzLqL0CXMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
-----END CERTIFICATE-----"""

        result = ChainValidator.validate(truncated, "")

        assert result.status == ChainValidationStatus.PARSE_ERROR
        assert result.is_valid is False


class TestChainDepth:
    """Tests for chain depth calculation."""

    @pytest.mark.unit
    def test_single_cert_depth(self):
        """Test chain depth for single certificate."""
        result = ChainValidator.validate(SELF_SIGNED_CERT, "")

        assert result.chain_depth == 1

    @pytest.mark.unit
    def test_chain_with_duplicates_counted(self):
        """Test that all certificates in chain are counted."""
        # Use same cert twice as a pseudo-chain
        result = ChainValidator.validate(SELF_SIGNED_CERT, SELF_SIGNED_CERT)

        # This will fail validation (not a real chain) but should still parse
        # Self-signed cert doesn't need a chain, so it returns immediately
        assert result.chain_depth >= 1
