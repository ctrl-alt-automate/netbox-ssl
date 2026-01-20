"""
Unit tests for the CSR parser utility and CSR model.

These tests verify CSR PEM parsing and attribute extraction.
"""

import sys
from pathlib import Path

import pytest

# Allow importing modules directly without loading the full netbox_ssl package
# This enables running tests locally without NetBox installed
_project_root = Path(__file__).parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

# Mock netbox.plugins if not available (for local testing without NetBox)
if "netbox" not in sys.modules:
    from unittest.mock import MagicMock

    sys.modules["netbox"] = MagicMock()
    sys.modules["netbox.plugins"] = MagicMock()
    sys.modules["netbox.models"] = MagicMock()
    sys.modules["utilities"] = MagicMock()
    sys.modules["utilities.choices"] = MagicMock()

from netbox_ssl.utils.csr_parser import (  # noqa: E402
    CSRParseError,
    CSRParser,
    ParsedCSR,
)

# Sample CSR - RSA 2048-bit with full subject fields
# Generated with: openssl req -new -key key.pem -subj "/C=NL/ST=Noord-Holland/L=Amsterdam/O=Test Organization/OU=IT Department/CN=www.example.com"
TEST_CSR_PEM = """-----BEGIN CERTIFICATE REQUEST-----
MIICzTCCAbUCAQAwgYcxCzAJBgNVBAYTAk5MMRYwFAYDVQQIDA1Ob29yZC1Ib2xs
YW5kMRIwEAYDVQQHDAlBbXN0ZXJkYW0xGjAYBgNVBAoMEVRlc3QgT3JnYW5pemF0
aW9uMRYwFAYDVQQLDA1JVCBEZXBhcnRtZW50MRgwFgYDVQQDDA93d3cuZXhhbXBs
ZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCY9HD+lUZtaANv
D0kCGlN6CYbSux1qcEP/W9piNJA1XWFoZIIjmWW+KSkKKL0TSd+2gCS1cqnEENoi
qBwQxZ+UPKFBUhfCxldrWVkeTV6oSqSvdBNF/3bFFxg6ARgg14SLpguC3NkZGoab
jP5kaI1Vry92tejE8vbMctAnfM+Ufajn/E7am1k8NvPRRH79R7TE42fvPtJjZdk8
r3fXbhl94IvTz4F3T4DZjKm8IACMmmVaTWxHwUqjrNEPPgJa7XdqdG2p0ndQCXfu
hjj7CTrnFE4IvLIy5igUASYGCxXlv6CqLS87Jkm+dIxh9GddMP/zUGqGGfZrwpFm
Hn9NrC1/AgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAQEAFcGXwr9krB4KJ0Flu70r
umdLmThNu/QMuqyXK6oQ+1Pox0hKg2RcmrA8smxm3+SQOkdrXzy3HmZ0oBOK/Dxq
RF850HW1uRqt08yvsU7GF7tU2g5txTzF49OmymEdAPtJx0vTfEL+LXO49bbBIhQR
XEIXhu7Vaj2aZ6wweDNbGDVQbo6qyud5LCDBascocgv/l7O2yweqfsWAvcRFpXap
W3cWqVIwM2Iybur5kk414OItaGY2QXsi7te6HDeSBCdC0bydMGT1dbhQ2DXmpjtf
6bFJJip3RSyLnqJCB3PyUZdK0UMn33t1MVzdIpCWV8MdW6xIznh7BkfvW5HtYBJQ
9w==
-----END CERTIFICATE REQUEST-----"""

# Sample CSR with just CN (simpler subject)
# Generated with: openssl req -new -key key.pem -subj "/CN=localhost"
TEST_CSR_SIMPLE_PEM = TEST_CSR_PEM  # Use the same valid CSR for now

# Invalid CSR
TEST_INVALID_CSR = """-----BEGIN CERTIFICATE REQUEST-----
not valid base64 data here !@#$%
-----END CERTIFICATE REQUEST-----"""


class TestCSRExtraction:
    """Tests for CSR block extraction."""

    @pytest.mark.unit
    def test_extract_single_csr(self):
        """Test extraction of a single CSR."""
        csr = CSRParser.extract_csr(TEST_CSR_PEM)
        assert csr is not None
        assert "BEGIN CERTIFICATE REQUEST" in csr
        assert "END CERTIFICATE REQUEST" in csr

    @pytest.mark.unit
    def test_extract_no_csr(self):
        """Test extraction with no valid CSR."""
        csr = CSRParser.extract_csr("just some random text")
        assert csr is None

    @pytest.mark.unit
    def test_extract_with_extra_whitespace(self):
        """Test extraction with extra whitespace around CSR."""
        padded = "\n\n  " + TEST_CSR_PEM + "  \n\n"
        csr = CSRParser.extract_csr(padded)
        assert csr is not None

    @pytest.mark.unit
    def test_extract_new_csr_format(self):
        """Test extraction of 'NEW CERTIFICATE REQUEST' format."""
        new_csr = TEST_CSR_PEM.replace("BEGIN CERTIFICATE REQUEST", "BEGIN NEW CERTIFICATE REQUEST").replace(
            "END CERTIFICATE REQUEST", "END NEW CERTIFICATE REQUEST"
        )
        csr = CSRParser.extract_csr(new_csr)
        assert csr is not None
        assert "BEGIN NEW CERTIFICATE REQUEST" in csr


class TestCSRParsing:
    """Tests for full CSR parsing."""

    @pytest.mark.unit
    def test_parse_valid_csr(self):
        """Test parsing a valid CSR."""
        result = CSRParser.parse(TEST_CSR_PEM)

        assert isinstance(result, ParsedCSR)
        assert result.common_name == "www.example.com"
        assert result.organization == "Internet Widgits Pty Ltd"
        assert result.locality == "Amsterdam"
        assert result.state == "Some-State"
        assert result.country == "NL"
        assert result.fingerprint_sha256  # Has fingerprint
        assert result.algorithm == "rsa"
        assert result.key_size == 2048
        assert result.pem_content  # Has the PEM

    @pytest.mark.unit
    def test_parse_no_csr_raises_error(self):
        """Test that parsing raises error when no CSR found."""
        with pytest.raises(CSRParseError) as exc_info:
            CSRParser.parse("not a CSR")

        assert "No valid CSR found" in str(exc_info.value)

    @pytest.mark.unit
    def test_parse_invalid_csr_raises_error(self):
        """Test that parsing raises error for invalid CSR data."""
        with pytest.raises(CSRParseError) as exc_info:
            CSRParser.parse(TEST_INVALID_CSR)

        assert "Failed to parse CSR" in str(exc_info.value)

    @pytest.mark.unit
    def test_fingerprint_format(self):
        """Test that fingerprint is in correct format with colons."""
        result = CSRParser.parse(TEST_CSR_PEM)

        # Should be SHA256 with colons: XX:XX:XX:...
        parts = result.fingerprint_sha256.split(":")
        assert len(parts) == 32  # SHA256 = 32 bytes
        for part in parts:
            assert len(part) == 2
            assert all(c in "0123456789ABCDEF" for c in part)


class TestSubjectFieldExtraction:
    """Tests for CSR subject field extraction."""

    @pytest.mark.unit
    def test_common_name_extraction(self):
        """Test extraction of common name."""
        result = CSRParser.parse(TEST_CSR_PEM)
        assert result.common_name == "www.example.com"

    @pytest.mark.unit
    def test_organization_extraction(self):
        """Test extraction of organization."""
        result = CSRParser.parse(TEST_CSR_PEM)
        assert result.organization == "Test Organization"

    @pytest.mark.unit
    def test_locality_extraction(self):
        """Test extraction of locality."""
        result = CSRParser.parse(TEST_CSR_PEM)
        assert result.locality == "Amsterdam"

    @pytest.mark.unit
    def test_country_extraction(self):
        """Test extraction of country code."""
        result = CSRParser.parse(TEST_CSR_PEM)
        assert result.country == "NL"


class TestKeyInfoExtraction:
    """Tests for key algorithm and size extraction."""

    @pytest.mark.unit
    def test_rsa_key_detection(self):
        """Test that RSA keys are correctly identified."""
        result = CSRParser.parse(TEST_CSR_PEM)

        assert result.algorithm == "rsa"
        assert result.key_size == 2048


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    @pytest.mark.unit
    def test_empty_input(self):
        """Test parsing empty input."""
        with pytest.raises(CSRParseError):
            CSRParser.parse("")

    @pytest.mark.unit
    def test_whitespace_only_input(self):
        """Test parsing whitespace-only input."""
        with pytest.raises(CSRParseError):
            CSRParser.parse("   \n\t  ")

    @pytest.mark.unit
    def test_certificate_instead_of_csr(self):
        """Test that certificates are not mistaken for CSRs."""
        cert_pem = """-----BEGIN CERTIFICATE-----
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
        with pytest.raises(CSRParseError):
            CSRParser.parse(cert_pem)


class TestParsedCSRDataclass:
    """Tests for ParsedCSR dataclass."""

    @pytest.mark.unit
    def test_parsed_csr_fields(self):
        """Test that ParsedCSR has all expected fields."""
        result = CSRParser.parse(TEST_CSR_PEM)

        # Check all fields are present
        assert hasattr(result, "common_name")
        assert hasattr(result, "organization")
        assert hasattr(result, "organizational_unit")
        assert hasattr(result, "locality")
        assert hasattr(result, "state")
        assert hasattr(result, "country")
        assert hasattr(result, "sans")
        assert hasattr(result, "key_size")
        assert hasattr(result, "algorithm")
        assert hasattr(result, "fingerprint_sha256")
        assert hasattr(result, "pem_content")

    @pytest.mark.unit
    def test_sans_is_list(self):
        """Test that SANs is a list."""
        result = CSRParser.parse(TEST_CSR_PEM)
        assert isinstance(result.sans, list)
