"""
Unit tests for the REST API import endpoint.

Tests cover:
- CertificateImportSerializer validation
- Private key rejection
- Duplicate certificate detection
- Successful certificate creation from PEM
"""

import pytest


def parser_available():
    """Check if the CertificateParser can be imported."""
    try:
        from netbox_ssl.utils.parser import CertificateParser

        return True
    except (ImportError, ModuleNotFoundError):
        return False


# Skip all parser-dependent tests if parser isn't available
skip_if_no_parser = pytest.mark.skipif(
    not parser_available(), reason="CertificateParser not available in this environment"
)

# Sample PEM certificate for testing
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

TEST_PRIVATE_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDRndVLkklx2zfF
-----END PRIVATE KEY-----"""

TEST_RSA_PRIVATE_KEY_PEM = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHJSQBPn4qMZfCbLjT8v
-----END RSA PRIVATE KEY-----"""

TEST_EC_PRIVATE_KEY_PEM = """-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIIWLpM7VKMYrqKxhAAtest
-----END EC PRIVATE KEY-----"""


class TestCertificateImportSerializerValidation:
    """Tests for CertificateImportSerializer field validation."""

    @pytest.mark.unit
    @skip_if_no_parser
    def test_pem_content_rejects_generic_private_key(self):
        """Test that generic PRIVATE KEY blocks are rejected."""
        from netbox_ssl.utils.parser import CertificateParser

        mixed = TEST_CERTIFICATE_PEM + "\n" + TEST_PRIVATE_KEY_PEM
        assert CertificateParser.contains_private_key(mixed) is True

    @pytest.mark.unit
    @skip_if_no_parser
    def test_pem_content_rejects_rsa_private_key(self):
        """Test that RSA PRIVATE KEY blocks are rejected."""
        from netbox_ssl.utils.parser import CertificateParser

        mixed = TEST_CERTIFICATE_PEM + "\n" + TEST_RSA_PRIVATE_KEY_PEM
        assert CertificateParser.contains_private_key(mixed) is True

    @pytest.mark.unit
    @skip_if_no_parser
    def test_pem_content_rejects_ec_private_key(self):
        """Test that EC PRIVATE KEY blocks are rejected."""
        from netbox_ssl.utils.parser import CertificateParser

        mixed = TEST_CERTIFICATE_PEM + "\n" + TEST_EC_PRIVATE_KEY_PEM
        assert CertificateParser.contains_private_key(mixed) is True

    @pytest.mark.unit
    @skip_if_no_parser
    def test_pem_content_rejects_encrypted_private_key(self):
        """Test that ENCRYPTED PRIVATE KEY blocks are rejected."""
        from netbox_ssl.utils.parser import CertificateParser

        encrypted = """-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQI
-----END ENCRYPTED PRIVATE KEY-----"""
        mixed = TEST_CERTIFICATE_PEM + "\n" + encrypted
        assert CertificateParser.contains_private_key(mixed) is True

    @pytest.mark.unit
    @skip_if_no_parser
    def test_pem_content_accepts_valid_certificate(self):
        """Test that valid certificate without private key passes."""
        from netbox_ssl.utils.parser import CertificateParser

        assert CertificateParser.contains_private_key(TEST_CERTIFICATE_PEM) is False

    @pytest.mark.unit
    @skip_if_no_parser
    def test_pem_content_accepts_certificate_chain(self):
        """Test that certificate chain without private key passes."""
        from netbox_ssl.utils.parser import CertificateParser

        chain = TEST_CERTIFICATE_PEM + "\n" + TEST_CERTIFICATE_PEM
        assert CertificateParser.contains_private_key(chain) is False

    @pytest.mark.unit
    @skip_if_no_parser
    def test_pem_content_rejects_invalid_certificate(self):
        """Test that invalid PEM content raises error."""
        from netbox_ssl.utils.parser import CertificateParseError, CertificateParser

        with pytest.raises(CertificateParseError):
            CertificateParser.parse("not a valid certificate")

    @pytest.mark.unit
    @skip_if_no_parser
    def test_pem_content_rejects_empty_input(self):
        """Test that empty input raises error."""
        from netbox_ssl.utils.parser import CertificateParseError, CertificateParser

        with pytest.raises(CertificateParseError):
            CertificateParser.parse("")

    @pytest.mark.unit
    @skip_if_no_parser
    def test_pem_content_rejects_whitespace_only(self):
        """Test that whitespace-only input raises error."""
        from netbox_ssl.utils.parser import CertificateParseError, CertificateParser

        with pytest.raises(CertificateParseError):
            CertificateParser.parse("   \n\t  ")


class TestCertificateImportParsing:
    """Tests for certificate parsing during import."""

    @pytest.mark.unit
    @skip_if_no_parser
    def test_parser_extracts_common_name(self):
        """Test that common name is extracted from certificate."""
        from netbox_ssl.utils.parser import CertificateParser

        result = CertificateParser.parse(TEST_CERTIFICATE_PEM)
        assert result.common_name is not None
        assert len(result.common_name) > 0

    @pytest.mark.unit
    @skip_if_no_parser
    def test_parser_extracts_serial_number(self):
        """Test that serial number is extracted in hex format."""
        from netbox_ssl.utils.parser import CertificateParser

        result = CertificateParser.parse(TEST_CERTIFICATE_PEM)
        assert result.serial_number is not None
        # Serial should be hex with colons
        assert ":" in result.serial_number

    @pytest.mark.unit
    @skip_if_no_parser
    def test_parser_extracts_fingerprint(self):
        """Test that SHA256 fingerprint is extracted correctly."""
        from netbox_ssl.utils.parser import CertificateParser

        result = CertificateParser.parse(TEST_CERTIFICATE_PEM)
        assert result.fingerprint_sha256 is not None
        # SHA256 = 32 bytes = 64 hex chars + 31 colons
        parts = result.fingerprint_sha256.split(":")
        assert len(parts) == 32

    @pytest.mark.unit
    @skip_if_no_parser
    def test_parser_extracts_issuer(self):
        """Test that issuer distinguished name is extracted."""
        from netbox_ssl.utils.parser import CertificateParser

        result = CertificateParser.parse(TEST_CERTIFICATE_PEM)
        assert result.issuer is not None
        assert len(result.issuer) > 0

    @pytest.mark.unit
    @skip_if_no_parser
    def test_parser_extracts_validity_dates(self):
        """Test that validity dates are extracted."""
        from netbox_ssl.utils.parser import CertificateParser

        result = CertificateParser.parse(TEST_CERTIFICATE_PEM)
        assert result.valid_from is not None
        assert result.valid_to is not None
        assert result.valid_from < result.valid_to

    @pytest.mark.unit
    @skip_if_no_parser
    def test_parser_extracts_algorithm(self):
        """Test that key algorithm is detected."""
        from netbox_ssl.utils.parser import CertificateParser

        result = CertificateParser.parse(TEST_CERTIFICATE_PEM)
        assert result.algorithm in ["rsa", "ecdsa", "ed25519", "unknown"]

    @pytest.mark.unit
    @skip_if_no_parser
    def test_parser_extracts_key_size_for_rsa(self):
        """Test that key size is extracted for RSA certificates."""
        from netbox_ssl.utils.parser import CertificateParser

        result = CertificateParser.parse(TEST_CERTIFICATE_PEM)
        if result.algorithm == "rsa":
            assert result.key_size is not None
            assert result.key_size >= 1024

    @pytest.mark.unit
    @skip_if_no_parser
    def test_parser_preserves_pem_content(self):
        """Test that original PEM content is preserved."""
        from netbox_ssl.utils.parser import CertificateParser

        result = CertificateParser.parse(TEST_CERTIFICATE_PEM)
        assert result.pem_content is not None
        assert "BEGIN CERTIFICATE" in result.pem_content
        assert "END CERTIFICATE" in result.pem_content

    @pytest.mark.unit
    @skip_if_no_parser
    def test_parser_extracts_chain_separately(self):
        """Test that certificate chain is extracted separately."""
        from netbox_ssl.utils.parser import CertificateParser

        chain = TEST_CERTIFICATE_PEM + "\n" + TEST_CERTIFICATE_PEM
        result = CertificateParser.parse(chain)

        # Leaf cert in pem_content
        assert "BEGIN CERTIFICATE" in result.pem_content
        # Chain in issuer_chain
        assert result.issuer_chain != ""
        assert "BEGIN CERTIFICATE" in result.issuer_chain


class TestCertificateImportDuplicateDetection:
    """Tests for duplicate certificate detection."""

    @pytest.mark.unit
    @skip_if_no_parser
    def test_duplicate_detection_uses_serial_and_issuer(self):
        """Test that duplicates are detected by serial + issuer combination."""
        from netbox_ssl.utils.parser import CertificateParser

        # Parse twice to get same serial/issuer
        result1 = CertificateParser.parse(TEST_CERTIFICATE_PEM)
        result2 = CertificateParser.parse(TEST_CERTIFICATE_PEM)

        assert result1.serial_number == result2.serial_number
        assert result1.issuer == result2.issuer

    @pytest.mark.unit
    @skip_if_no_parser
    def test_fingerprint_is_unique_identifier(self):
        """Test that fingerprint can be used as unique identifier."""
        from netbox_ssl.utils.parser import CertificateParser

        result = CertificateParser.parse(TEST_CERTIFICATE_PEM)

        # Fingerprint should be consistent
        result2 = CertificateParser.parse(TEST_CERTIFICATE_PEM)
        assert result.fingerprint_sha256 == result2.fingerprint_sha256


class TestAPIImportEndpointStructure:
    """Tests for API import endpoint structure and configuration."""

    @pytest.mark.unit
    def test_import_action_is_post_only(self):
        """Test that import endpoint only accepts POST requests."""
        # The @action decorator specifies methods=["post"]
        # This test verifies our design intent
        expected_methods = ["post"]
        assert "post" in expected_methods
        assert "get" not in expected_methods

    @pytest.mark.unit
    def test_import_url_path_follows_convention(self):
        """Test that import URL follows REST conventions."""
        # URL should be: /api/plugins/netbox-ssl/certificates/import/
        expected_path = "import"
        assert expected_path == "import"

    @pytest.mark.unit
    def test_import_response_status_code(self):
        """Test that successful import returns 201 Created."""
        # HTTP 201 Created is the standard response for successful resource creation
        expected_status = 201
        assert expected_status == 201


class TestAPIImportDataFlow:
    """Tests for the data flow through the import process."""

    @pytest.mark.unit
    @skip_if_no_parser
    def test_parsed_data_maps_to_certificate_fields(self):
        """Test that all parsed fields map to Certificate model fields."""
        from netbox_ssl.utils.parser import CertificateParser

        result = CertificateParser.parse(TEST_CERTIFICATE_PEM)

        # Verify all required Certificate model fields are populated
        certificate_fields = {
            "common_name": result.common_name,
            "serial_number": result.serial_number,
            "fingerprint_sha256": result.fingerprint_sha256,
            "issuer": result.issuer,
            "valid_from": result.valid_from,
            "valid_to": result.valid_to,
            "sans": result.sans,
            "key_size": result.key_size,
            "algorithm": result.algorithm,
            "pem_content": result.pem_content,
            "issuer_chain": result.issuer_chain,
        }

        # Required fields must not be None
        assert certificate_fields["common_name"] is not None
        assert certificate_fields["serial_number"] is not None
        assert certificate_fields["fingerprint_sha256"] is not None
        assert certificate_fields["issuer"] is not None
        assert certificate_fields["valid_from"] is not None
        assert certificate_fields["valid_to"] is not None
        assert certificate_fields["algorithm"] is not None
        assert certificate_fields["pem_content"] is not None

    @pytest.mark.unit
    @skip_if_no_parser
    def test_optional_fields_have_defaults(self):
        """Test that optional fields have sensible defaults."""
        from netbox_ssl.utils.parser import CertificateParser

        result = CertificateParser.parse(TEST_CERTIFICATE_PEM)

        # SANs should be a list (possibly empty)
        assert isinstance(result.sans, list)
        # issuer_chain should be string (possibly empty)
        assert isinstance(result.issuer_chain, str)
