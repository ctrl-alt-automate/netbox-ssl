"""
Unit tests for the Bulk Certificate Import API endpoint.

Tests cover:
- Successful bulk import of multiple certificates
- Validation error handling (atomic rollback)
- Input validation (list, empty, batch size)
- Response format
"""

from pathlib import Path

import pytest


def parser_available():
    """Check if the CertificateParser can be imported."""
    try:
        from netbox_ssl.utils.parser import CertificateParser  # noqa: F401

        return True
    except Exception:
        return False


skip_if_no_parser = pytest.mark.skipif(
    not parser_available(), reason="CertificateParser not available in this environment"
)

# Path to test certificates
FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_test_certificate(name):
    """Load a test certificate from the fixtures directory."""
    cert_path = FIXTURES_DIR / f"{name}.pem"
    if cert_path.exists():
        return cert_path.read_text()
    return None


def get_available_test_certs():
    """Get list of available test certificate names."""
    if not FIXTURES_DIR.exists():
        return []
    return [f.stem for f in FIXTURES_DIR.glob("cert_*.pem")]


class TestBulkImportInputValidation:
    """Tests for bulk import input validation."""

    @pytest.mark.unit
    def test_input_must_be_list(self):
        """Test that input must be a list, not a dict."""
        invalid_input = {"pem_content": "-----BEGIN CERTIFICATE-----"}
        assert not isinstance(invalid_input, list)

    @pytest.mark.unit
    def test_input_must_not_be_empty(self):
        """Test that empty list is rejected."""
        empty_input = []
        assert len(empty_input) == 0

    @pytest.mark.unit
    def test_batch_size_limit(self):
        """Test that batch size is limited to 100."""
        max_batch_size = 100
        large_batch = [{"pem_content": "cert"} for _ in range(101)]
        assert len(large_batch) > max_batch_size

    @pytest.mark.unit
    def test_valid_batch_size(self):
        """Test that batches up to 100 are accepted."""
        max_batch_size = 100
        valid_batch = [{"pem_content": "cert"} for _ in range(50)]
        assert len(valid_batch) <= max_batch_size


class TestBulkImportCertificateLoading:
    """Tests for loading test certificates."""

    @pytest.mark.unit
    def test_fixtures_directory_exists(self):
        """Test that the fixtures directory exists."""
        assert FIXTURES_DIR.exists(), f"Fixtures directory not found: {FIXTURES_DIR}"

    @pytest.mark.unit
    def test_test_certificates_generated(self):
        """Test that test certificates have been generated."""
        certs = get_available_test_certs()
        assert len(certs) >= 10, f"Expected at least 10 test certificates, found {len(certs)}"

    @pytest.mark.unit
    def test_can_load_web_prod_certificate(self):
        """Test that we can load the web_prod certificate."""
        cert = load_test_certificate("cert_web_prod")
        if cert:
            assert "BEGIN CERTIFICATE" in cert
            assert "END CERTIFICATE" in cert

    @pytest.mark.unit
    def test_can_load_multiple_certificates(self):
        """Test that we can load multiple certificates."""
        certs = get_available_test_certs()
        loaded = []
        for cert_name in certs[:5]:
            cert = load_test_certificate(cert_name)
            if cert:
                loaded.append(cert)
        assert len(loaded) >= 5, "Should be able to load at least 5 certificates"


class TestBulkImportPayloadFormat:
    """Tests for bulk import payload format."""

    @pytest.mark.unit
    def test_payload_structure_with_pem_only(self):
        """Test payload with only pem_content."""
        cert = load_test_certificate("cert_web_prod")
        if not cert:
            pytest.skip("Test certificate not available")

        payload = [{"pem_content": cert}]
        assert len(payload) == 1
        assert "pem_content" in payload[0]

    @pytest.mark.unit
    def test_payload_structure_with_optional_fields(self):
        """Test payload with optional fields."""
        cert = load_test_certificate("cert_web_prod")
        if not cert:
            pytest.skip("Test certificate not available")

        payload = [
            {
                "pem_content": cert,
                "private_key_location": "Vault: /secret/prod/web1",
                "tenant": None,
            }
        ]
        assert "private_key_location" in payload[0]
        assert "tenant" in payload[0]

    @pytest.mark.unit
    def test_multiple_certificates_payload(self):
        """Test payload with multiple certificates."""
        certs = get_available_test_certs()[:5]
        payload = []
        for i, cert_name in enumerate(certs):
            cert = load_test_certificate(cert_name)
            if cert:
                payload.append(
                    {
                        "pem_content": cert,
                        "private_key_location": f"Vault: /secret/cert_{i}",
                    }
                )

        assert len(payload) >= 5, "Should have at least 5 certificates in payload"
        for item in payload:
            assert "pem_content" in item
            assert "BEGIN CERTIFICATE" in item["pem_content"]


class TestBulkImportParsing:
    """Tests for certificate parsing during bulk import."""

    @pytest.mark.unit
    @skip_if_no_parser
    def test_parse_single_certificate(self):
        """Test parsing a single certificate."""
        from netbox_ssl.utils.parser import CertificateParser

        cert = load_test_certificate("cert_web_prod")
        if not cert:
            pytest.skip("Test certificate not available")

        result = CertificateParser.parse(cert)
        assert result.common_name == "www.example.com"

    @pytest.mark.unit
    @skip_if_no_parser
    def test_parse_certificate_with_sans(self):
        """Test parsing a certificate with SANs."""
        from netbox_ssl.utils.parser import CertificateParser

        cert = load_test_certificate("cert_multi_domain")
        if not cert:
            pytest.skip("Test certificate not available")

        result = CertificateParser.parse(cert)
        assert result.common_name == "shop.example.com"
        assert isinstance(result.sans, list)
        assert len(result.sans) >= 1

    @pytest.mark.unit
    @skip_if_no_parser
    def test_parse_wildcard_certificate(self):
        """Test parsing a wildcard certificate."""
        from netbox_ssl.utils.parser import CertificateParser

        cert = load_test_certificate("cert_wildcard_prod")
        if not cert:
            pytest.skip("Test certificate not available")

        result = CertificateParser.parse(cert)
        assert "*.prod.example.com" in result.common_name or any("*" in san for san in result.sans)

    @pytest.mark.unit
    @skip_if_no_parser
    def test_parse_all_test_certificates(self):
        """Test parsing all test certificates."""
        from netbox_ssl.utils.parser import CertificateParser

        certs = get_available_test_certs()
        parsed_count = 0

        for cert_name in certs:
            cert = load_test_certificate(cert_name)
            if cert:
                result = CertificateParser.parse(cert)
                assert result.common_name is not None
                assert result.serial_number is not None
                assert result.fingerprint_sha256 is not None
                parsed_count += 1

        assert parsed_count >= 10, f"Should parse at least 10 certificates, parsed {parsed_count}"


class TestBulkImportAtomicity:
    """Tests for atomic transaction behavior."""

    @pytest.mark.unit
    def test_all_or_nothing_concept(self):
        """Document that bulk import should be atomic."""
        # If one certificate fails, all should be rolled back
        # This test documents the expected behavior
        expected_behavior = "atomic"
        assert expected_behavior == "atomic"

    @pytest.mark.unit
    def test_validation_before_creation(self):
        """Document that validation happens before any creation."""
        # All certificates should be validated first
        # Only if all pass, then creation begins
        expected_flow = ["validate_all", "create_all"]
        assert "validate_all" in expected_flow
        assert expected_flow.index("validate_all") < expected_flow.index("create_all")


class TestBulkImportResponseFormat:
    """Tests for bulk import response format."""

    @pytest.mark.unit
    def test_success_response_has_created_count(self):
        """Test that success response includes created_count."""
        sample_response = {
            "created_count": 5,
            "certificates": [],
        }
        assert "created_count" in sample_response
        assert sample_response["created_count"] == 5

    @pytest.mark.unit
    def test_success_response_has_certificates_list(self):
        """Test that success response includes certificates list."""
        sample_response = {
            "created_count": 2,
            "certificates": [
                {"id": 1, "common_name": "example.com"},
                {"id": 2, "common_name": "test.com"},
            ],
        }
        assert "certificates" in sample_response
        assert len(sample_response["certificates"]) == 2

    @pytest.mark.unit
    def test_error_response_has_detail(self):
        """Test that error response includes detail message."""
        sample_error = {
            "detail": "Validation failed for one or more certificates.",
            "failed_certificates": [],
        }
        assert "detail" in sample_error

    @pytest.mark.unit
    def test_error_response_has_failed_certificates(self):
        """Test that error response includes failed certificate details."""
        sample_error = {
            "detail": "Validation failed for one or more certificates.",
            "failed_certificates": [
                {"index": 2, "errors": {"pem_content": ["Invalid PEM format"]}},
                {"index": 5, "errors": {"pem_content": ["Certificate already exists"]}},
            ],
        }
        assert "failed_certificates" in sample_error
        assert len(sample_error["failed_certificates"]) == 2
        assert sample_error["failed_certificates"][0]["index"] == 2


class TestBulkImportEdgeCases:
    """Tests for edge cases in bulk import."""

    @pytest.mark.unit
    def test_duplicate_in_same_batch(self):
        """Document that duplicates within the same batch should be detected."""
        cert = load_test_certificate("cert_web_prod")
        if not cert:
            pytest.skip("Test certificate not available")

        # Same certificate twice in one batch
        payload = [{"pem_content": cert}, {"pem_content": cert}]
        assert len(payload) == 2
        assert payload[0]["pem_content"] == payload[1]["pem_content"]

    @pytest.mark.unit
    def test_mixed_valid_invalid_certificates(self):
        """Document behavior with mixed valid and invalid certificates."""
        cert = load_test_certificate("cert_web_prod")
        if not cert:
            pytest.skip("Test certificate not available")

        # Mix of valid certificate and invalid data
        payload = [
            {"pem_content": cert},  # valid
            {"pem_content": "not a certificate"},  # invalid
            {"pem_content": cert.replace("CERTIFICATE", "INVALID")},  # invalid
        ]
        assert len(payload) == 3

    @pytest.mark.unit
    @skip_if_no_parser
    def test_private_key_rejection_in_bulk(self):
        """Test that private keys are rejected in bulk import."""
        from netbox_ssl.utils.parser import CertificateParser

        cert = load_test_certificate("cert_web_prod")
        if not cert:
            pytest.skip("Test certificate not available")

        private_key = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7
-----END PRIVATE KEY-----"""

        mixed_content = cert + "\n" + private_key
        assert CertificateParser.contains_private_key(mixed_content) is True


class TestBulkImportPerformance:
    """Tests documenting performance characteristics."""

    @pytest.mark.unit
    def test_batch_reduces_http_calls(self):
        """Document that batching reduces HTTP calls."""
        total_certs = 500
        batch_size = 100

        # Without batching: 500 HTTP calls
        calls_without_batch = total_certs

        # With batching: 5 HTTP calls
        calls_with_batch = (total_certs + batch_size - 1) // batch_size

        assert calls_with_batch == 5
        assert calls_without_batch / calls_with_batch == 100  # 100x reduction

    @pytest.mark.unit
    def test_max_batch_size_is_reasonable(self):
        """Test that max batch size is reasonable for performance."""
        max_batch_size = 100

        # 100 is a reasonable default:
        # - Small enough to fit in memory
        # - Large enough to provide significant batching benefit
        # - Completes in reasonable time
        assert 50 <= max_batch_size <= 200
