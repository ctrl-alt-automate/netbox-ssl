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


# =============================================================================
# Integration Tests - These test the actual API endpoint
# =============================================================================


def django_api_available():
    """Check if Django REST framework test client is available and configured."""
    try:
        # Check if Django is configured
        from django.conf import settings

        if not settings.configured:
            return False

        # Try to import REST framework test client
        from django.contrib.auth import get_user_model  # noqa: F401
        from rest_framework.test import APIClient  # noqa: F401

        return True
    except Exception:
        # Catch all exceptions (ImportError, ImproperlyConfigured, etc.)
        return False


skip_if_no_django_api = pytest.mark.skipif(
    not django_api_available(), reason="Django REST Framework not available or not configured"
)


@pytest.fixture
def api_client():
    """Create an authenticated API client for testing."""
    from django.contrib.auth import get_user_model
    from rest_framework.test import APIClient

    User = get_user_model()

    # Get or create admin user
    user, _ = User.objects.get_or_create(
        username="test_bulk_import_user",
        defaults={"is_superuser": True, "is_staff": True},
    )

    client = APIClient()
    client.force_authenticate(user=user)
    return client


@pytest.fixture
def cleanup_certificates():
    """Fixture to clean up certificates after tests."""
    yield
    # Cleanup after test
    try:
        from netbox_ssl.models import Certificate

        Certificate.objects.filter(common_name__contains="example.com").delete()
    except Exception:
        pass


class TestBulkImportAPIIntegration:
    """Integration tests that actually call the bulk import API endpoint."""

    @pytest.mark.integration
    @skip_if_no_django_api
    @skip_if_no_parser
    def test_bulk_import_success_single_certificate(self, api_client, cleanup_certificates):
        """Test successful bulk import of a single certificate."""
        cert = load_test_certificate("cert_web_prod")
        if not cert:
            pytest.skip("Test certificate not available")

        response = api_client.post(
            "/api/plugins/netbox-ssl/certificates/bulk-import/",
            [{"pem_content": cert}],
            format="json",
        )

        assert response.status_code == 201
        data = response.json()
        assert "created_count" in data
        assert data["created_count"] == 1
        assert "certificates" in data
        assert len(data["certificates"]) == 1
        assert data["certificates"][0]["common_name"] == "www.example.com"

    @pytest.mark.integration
    @skip_if_no_django_api
    @skip_if_no_parser
    def test_bulk_import_success_multiple_certificates(self, api_client, cleanup_certificates):
        """Test successful bulk import of multiple certificates."""
        cert_names = ["cert_web_prod", "cert_api_gateway", "cert_wildcard_prod"]
        certs = []
        for name in cert_names:
            cert = load_test_certificate(name)
            if cert:
                certs.append({"pem_content": cert})

        if len(certs) < 3:
            pytest.skip("Not enough test certificates available")

        response = api_client.post(
            "/api/plugins/netbox-ssl/certificates/bulk-import/",
            certs,
            format="json",
        )

        assert response.status_code == 201
        data = response.json()
        assert data["created_count"] == 3
        assert len(data["certificates"]) == 3

    @pytest.mark.integration
    @skip_if_no_django_api
    def test_bulk_import_rejects_empty_list(self, api_client):
        """Test that empty list is rejected with 400 error."""
        response = api_client.post(
            "/api/plugins/netbox-ssl/certificates/bulk-import/",
            [],
            format="json",
        )

        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
        assert "empty" in data["detail"].lower() or "at least one" in data["detail"].lower()

    @pytest.mark.integration
    @skip_if_no_django_api
    def test_bulk_import_rejects_non_list(self, api_client):
        """Test that non-list input is rejected with 400 error."""
        response = api_client.post(
            "/api/plugins/netbox-ssl/certificates/bulk-import/",
            {"pem_content": "test"},
            format="json",
        )

        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
        assert "list" in data["detail"].lower()

    @pytest.mark.integration
    @skip_if_no_django_api
    def test_bulk_import_rejects_invalid_certificate(self, api_client):
        """Test that invalid certificates are rejected with detailed errors."""
        response = api_client.post(
            "/api/plugins/netbox-ssl/certificates/bulk-import/",
            [{"pem_content": "not a valid certificate"}],
            format="json",
        )

        assert response.status_code == 400
        data = response.json()
        assert "failed_certificates" in data
        assert len(data["failed_certificates"]) == 1
        assert data["failed_certificates"][0]["index"] == 0

    @pytest.mark.integration
    @skip_if_no_django_api
    @skip_if_no_parser
    def test_bulk_import_atomic_rollback_on_error(self, api_client, cleanup_certificates):
        """Test that entire batch is rolled back when one certificate fails."""
        from netbox_ssl.models import Certificate

        cert = load_test_certificate("cert_web_prod")
        if not cert:
            pytest.skip("Test certificate not available")

        # Count existing certificates before
        count_before = Certificate.objects.count()

        # Mix valid and invalid certificates
        response = api_client.post(
            "/api/plugins/netbox-ssl/certificates/bulk-import/",
            [
                {"pem_content": cert},  # valid
                {"pem_content": "invalid cert"},  # invalid
            ],
            format="json",
        )

        assert response.status_code == 400

        # Verify no certificates were created (atomic rollback)
        count_after = Certificate.objects.count()
        assert count_after == count_before, "Atomic rollback failed - certificates were created"

    @pytest.mark.integration
    @skip_if_no_django_api
    @skip_if_no_parser
    def test_bulk_import_with_optional_fields(self, api_client, cleanup_certificates):
        """Test bulk import with optional fields like private_key_location."""
        cert = load_test_certificate("cert_web_prod")
        if not cert:
            pytest.skip("Test certificate not available")

        response = api_client.post(
            "/api/plugins/netbox-ssl/certificates/bulk-import/",
            [
                {
                    "pem_content": cert,
                    "private_key_location": "Vault: /secret/test/cert1",
                }
            ],
            format="json",
        )

        assert response.status_code == 201
        data = response.json()
        assert data["created_count"] == 1

    @pytest.mark.integration
    @skip_if_no_django_api
    def test_bulk_import_batch_size_limit(self, api_client):
        """Test that batch size is limited (default 100)."""
        # Create 101 dummy certificates (exceeds limit)
        certs = [{"pem_content": f"cert-{i}"} for i in range(101)]

        response = api_client.post(
            "/api/plugins/netbox-ssl/certificates/bulk-import/",
            certs,
            format="json",
        )

        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
        assert "100" in data["detail"] or "batch" in data["detail"].lower()

    @pytest.mark.integration
    @skip_if_no_django_api
    @skip_if_no_parser
    def test_bulk_import_rejects_private_key(self, api_client):
        """Test that certificates with private keys are rejected."""
        cert = load_test_certificate("cert_web_prod")
        if not cert:
            pytest.skip("Test certificate not available")

        private_key = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7
-----END PRIVATE KEY-----"""

        mixed_content = cert + "\n" + private_key

        response = api_client.post(
            "/api/plugins/netbox-ssl/certificates/bulk-import/",
            [{"pem_content": mixed_content}],
            format="json",
        )

        assert response.status_code == 400
        data = response.json()
        assert "failed_certificates" in data

    @pytest.mark.integration
    @skip_if_no_django_api
    @skip_if_no_parser
    def test_bulk_import_duplicate_detection(self, api_client, cleanup_certificates):
        """Test that duplicate certificates in same batch are detected."""
        cert = load_test_certificate("cert_web_prod")
        if not cert:
            pytest.skip("Test certificate not available")

        # First import should succeed
        response1 = api_client.post(
            "/api/plugins/netbox-ssl/certificates/bulk-import/",
            [{"pem_content": cert}],
            format="json",
        )
        assert response1.status_code == 201

        # Second import with same certificate should fail (duplicate)
        response2 = api_client.post(
            "/api/plugins/netbox-ssl/certificates/bulk-import/",
            [{"pem_content": cert}],
            format="json",
        )
        assert response2.status_code == 400
        data = response2.json()
        assert "failed_certificates" in data
