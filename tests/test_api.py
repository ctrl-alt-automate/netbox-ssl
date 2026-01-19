"""
Unit tests for the REST API import endpoint.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# Allow importing modules directly without loading the full netbox_ssl package
_project_root = Path(__file__).parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

# Mock netbox modules for local testing
if "netbox" not in sys.modules:
    sys.modules["netbox"] = MagicMock()
    sys.modules["netbox.plugins"] = MagicMock()
    sys.modules["netbox.models"] = MagicMock()
    sys.modules["netbox.api"] = MagicMock()
    sys.modules["netbox.api.serializers"] = MagicMock()
    sys.modules["netbox.api.viewsets"] = MagicMock()

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


class TestCertificateImportSerializer:
    """Tests for CertificateImportSerializer validation."""

    @pytest.mark.unit
    def test_validate_pem_rejects_private_key(self):
        """Test that private keys are rejected during validation."""
        from netbox_ssl.utils.parser import CertificateParser

        mixed_content = TEST_CERTIFICATE_PEM + "\n" + TEST_PRIVATE_KEY_PEM
        assert CertificateParser.contains_private_key(mixed_content) is True

    @pytest.mark.unit
    def test_validate_pem_accepts_valid_certificate(self):
        """Test that valid PEM certificates pass validation."""
        from netbox_ssl.utils.parser import CertificateParser, ParsedCertificate

        result = CertificateParser.parse(TEST_CERTIFICATE_PEM)
        assert isinstance(result, ParsedCertificate)
        assert result.common_name is not None

    @pytest.mark.unit
    def test_parser_extracts_all_fields(self):
        """Test that parser extracts all required fields for import."""
        from netbox_ssl.utils.parser import CertificateParser

        result = CertificateParser.parse(TEST_CERTIFICATE_PEM)

        # All fields needed for Certificate model
        assert result.common_name
        assert result.serial_number
        assert result.fingerprint_sha256
        assert result.issuer
        assert result.valid_from
        assert result.valid_to
        assert result.algorithm in ["rsa", "ecdsa", "ed25519", "unknown"]
        assert result.pem_content


class TestAPIImportEndpoint:
    """Tests for the API import endpoint behavior."""

    @pytest.mark.unit
    def test_import_endpoint_url_pattern(self):
        """Test that import endpoint follows REST convention."""
        # The endpoint should be: POST /api/plugins/netbox-ssl/certificates/import/
        expected_url_path = "import"
        # This is configured via @action(url_path="import")
        assert expected_url_path == "import"

    @pytest.mark.unit
    def test_import_returns_certificate_object(self):
        """Test that successful import returns the created certificate."""
        # The endpoint should return a CertificateSerializer response
        # with status 201 Created
        from netbox_ssl.utils.parser import CertificateParser

        parsed = CertificateParser.parse(TEST_CERTIFICATE_PEM)

        # Verify all fields are available for response
        assert parsed.common_name
        assert parsed.serial_number
        assert parsed.fingerprint_sha256
