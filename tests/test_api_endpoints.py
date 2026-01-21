"""
Integration tests for NetBox SSL plugin REST API endpoints.

These tests run against a live NetBox instance and verify that all API
endpoints work correctly. They test:
- CRUD operations for all models
- Custom actions (import, export, validate-chain, compliance-check, etc.)
- Error handling and validation
- Authentication and permissions

Run with: pytest tests/test_api_endpoints.py -v -m api

Requires:
- Running NetBox instance at http://localhost:8000
- NETBOX_TOKEN environment variable with valid API token (v2 format: nbt_xxx.yyy)
"""

import os
from pathlib import Path

import pytest
import requests

# Configuration
NETBOX_URL = os.environ.get("NETBOX_URL", "http://localhost:8000")
NETBOX_TOKEN = os.environ.get("NETBOX_TOKEN")  # Required: v2 token format nbt_xxx.yyy
API_BASE = f"{NETBOX_URL}/api/plugins/ssl"  # Note: 'ssl' not 'netbox-ssl'

# Test certificate PEM
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

# Test CSR PEM
TEST_CSR_PEM = """-----BEGIN CERTIFICATE REQUEST-----
MIICijCCAXICAQAwRTELMAkGA1UEBhMCTkwxEzARBgNVBAgMClNvbWUtU3RhdGUx
ITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBANGd1UuSSXHbN8X5/8oFshfD25xstAByUkAT5+Kj
GXwmy40/LxSSEsZSsjKwCRxsEo0C/xWVamME0dxTUvDlxxNDVSr/7GCdoAeKvCR6
+qpkMank/W1w+pZOwINFKQLB5iYMgtMWR2LmC3wRtY8Uf+aiyqQgYxtRb9CW0lOA
PG9RuekG/0hx0MfDWH+sOynW3+GzdI1h+55BuImCYR6Zgmzb/8/ExzUOY+/pKhct
I5GBSIRydwvLilQUzXA9zfBVT6tFhd7B0xys9TzB0hZJz30d6V1yitJN23gYui9X
DOzNwHlb8i7xnz7SeWgnP+KOEy2LLy0gz/MYScxH1n6pcqsCAwEAAaAAMA0GCSqG
SIb3DQEBCwUAA4IBAQBMHs7rCfIYRyPQjN9N+i5t5Qvt7lqg0Y8QqOqrL4fH3Y+4
q5xn5l0C6QfB7r5I9u+/+0q0yL5gP1CwP3N2l8d8Qu3L7HgN8Lp0J5T6V0d3VDB4
Pt9X/Y7wENqmHL1BMDZ1EtQgPl9U8N0g8M3MaPJ5PCRi/Y5xqe3J5M9V0dwzV5fS
N/Db1s8B3sDr9cPXqj4L8D9SaP8M8N3L3b0qOGn9LDt7JNZKt2F1Zp5K3pJQaM9E
Ny8J0xvxCP5p9X7vCZm7aDN0H7JoN7jLrM3qKZBCZv3Y0K1X5T9U9H+0nBeJ3D7k
HJF2qwG6kv3C0qRN7g5P0nL5L8N9ZXMN7P3vN8J8LNBO
-----END CERTIFICATE REQUEST-----"""


def _is_netbox_available():
    """Check if NetBox is available.

    Returns True if NetBox responds (200 or 403 - auth required but server is up).
    """
    try:
        resp = requests.get(f"{NETBOX_URL}/api/", timeout=5)
        # 200 = authenticated/public, 403 = auth required but server is responding
        return resp.status_code in (200, 403)
    except requests.exceptions.RequestException:
        return False


@pytest.fixture(scope="module")
def api_client():
    """Create an API client with authentication.

    For NetBox 4.5+, use v2 tokens with format: Bearer nbt_xxx.yyy
    Requires NETBOX_TOKEN environment variable to be set.
    """
    if not NETBOX_TOKEN:
        pytest.skip("NETBOX_TOKEN environment variable not set")

    if not _is_netbox_available():
        pytest.skip("NetBox not available at " + NETBOX_URL)

    session = requests.Session()
    # v2 tokens use "Bearer" prefix, v1 tokens use "Token" prefix
    auth_prefix = "Bearer" if NETBOX_TOKEN.startswith("nbt_") else "Token"
    session.headers.update(
        {
            "Authorization": f"{auth_prefix} {NETBOX_TOKEN}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
    )
    return session


@pytest.fixture
def test_certificate(api_client):
    """Create a test certificate for use in tests, cleanup after.

    This fixture creates a certificate via the import API and deletes it
    after the test completes, ensuring tests are self-contained.
    """
    # Import a test certificate
    resp = api_client.post(
        f"{API_BASE}/certificates/import/",
        json={
            "pem_content": TEST_CERTIFICATE_PEM,
            "private_key_location": "test-fixture",
        },
    )

    if resp.status_code != 201:
        pytest.skip(f"Could not create test certificate: {resp.text}")

    cert_data = resp.json()
    cert_id = cert_data["id"]

    yield cert_data

    # Cleanup: delete the certificate
    api_client.delete(f"{API_BASE}/certificates/{cert_id}/")


@pytest.fixture
def test_compliance_policy(api_client):
    """Create a test compliance policy for use in tests, cleanup after."""
    policy_data = {
        "name": f"Test Policy {os.urandom(4).hex()}",
        "enabled": True,
        "min_key_size": 2048,
        "allowed_algorithms": ["rsa", "ecdsa"],
    }

    resp = api_client.post(f"{API_BASE}/compliance-policies/", json=policy_data)

    if resp.status_code != 201:
        pytest.skip(f"Could not create test policy: {resp.text}")

    policy = resp.json()
    policy_id = policy["id"]

    yield policy

    # Cleanup
    api_client.delete(f"{API_BASE}/compliance-policies/{policy_id}/")


# =============================================================================
# Certificate Authority API Tests
# =============================================================================


class TestCertificateAuthorityAPI:
    """Tests for Certificate Authority API endpoints."""

    @pytest.mark.api
    def test_list_certificate_authorities(self, api_client):
        """Test GET /certificate-authorities/ returns list."""

        resp = api_client.get(f"{API_BASE}/certificate-authorities/")
        assert resp.status_code == 200
        data = resp.json()
        assert "results" in data
        assert "count" in data
        assert isinstance(data["results"], list)

    @pytest.mark.api
    def test_create_certificate_authority(self, api_client):
        """Test POST /certificate-authorities/ creates a new CA."""

        ca_data = {
            "name": f"Test CA API {os.urandom(4).hex()}",
            "type": "internal",
            "description": "Created by API test",
            "is_approved": True,
            "issuer_pattern": "test-ca-pattern",
        }

        resp = api_client.post(f"{API_BASE}/certificate-authorities/", json=ca_data)
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == ca_data["name"]
        assert data["type"] == ca_data["type"]
        assert data["is_approved"] is True

        # Cleanup
        ca_id = data["id"]
        api_client.delete(f"{API_BASE}/certificate-authorities/{ca_id}/")

    @pytest.mark.api
    def test_retrieve_certificate_authority(self, api_client):
        """Test GET /certificate-authorities/{id}/ returns CA details."""

        # First create a CA
        ca_data = {"name": f"Test CA Retrieve {os.urandom(4).hex()}", "type": "public"}
        create_resp = api_client.post(f"{API_BASE}/certificate-authorities/", json=ca_data)
        assert create_resp.status_code == 201
        ca_id = create_resp.json()["id"]

        # Retrieve it
        resp = api_client.get(f"{API_BASE}/certificate-authorities/{ca_id}/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == ca_id
        assert data["name"] == ca_data["name"]

        # Cleanup
        api_client.delete(f"{API_BASE}/certificate-authorities/{ca_id}/")

    @pytest.mark.api
    def test_update_certificate_authority(self, api_client):
        """Test PUT /certificate-authorities/{id}/ updates CA."""

        # Create CA
        ca_data = {"name": f"Test CA Update {os.urandom(4).hex()}", "type": "internal"}
        create_resp = api_client.post(f"{API_BASE}/certificate-authorities/", json=ca_data)
        ca_id = create_resp.json()["id"]

        # Update it
        update_data = {
            "name": ca_data["name"],
            "type": "public",
            "description": "Updated description",
        }
        resp = api_client.put(f"{API_BASE}/certificate-authorities/{ca_id}/", json=update_data)
        assert resp.status_code == 200
        data = resp.json()
        assert data["type"] == "public"
        assert data["description"] == "Updated description"

        # Cleanup
        api_client.delete(f"{API_BASE}/certificate-authorities/{ca_id}/")

    @pytest.mark.api
    def test_delete_certificate_authority(self, api_client):
        """Test DELETE /certificate-authorities/{id}/ deletes CA."""

        # Create CA
        ca_data = {"name": f"Test CA Delete {os.urandom(4).hex()}", "type": "acme"}
        create_resp = api_client.post(f"{API_BASE}/certificate-authorities/", json=ca_data)
        ca_id = create_resp.json()["id"]

        # Delete it
        resp = api_client.delete(f"{API_BASE}/certificate-authorities/{ca_id}/")
        assert resp.status_code == 204

        # Verify it's gone
        resp = api_client.get(f"{API_BASE}/certificate-authorities/{ca_id}/")
        assert resp.status_code == 404

    @pytest.mark.api
    def test_certificate_authority_not_found(self, api_client):
        """Test GET /certificate-authorities/{id}/ returns 404 for non-existent CA."""

        resp = api_client.get(f"{API_BASE}/certificate-authorities/99999/")
        assert resp.status_code == 404


# =============================================================================
# Certificate API Tests
# =============================================================================


class TestCertificateAPI:
    """Tests for Certificate API endpoints."""

    @pytest.mark.api
    def test_list_certificates(self, api_client):
        """Test GET /certificates/ returns list."""

        resp = api_client.get(f"{API_BASE}/certificates/")
        assert resp.status_code == 200
        data = resp.json()
        assert "results" in data
        assert "count" in data

    @pytest.mark.api
    def test_import_certificate(self, api_client):
        """Test POST /certificates/import/ imports a PEM certificate."""

        import_data = {
            "pem_content": TEST_CERTIFICATE_PEM,
            "private_key_location": "Test vault location",
        }

        resp = api_client.post(f"{API_BASE}/certificates/import/", json=import_data)

        # Could be 201 (created) or 400 (duplicate)
        if resp.status_code == 201:
            data = resp.json()
            assert "common_name" in data
            assert "serial_number" in data
            # Cleanup
            api_client.delete(f"{API_BASE}/certificates/{data['id']}/")
        else:
            # Duplicate certificate - that's OK
            assert resp.status_code == 400

    @pytest.mark.api
    def test_import_certificate_rejects_private_key(self, api_client):
        """Test POST /certificates/import/ rejects PEM with private key."""

        pem_with_key = (
            TEST_CERTIFICATE_PEM
            + "\n-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0B\n-----END PRIVATE KEY-----"
        )
        import_data = {"pem_content": pem_with_key}

        resp = api_client.post(f"{API_BASE}/certificates/import/", json=import_data)
        assert resp.status_code == 400
        assert "private key" in resp.text.lower() or "Private key" in resp.text

    @pytest.mark.api
    def test_bulk_import_certificates(self, api_client):
        """Test POST /certificates/bulk-import/ imports multiple certificates."""

        # Load real certificates
        fixtures_dir = Path(__file__).parent / "fixtures" / "real_world"
        if not fixtures_dir.exists():
            pytest.skip("Real certificate fixtures not available")

        certs = []
        for pem_file in fixtures_dir.glob("*_leaf.pem"):
            certs.append({"pem_content": pem_file.read_text()})

        if not certs:
            pytest.skip("No certificate fixtures found")

        resp = api_client.post(f"{API_BASE}/certificates/bulk-import/", json=certs)

        # Could be 201 (created) or 400 (some duplicates)
        assert resp.status_code in [201, 400]

    @pytest.mark.api
    def test_bulk_import_empty_list(self, api_client):
        """Test POST /certificates/bulk-import/ rejects empty list."""

        resp = api_client.post(f"{API_BASE}/certificates/bulk-import/", json=[])
        assert resp.status_code == 400
        assert "empty" in resp.text.lower() or "required" in resp.text.lower()

    @pytest.mark.api
    def test_bulk_import_not_list(self, api_client):
        """Test POST /certificates/bulk-import/ rejects non-list input."""

        resp = api_client.post(f"{API_BASE}/certificates/bulk-import/", json={"pem_content": "test"})
        assert resp.status_code == 400

    @pytest.mark.api
    def test_retrieve_certificate(self, api_client, test_certificate):
        """Test GET /certificates/{id}/ returns certificate details."""
        cert_id = test_certificate["id"]

        resp = api_client.get(f"{API_BASE}/certificates/{cert_id}/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == cert_id
        assert "common_name" in data
        assert "serial_number" in data
        assert "valid_from" in data
        assert "valid_to" in data

    @pytest.mark.api
    def test_certificate_not_found(self, api_client):
        """Test GET /certificates/{id}/ returns 404 for non-existent certificate."""

        resp = api_client.get(f"{API_BASE}/certificates/99999/")
        assert resp.status_code == 404


# =============================================================================
# Certificate Chain Validation API Tests
# =============================================================================


class TestCertificateChainValidationAPI:
    """Tests for certificate chain validation API endpoints."""

    @pytest.mark.api
    def test_validate_chain_single(self, api_client, test_certificate):
        """Test POST /certificates/{id}/validate-chain/ validates chain."""
        cert_id = test_certificate["id"]

        resp = api_client.post(f"{API_BASE}/certificates/{cert_id}/validate-chain/")
        assert resp.status_code == 200
        data = resp.json()
        assert "status" in data
        assert "is_valid" in data
        assert "message" in data

    @pytest.mark.api
    def test_bulk_validate_chain(self, api_client, test_certificate):
        """Test POST /certificates/bulk-validate-chain/ validates multiple chains."""
        cert_ids = [test_certificate["id"]]

        resp = api_client.post(f"{API_BASE}/certificates/bulk-validate-chain/", json={"ids": cert_ids})
        assert resp.status_code == 200
        data = resp.json()
        assert "validated_count" in data
        assert "valid_count" in data
        assert "invalid_count" in data
        assert "results" in data
        assert len(data["results"]) == len(cert_ids)

    @pytest.mark.api
    def test_bulk_validate_chain_empty_ids(self, api_client):
        """Test POST /certificates/bulk-validate-chain/ rejects empty IDs."""

        resp = api_client.post(f"{API_BASE}/certificates/bulk-validate-chain/", json={"ids": []})
        assert resp.status_code == 400

    @pytest.mark.api
    def test_bulk_validate_chain_no_ids(self, api_client):
        """Test POST /certificates/bulk-validate-chain/ rejects missing IDs."""

        resp = api_client.post(f"{API_BASE}/certificates/bulk-validate-chain/", json={})
        assert resp.status_code == 400


# =============================================================================
# Certificate Compliance API Tests
# =============================================================================


class TestCertificateComplianceAPI:
    """Tests for certificate compliance API endpoints."""

    @pytest.mark.api
    def test_compliance_check_single(self, api_client, test_certificate):
        """Test POST /certificates/{id}/compliance-check/ runs compliance check."""
        cert_id = test_certificate["id"]

        resp = api_client.post(f"{API_BASE}/certificates/{cert_id}/compliance-check/", json={})
        assert resp.status_code == 200
        data = resp.json()
        assert "certificate_id" in data
        assert "total_checks" in data
        assert "passed" in data
        assert "failed" in data
        assert "compliance_score" in data

    @pytest.mark.api
    def test_bulk_compliance_check(self, api_client, test_certificate):
        """Test POST /certificates/bulk-compliance-check/ runs bulk compliance."""
        cert_ids = [test_certificate["id"]]

        resp = api_client.post(
            f"{API_BASE}/certificates/bulk-compliance-check/", json={"certificate_ids": cert_ids}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "total_certificates" in data
        assert "processed" in data
        assert "overall_passed" in data
        assert "overall_failed" in data
        assert "reports" in data

    @pytest.mark.api
    def test_bulk_compliance_check_with_policies(self, api_client, test_certificate, test_compliance_policy):
        """Test bulk compliance check with specific policy IDs."""
        cert_ids = [test_certificate["id"]]
        policy_ids = [test_compliance_policy["id"]]

        payload = {"certificate_ids": cert_ids, "policy_ids": policy_ids}

        resp = api_client.post(f"{API_BASE}/certificates/bulk-compliance-check/", json=payload)
        assert resp.status_code == 200


# =============================================================================
# Certificate Export API Tests
# =============================================================================


class TestCertificateExportAPI:
    """Tests for certificate export API endpoints."""

    @pytest.mark.api
    def test_export_certificates_json(self, api_client):
        """Test GET /certificates/export/?format=json exports as JSON."""

        resp = api_client.get(f"{API_BASE}/certificates/export/?format=json")
        assert resp.status_code == 200
        assert "application/json" in resp.headers.get("Content-Type", "")

    @pytest.mark.api
    def test_export_certificates_csv(self, api_client):
        """Test POST /certificates/export/ with format=csv exports as CSV.

        Note: Must use POST because DRF intercepts GET ?format=xxx for content negotiation.
        """

        resp = api_client.post(f"{API_BASE}/certificates/export/", json={"format": "csv"})
        assert resp.status_code == 200
        assert "text/csv" in resp.headers.get("Content-Type", "")

    @pytest.mark.api
    def test_export_certificates_pem(self, api_client):
        """Test POST /certificates/export/ with format=pem exports as PEM.

        Note: Must use POST because DRF intercepts GET ?format=xxx for content negotiation.
        """

        resp = api_client.post(f"{API_BASE}/certificates/export/", json={"format": "pem"})
        assert resp.status_code == 200
        assert "application/x-pem-file" in resp.headers.get("Content-Type", "")

    @pytest.mark.api
    def test_export_single_certificate(self, api_client, test_certificate):
        """Test GET /certificates/{id}/export/ exports single certificate."""
        cert_id = test_certificate["id"]

        resp = api_client.get(f"{API_BASE}/certificates/{cert_id}/export/?format=json")
        assert resp.status_code == 200

    @pytest.mark.api
    def test_export_invalid_format(self, api_client):
        """Test export with invalid format returns error.

        Note: Must use POST because DRF intercepts GET ?format=xxx for content negotiation.
        """

        resp = api_client.post(f"{API_BASE}/certificates/export/", json={"format": "invalid"})
        assert resp.status_code == 400


# =============================================================================
# Certificate Assignment API Tests
# =============================================================================


class TestCertificateAssignmentAPI:
    """Tests for Certificate Assignment API endpoints."""

    @pytest.mark.api
    def test_list_assignments(self, api_client):
        """Test GET /assignments/ returns list."""

        resp = api_client.get(f"{API_BASE}/assignments/")
        assert resp.status_code == 200
        data = resp.json()
        assert "results" in data
        assert "count" in data

    @pytest.mark.api
    def test_assignment_not_found(self, api_client):
        """Test GET /assignments/{id}/ returns 404 for non-existent assignment."""

        resp = api_client.get(f"{API_BASE}/assignments/99999/")
        assert resp.status_code == 404


# =============================================================================
# CSR API Tests
# =============================================================================


class TestCSRAPI:
    """Tests for Certificate Signing Request API endpoints."""

    @pytest.mark.api
    def test_list_csrs(self, api_client):
        """Test GET /csrs/ returns list."""

        resp = api_client.get(f"{API_BASE}/csrs/")
        assert resp.status_code == 200
        data = resp.json()
        assert "results" in data
        assert "count" in data

    @pytest.mark.api
    def test_csr_not_found(self, api_client):
        """Test GET /csrs/{id}/ returns 404 for non-existent CSR."""

        resp = api_client.get(f"{API_BASE}/csrs/99999/")
        assert resp.status_code == 404


# =============================================================================
# Compliance Policy API Tests
# =============================================================================


class TestCompliancePolicyAPI:
    """Tests for Compliance Policy API endpoints."""

    @pytest.mark.api
    def test_list_compliance_policies(self, api_client):
        """Test GET /compliance-policies/ returns list."""

        resp = api_client.get(f"{API_BASE}/compliance-policies/")
        assert resp.status_code == 200
        data = resp.json()
        assert "results" in data
        assert "count" in data

    @pytest.mark.api
    def test_create_compliance_policy(self, api_client):
        """Test POST /compliance-policies/ creates a new policy."""

        policy_data = {
            "name": f"Test Policy {os.urandom(4).hex()}",
            "policy_type": "min_key_size",
            "severity": "warning",
            "enabled": True,
            "parameters": {"min_bits": 2048},
        }

        resp = api_client.post(f"{API_BASE}/compliance-policies/", json=policy_data)
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == policy_data["name"]
        assert data["policy_type"] == policy_data["policy_type"]

        # Cleanup
        api_client.delete(f"{API_BASE}/compliance-policies/{data['id']}/")

    @pytest.mark.api
    def test_retrieve_compliance_policy(self, api_client):
        """Test GET /compliance-policies/{id}/ returns policy details."""

        # Create a policy
        policy_data = {
            "name": f"Test Policy Retrieve {os.urandom(4).hex()}",
            "policy_type": "max_validity_days",
            "severity": "critical",
            "parameters": {"max_days": 365},
        }
        create_resp = api_client.post(f"{API_BASE}/compliance-policies/", json=policy_data)
        policy_id = create_resp.json()["id"]

        # Retrieve it
        resp = api_client.get(f"{API_BASE}/compliance-policies/{policy_id}/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == policy_id

        # Cleanup
        api_client.delete(f"{API_BASE}/compliance-policies/{policy_id}/")

    @pytest.mark.api
    def test_update_compliance_policy(self, api_client):
        """Test PUT /compliance-policies/{id}/ updates policy."""

        # Create policy
        policy_data = {
            "name": f"Test Policy Update {os.urandom(4).hex()}",
            "policy_type": "min_key_size",
            "severity": "info",
            "parameters": {"min_bits": 1024},
        }
        create_resp = api_client.post(f"{API_BASE}/compliance-policies/", json=policy_data)
        policy_id = create_resp.json()["id"]

        # Update it
        update_data = {
            "name": policy_data["name"],
            "policy_type": "min_key_size",
            "severity": "critical",
            "parameters": {"min_bits": 4096},
        }
        resp = api_client.put(f"{API_BASE}/compliance-policies/{policy_id}/", json=update_data)
        assert resp.status_code == 200
        data = resp.json()
        assert data["severity"] == "critical"

        # Cleanup
        api_client.delete(f"{API_BASE}/compliance-policies/{policy_id}/")

    @pytest.mark.api
    def test_delete_compliance_policy(self, api_client):
        """Test DELETE /compliance-policies/{id}/ deletes policy."""

        # Create policy
        policy_data = {
            "name": f"Test Policy Delete {os.urandom(4).hex()}",
            "policy_type": "chain_required",
            "severity": "warning",
            "parameters": {},
        }
        create_resp = api_client.post(f"{API_BASE}/compliance-policies/", json=policy_data)
        policy_id = create_resp.json()["id"]

        # Delete it
        resp = api_client.delete(f"{API_BASE}/compliance-policies/{policy_id}/")
        assert resp.status_code == 204

        # Verify it's gone
        resp = api_client.get(f"{API_BASE}/compliance-policies/{policy_id}/")
        assert resp.status_code == 404

    @pytest.mark.api
    def test_compliance_policy_not_found(self, api_client):
        """Test GET /compliance-policies/{id}/ returns 404 for non-existent policy."""

        resp = api_client.get(f"{API_BASE}/compliance-policies/99999/")
        assert resp.status_code == 404


# =============================================================================
# Compliance Check API Tests
# =============================================================================


class TestComplianceCheckAPI:
    """Tests for Compliance Check API endpoints."""

    @pytest.mark.api
    def test_list_compliance_checks(self, api_client):
        """Test GET /compliance-checks/ returns list."""

        resp = api_client.get(f"{API_BASE}/compliance-checks/")
        assert resp.status_code == 200
        data = resp.json()
        assert "results" in data
        assert "count" in data

    @pytest.mark.api
    def test_compliance_check_not_found(self, api_client):
        """Test GET /compliance-checks/{id}/ returns 404 for non-existent check."""

        resp = api_client.get(f"{API_BASE}/compliance-checks/99999/")
        assert resp.status_code == 404


# =============================================================================
# Authentication Tests
# =============================================================================


class TestAPIAuthentication:
    """Tests for API authentication."""

    @pytest.mark.api
    def test_unauthenticated_request_rejected(self):
        """Test that requests without authentication are rejected."""

        resp = requests.get(f"{API_BASE}/certificates/")
        # Should be 403 Forbidden or 401 Unauthorized
        assert resp.status_code in [401, 403]

    @pytest.mark.api
    def test_invalid_token_rejected(self):
        """Test that requests with invalid token are rejected."""

        headers = {"Authorization": "Token invalid_token_12345"}
        resp = requests.get(f"{API_BASE}/certificates/", headers=headers)
        assert resp.status_code in [401, 403]
