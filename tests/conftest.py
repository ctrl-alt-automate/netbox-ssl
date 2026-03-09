"""
Pytest configuration and fixtures for NetBox SSL plugin tests.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta

import pytest
import requests

# Try to import Django - not needed for browser tests
try:
    from django.utils import timezone

    DJANGO_AVAILABLE = True
except ImportError:
    DJANGO_AVAILABLE = False
    # Provide a fallback for non-Django tests
    from datetime import timezone as dt_timezone

    class timezone:
        @staticmethod
        def now():
            return datetime.now(dt_timezone.utc)


# Sample PEM certificate for testing
SAMPLE_PEM_CERTIFICATE = """-----BEGIN CERTIFICATE-----
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


@pytest.fixture
def sample_pem():
    """Return a sample PEM certificate for testing."""
    return SAMPLE_PEM_CERTIFICATE


@pytest.fixture
def certificate_data():
    """Return sample certificate data for creating test certificates."""
    now = timezone.now()
    return {
        "common_name": "test.example.com",
        "serial_number": "01:23:45:67:89:AB:CD:EF",
        "fingerprint_sha256": "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:"
        "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99",
        "issuer": "CN=Test CA, O=Test Organization, C=NL",
        "valid_from": now - timedelta(days=30),
        "valid_to": now + timedelta(days=335),
        "algorithm": "rsa",
        "key_size": 2048,
        "status": "active",
        "sans": ["test.example.com", "www.test.example.com"],
    }


@pytest.fixture
def expired_certificate_data(certificate_data):
    """Return certificate data for an expired certificate."""
    now = timezone.now()
    data = certificate_data.copy()
    data.update(
        {
            "common_name": "expired.example.com",
            "fingerprint_sha256": "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:"
            "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00",
            "valid_from": now - timedelta(days=400),
            "valid_to": now - timedelta(days=35),
            "status": "expired",
        }
    )
    return data


@pytest.fixture
def expiring_soon_certificate_data(certificate_data):
    """Return certificate data for a certificate expiring within 14 days."""
    now = timezone.now()
    data = certificate_data.copy()
    data.update(
        {
            "common_name": "expiring-soon.example.com",
            "fingerprint_sha256": "22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:"
            "22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11",
            "valid_from": now - timedelta(days=351),
            "valid_to": now + timedelta(days=10),
        }
    )
    return data


# Browser test configuration
NETBOX_BASE_URL = "http://localhost:8000"
NETBOX_USERNAME = "admin"
NETBOX_PASSWORD = "admin"


@pytest.fixture
def netbox_credentials():
    """Return NetBox test credentials."""
    return {
        "base_url": NETBOX_BASE_URL,
        "username": NETBOX_USERNAME,
        "password": NETBOX_PASSWORD,
    }


# ---------------------------------------------------------------------------
# NetBox REST API helper for E2E test fixture setup/teardown
# ---------------------------------------------------------------------------

NETBOX_TOKEN = os.environ.get("NETBOX_TOKEN")


class NetBoxAPI:
    """Thin wrapper around requests for NetBox REST API calls.

    Used by E2E test fixtures to create and clean up test data.
    """

    def __init__(self, base_url: str, token: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        auth_prefix = "Bearer" if token.startswith("nbt_") else "Token"
        self.session.headers.update(
            {
                "Authorization": f"{auth_prefix} {token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )

    # -- helpers --

    def _post(self, path: str, json: dict) -> dict:
        resp = self.session.post(f"{self.base_url}{path}", json=json)
        resp.raise_for_status()
        return resp.json()

    def _get(self, path: str) -> dict:
        resp = self.session.get(f"{self.base_url}{path}")
        resp.raise_for_status()
        return resp.json()

    def _delete(self, path: str) -> None:
        resp = self.session.delete(f"{self.base_url}{path}")
        # 204 = deleted, 404 = already gone — both are fine
        if resp.status_code not in (204, 404):
            resp.raise_for_status()

    # -- certificates --

    def import_certificate(self, pem: str, private_key_location: str = "") -> dict:
        """Import a certificate via PEM content."""
        return self._post(
            "/api/plugins/ssl/certificates/import/",
            {"pem_content": pem, "private_key_location": private_key_location},
        )

    def get_certificate(self, pk: int) -> dict:
        """Get certificate details by ID."""
        return self._get(f"/api/plugins/ssl/certificates/{pk}/")

    def delete_certificate(self, pk: int) -> None:
        """Delete a certificate by ID."""
        self._delete(f"/api/plugins/ssl/certificates/{pk}/")

    # -- assignments --

    def create_assignment(
        self,
        certificate_id: int,
        assigned_object_type: str,
        assigned_object_id: int,
        is_primary: bool = True,
        notes: str = "",
    ) -> dict:
        """Create a certificate assignment."""
        return self._post(
            "/api/plugins/ssl/assignments/",
            {
                "certificate": certificate_id,
                "assigned_object_type": assigned_object_type,
                "assigned_object_id": assigned_object_id,
                "is_primary": is_primary,
                "notes": notes,
            },
        )

    def delete_assignment(self, pk: int) -> None:
        """Delete an assignment by ID."""
        self._delete(f"/api/plugins/ssl/assignments/{pk}/")

    # -- infrastructure (DCIM / IPAM) --

    def create_site(self, name: str, slug: str) -> dict:
        """Create a DCIM site."""
        return self._post("/api/dcim/sites/", {"name": name, "slug": slug})

    def delete_site(self, pk: int) -> None:
        self._delete(f"/api/dcim/sites/{pk}/")

    def create_manufacturer(self, name: str, slug: str) -> dict:
        """Create a DCIM manufacturer."""
        return self._post("/api/dcim/manufacturers/", {"name": name, "slug": slug})

    def delete_manufacturer(self, pk: int) -> None:
        self._delete(f"/api/dcim/manufacturers/{pk}/")

    def create_device_type(self, manufacturer_id: int, model: str, slug: str) -> dict:
        """Create a DCIM device type."""
        return self._post(
            "/api/dcim/device-types/",
            {"manufacturer": manufacturer_id, "model": model, "slug": slug},
        )

    def delete_device_type(self, pk: int) -> None:
        self._delete(f"/api/dcim/device-types/{pk}/")

    def create_device_role(self, name: str, slug: str) -> dict:
        """Create a DCIM device role."""
        return self._post("/api/dcim/device-roles/", {"name": name, "slug": slug})

    def delete_device_role(self, pk: int) -> None:
        self._delete(f"/api/dcim/device-roles/{pk}/")

    def create_device(
        self,
        name: str,
        site_id: int,
        role_id: int,
        device_type_id: int,
    ) -> dict:
        """Create a DCIM device."""
        return self._post(
            "/api/dcim/devices/",
            {
                "name": name,
                "site": site_id,
                "role": role_id,
                "device_type": device_type_id,
            },
        )

    def delete_device(self, pk: int) -> None:
        self._delete(f"/api/dcim/devices/{pk}/")

    def create_service(
        self,
        name: str,
        device_id: int,
        ports: list[int],
        protocol: str = "tcp",
    ) -> dict:
        """Create an IPAM service on a device.

        NetBox 4.5 uses parent_object_type/parent_object_id instead of device.
        """
        return self._post(
            "/api/ipam/services/",
            {
                "name": name,
                "parent_object_type": "dcim.device",
                "parent_object_id": device_id,
                "ports": ports,
                "protocol": protocol,
            },
        )

    def delete_service(self, pk: int) -> None:
        self._delete(f"/api/ipam/services/{pk}/")


def _is_netbox_api_available() -> bool:
    """Check if NetBox API is reachable."""
    try:
        resp = requests.get(f"{NETBOX_BASE_URL}/api/", timeout=5)
        return resp.status_code in (200, 403)
    except requests.exceptions.RequestException:
        return False


@pytest.fixture(scope="module")
def netbox_api() -> NetBoxAPI:
    """Provide a NetBox API client. Requires NETBOX_TOKEN env var."""
    if not NETBOX_TOKEN:
        pytest.skip("NETBOX_TOKEN environment variable not set")
    if not _is_netbox_api_available():
        pytest.skip(f"NetBox not available at {NETBOX_BASE_URL}")
    return NetBoxAPI(NETBOX_BASE_URL, NETBOX_TOKEN)


@pytest.fixture
def renewal_test_data(netbox_api: NetBoxAPI):
    """Set up test infrastructure for Janus Renewal E2E tests.

    Creates:
    - An old certificate (expiring in 10 days) via PEM import
    - Site, manufacturer, device_type, device_role, device
    - Service (HTTPS, port 443) on the device
    - Assignment linking old cert to the service

    Yields a dict with all IDs and the new PEM for the renewal cert.
    Cleans up everything on teardown (reverse order).
    """
    from .cert_factory import CertFactory

    suffix = os.urandom(4).hex()
    cn = f"janus-{suffix}.example.com"

    # Generate certificate pair
    old_pem, new_pem = CertFactory.create_renewal_pair(cn=cn, sans=[cn, f"www.{cn}"])

    # Import old certificate
    old_cert = netbox_api.import_certificate(old_pem, private_key_location="test-fixture")
    old_cert_id = old_cert["id"]

    # Create infrastructure
    site = netbox_api.create_site(f"test-site-{suffix}", f"test-site-{suffix}")
    manufacturer = netbox_api.create_manufacturer(f"test-mfr-{suffix}", f"test-mfr-{suffix}")
    device_type = netbox_api.create_device_type(manufacturer["id"], f"test-model-{suffix}", f"test-model-{suffix}")
    device_role = netbox_api.create_device_role(f"test-role-{suffix}", f"test-role-{suffix}")
    device = netbox_api.create_device(f"test-srv-{suffix}", site["id"], device_role["id"], device_type["id"])
    service = netbox_api.create_service(f"HTTPS-{suffix}", device["id"], [443])

    # Create assignment
    assignment = netbox_api.create_assignment(
        certificate_id=old_cert_id,
        assigned_object_type="ipam.service",
        assigned_object_id=service["id"],
        is_primary=True,
        notes="E2E test assignment",
    )

    yield {
        "cn": cn,
        "old_cert_id": old_cert_id,
        "old_cert": old_cert,
        "new_pem": new_pem,
        "site_id": site["id"],
        "manufacturer_id": manufacturer["id"],
        "device_type_id": device_type["id"],
        "device_role_id": device_role["id"],
        "device_id": device["id"],
        "service_id": service["id"],
        "service_name": service["name"],
        "device_name": device["name"],
        "assignment_id": assignment["id"],
    }

    # Cleanup in reverse order — ignore 404s from cascade deletes
    netbox_api.delete_assignment(assignment["id"])
    # Also clean up any new cert that renewal may have created
    # Search for certs with this CN and delete them
    try:
        resp = netbox_api.session.get(
            f"{netbox_api.base_url}/api/plugins/ssl/certificates/",
            params={"common_name": cn},
        )
        if resp.status_code == 200:
            for cert in resp.json().get("results", []):
                netbox_api.delete_certificate(cert["id"])
    except requests.exceptions.RequestException:
        pass  # Network errors during cleanup are acceptable
    netbox_api.delete_certificate(old_cert_id)
    netbox_api.delete_service(service["id"])
    netbox_api.delete_device(device["id"])
    netbox_api.delete_device_type(device_type["id"])
    netbox_api.delete_device_role(device_role["id"])
    netbox_api.delete_manufacturer(manufacturer["id"])
    netbox_api.delete_site(site["id"])
