"""
Pytest configuration and fixtures for NetBox SSL plugin tests.
"""

from datetime import datetime, timedelta

import pytest

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
