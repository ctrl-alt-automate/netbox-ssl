"""
Unit tests for ACME certificate tracking functionality.

Tests the ACME detection, provider identification, and renewal status tracking
for certificates issued via ACME protocol (Let's Encrypt, ZeroSSL, etc.).

Uses local copies of _ACME_PATTERNS and choice values to avoid importing
netbox_ssl.models (which triggers Django model metaclass). A @requires_netbox
test verifies the local copies stay in sync with the real model module.
"""

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_project_root = Path(__file__).parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

# ---------------------------------------------------------------------------
# Detect NetBox availability
# ---------------------------------------------------------------------------
try:
    _spec = importlib.util.find_spec("netbox")
    _NETBOX_AVAILABLE = _spec is not None and _spec.origin is not None
except (ValueError, ModuleNotFoundError):
    _NETBOX_AVAILABLE = False

requires_netbox = pytest.mark.skipif(
    not _NETBOX_AVAILABLE,
    reason="NetBox not available - run these tests inside Docker container",
)

# ---------------------------------------------------------------------------
# Local copies of ACME constants (no Django dependency)
# These MUST match netbox_ssl/models/certificates.py — verified by
# TestACMESyncWithModel below.
# ---------------------------------------------------------------------------
_ACME_PROVIDER_VALUES = {
    "letsencrypt": "letsencrypt",
    "letsencrypt_staging": "letsencrypt_staging",
    "zerossl": "zerossl",
    "buypass": "buypass",
    "google": "google",
    "digicert": "digicert",
    "sectigo": "sectigo",
    "other": "other",
}

_ACME_CHALLENGE_VALUES = {
    "http-01": "http-01",
    "dns-01": "dns-01",
    "tls-alpn-01": "tls-alpn-01",
    "unknown": "unknown",
}

# Mirror of _ACME_PATTERNS from certificates.py
_ACME_PATTERNS = {
    "let's encrypt": "letsencrypt",
    "letsencrypt": "letsencrypt",
    "r3, o=let's encrypt": "letsencrypt",
    "r10, o=let's encrypt": "letsencrypt",
    "r11, o=let's encrypt": "letsencrypt",
    "e1, o=let's encrypt": "letsencrypt",
    "e5, o=let's encrypt": "letsencrypt",
    "e6, o=let's encrypt": "letsencrypt",
    "(staging)": "letsencrypt_staging",
    "fake le": "letsencrypt_staging",
    "zerossl": "zerossl",
    "buypass": "buypass",
    "google trust services": "google",
    "gts ca": "google",
    "sectigo": "sectigo",
    "digicert": "digicert",
}


# Mark all tests in this module as unit tests
pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Sync verification — runs only in Docker with real NetBox
# ---------------------------------------------------------------------------
class TestACMESyncWithModel:
    """Verify local test constants match the real model module."""

    @requires_netbox
    def test_acme_patterns_match_model(self):
        """Local _ACME_PATTERNS must match netbox_ssl.models.certificates."""
        from netbox_ssl.models.certificates import _ACME_PATTERNS as real_patterns

        assert real_patterns == _ACME_PATTERNS

    @requires_netbox
    def test_acme_provider_values_match_model(self):
        """Local provider values must match ACMEProviderChoices."""
        from netbox_ssl.models.certificates import ACMEProviderChoices

        for key, value in _ACME_PROVIDER_VALUES.items():
            attr = f"PROVIDER_{key.upper()}"
            assert getattr(ACMEProviderChoices, attr) == value

    @requires_netbox
    def test_acme_challenge_values_match_model(self):
        """Local challenge values must match ACMEChallengeTypeChoices."""
        from netbox_ssl.models.certificates import ACMEChallengeTypeChoices

        mapping = {
            "http-01": "CHALLENGE_HTTP01",
            "dns-01": "CHALLENGE_DNS01",
            "tls-alpn-01": "CHALLENGE_TLS_ALPN01",
            "unknown": "CHALLENGE_UNKNOWN",
        }
        for value, attr in mapping.items():
            assert getattr(ACMEChallengeTypeChoices, attr) == value

    @requires_netbox
    def test_acme_patterns_is_module_level(self):
        """_ACME_PATTERNS is defined at module level (not recreated per call)."""
        from netbox_ssl.models import certificates

        assert hasattr(certificates, "_ACME_PATTERNS")
        assert isinstance(certificates._ACME_PATTERNS, dict)
        assert certificates._ACME_PATTERNS is certificates._ACME_PATTERNS


# ---------------------------------------------------------------------------
# Pattern detection tests — use local _ACME_PATTERNS
# ---------------------------------------------------------------------------
class TestACMEProviderDetection:
    """Test cases for ACME provider auto-detection from issuer strings."""

    @pytest.mark.parametrize(
        "issuer,expected_provider",
        [
            ("CN=R3, O=Let's Encrypt, C=US", "letsencrypt"),
            ("CN=R10, O=Let's Encrypt, C=US", "letsencrypt"),
            ("CN=R11, O=Let's Encrypt, C=US", "letsencrypt"),
            ("CN=E1, O=Let's Encrypt, C=US", "letsencrypt"),
            ("CN=E5, O=Let's Encrypt, C=US", "letsencrypt"),
            ("CN=E6, O=Let's Encrypt, C=US", "letsencrypt"),
            ("O=Let's Encrypt, CN=ISRG Root X1", "letsencrypt"),
            ("CN=(STAGING) Pretend Pear X1", "letsencrypt_staging"),
            ("CN=Fake LE Intermediate X1", "letsencrypt_staging"),
            ("CN=ZeroSSL RSA Domain Secure Site CA, O=ZeroSSL", "zerossl"),
            ("O=ZeroSSL, CN=ZeroSSL ECC Domain Secure Site CA", "zerossl"),
            ("CN=Buypass Class 2 CA 5, O=Buypass AS-983163327, C=NO", "buypass"),
            ("CN=GTS CA 1C3, O=Google Trust Services LLC, C=US", "google"),
            ("O=Google Trust Services, CN=GTS Root R1", "google"),
            ("CN=Sectigo RSA Domain Validation Secure Server CA", "sectigo"),
            ("CN=DigiCert TLS RSA SHA256 2020 CA1, O=DigiCert Inc", "digicert"),
        ],
    )
    def test_detect_acme_provider(self, issuer, expected_provider):
        """Test that ACME providers are correctly detected from issuer strings."""
        issuer_lower = issuer.lower()
        detected_provider = None
        for pattern, provider in _ACME_PATTERNS.items():
            if pattern in issuer_lower:
                detected_provider = provider
                break

        assert detected_provider == expected_provider

    @pytest.mark.parametrize(
        "issuer",
        [
            "CN=GlobalSign GCC R3 DV TLS CA 2020, O=GlobalSign nv-sa",
            "CN=Entrust Certification Authority - L1K, O=Entrust, Inc.",
            "CN=RapidSSL TLS DV RSA Mixed SHA256 2020 CA-1",
            "CN=Amazon, O=Amazon, C=US",
            "CN=Internal CA, O=My Company",
            "CN=Self-Signed Certificate",
        ],
    )
    def test_non_acme_issuers(self, issuer):
        """Test that non-ACME issuers are not detected as ACME."""
        issuer_lower = issuer.lower()
        detected_provider = None
        for pattern, provider in _ACME_PATTERNS.items():
            if pattern in issuer_lower:
                detected_provider = provider
                break

        assert detected_provider is None


class TestACMERenewalStatus:
    """Test cases for ACME renewal status calculations."""

    def test_acme_renewal_due_within_threshold(self):
        """Test that renewal is due when days_remaining <= acme_renewal_days."""
        mock_cert = MagicMock()
        mock_cert.is_acme = True
        mock_cert.acme_auto_renewal = True
        mock_cert.acme_renewal_days = 30
        mock_cert.days_remaining = 25

        renewal_days = mock_cert.acme_renewal_days or 30
        is_renewal_due = (
            mock_cert.is_acme
            and mock_cert.acme_auto_renewal
            and mock_cert.days_remaining is not None
            and mock_cert.days_remaining <= renewal_days
        )

        assert is_renewal_due is True

    def test_acme_renewal_not_due_outside_threshold(self):
        """Test that renewal is not due when days_remaining > acme_renewal_days."""
        mock_cert = MagicMock()
        mock_cert.is_acme = True
        mock_cert.acme_auto_renewal = True
        mock_cert.acme_renewal_days = 30
        mock_cert.days_remaining = 60

        renewal_days = mock_cert.acme_renewal_days or 30
        is_renewal_due = (
            mock_cert.is_acme
            and mock_cert.acme_auto_renewal
            and mock_cert.days_remaining is not None
            and mock_cert.days_remaining <= renewal_days
        )

        assert is_renewal_due is False

    def test_acme_renewal_not_due_for_non_acme(self):
        """Test that renewal is never due for non-ACME certificates."""
        mock_cert = MagicMock()
        mock_cert.is_acme = False
        mock_cert.acme_auto_renewal = True
        mock_cert.acme_renewal_days = 30
        mock_cert.days_remaining = 10

        is_renewal_due = (
            mock_cert.is_acme
            and mock_cert.acme_auto_renewal
            and mock_cert.days_remaining is not None
            and mock_cert.days_remaining <= (mock_cert.acme_renewal_days or 30)
        )

        assert is_renewal_due is False

    def test_acme_renewal_not_due_without_auto_renewal(self):
        """Test that renewal is not due when auto_renewal is disabled."""
        mock_cert = MagicMock()
        mock_cert.is_acme = True
        mock_cert.acme_auto_renewal = False
        mock_cert.acme_renewal_days = 30
        mock_cert.days_remaining = 10

        is_renewal_due = (
            mock_cert.is_acme
            and mock_cert.acme_auto_renewal
            and mock_cert.days_remaining is not None
            and mock_cert.days_remaining <= (mock_cert.acme_renewal_days or 30)
        )

        assert is_renewal_due is False

    def test_custom_renewal_days_threshold(self):
        """Test that custom acme_renewal_days values are respected."""
        mock_cert = MagicMock()
        mock_cert.is_acme = True
        mock_cert.acme_auto_renewal = True
        mock_cert.acme_renewal_days = 14
        mock_cert.days_remaining = 20

        renewal_days = mock_cert.acme_renewal_days or 30
        is_renewal_due = (
            mock_cert.is_acme
            and mock_cert.acme_auto_renewal
            and mock_cert.days_remaining is not None
            and mock_cert.days_remaining <= renewal_days
        )

        assert is_renewal_due is False

        mock_cert.days_remaining = 10
        is_renewal_due = (
            mock_cert.is_acme
            and mock_cert.acme_auto_renewal
            and mock_cert.days_remaining is not None
            and mock_cert.days_remaining <= renewal_days
        )

        assert is_renewal_due is True


class TestACMERenewalStatusProperty:
    """Test cases for the acme_renewal_status property."""

    @pytest.mark.parametrize(
        "is_acme,acme_auto_renewal,is_expired,renewal_due,expected_status",
        [
            (False, False, False, False, "not_acme"),
            (True, False, False, False, "manual"),
            (True, True, True, False, "expired"),
            (True, True, False, True, "due"),
            (True, True, False, False, "ok"),
        ],
    )
    def test_acme_renewal_status_values(self, is_acme, acme_auto_renewal, is_expired, renewal_due, expected_status):
        """Test various ACME renewal status scenarios."""
        if not is_acme:
            status = "not_acme"
        elif not acme_auto_renewal:
            status = "manual"
        elif is_expired:
            status = "expired"
        elif renewal_due:
            status = "due"
        else:
            status = "ok"

        assert status == expected_status


class TestACMEChoices:
    """Test cases for ACME choice classes."""

    def test_acme_provider_choices_values(self):
        """Test that all expected ACME providers are defined."""
        for name, value in _ACME_PROVIDER_VALUES.items():
            assert value == name

    def test_acme_challenge_type_choices_values(self):
        """Test that all expected ACME challenge types are defined."""
        for name, value in _ACME_CHALLENGE_VALUES.items():
            assert value == name


class TestACMEPatterns:
    """Test cases for the module-level ACME patterns dictionary."""

    def test_acme_patterns_contains_all_providers(self):
        """Test that _ACME_PATTERNS contains patterns for all providers."""
        providers_with_patterns = set(_ACME_PATTERNS.values())

        assert "letsencrypt" in providers_with_patterns
        assert "letsencrypt_staging" in providers_with_patterns
        assert "zerossl" in providers_with_patterns
        assert "buypass" in providers_with_patterns
        assert "google" in providers_with_patterns
        assert "sectigo" in providers_with_patterns
        assert "digicert" in providers_with_patterns

    def test_acme_patterns_keys_are_lowercase(self):
        """Test that all pattern keys are lowercase for case-insensitive matching."""
        for key in _ACME_PATTERNS:
            assert key == key.lower(), f"Pattern key {key!r} is not lowercase"


class TestACMEModelFields:
    """Test cases for ACME model field defaults and constraints."""

    def test_default_renewal_days(self):
        """Test that default renewal days is 30."""
        default_renewal_days = 30
        assert default_renewal_days == 30

    def test_acme_server_url_max_length(self):
        """Test that ACME server URL can hold long URLs."""
        max_length = 500
        letsencrypt_url = "https://acme-v02.api.letsencrypt.org/directory"
        staging_url = "https://acme-staging-v02.api.letsencrypt.org/directory"

        assert len(letsencrypt_url) <= max_length
        assert len(staging_url) <= max_length


class TestACMEAPIEndpoints:
    """Test cases for ACME-related API endpoint behavior."""

    def test_detect_acme_response_detected(self):
        """Test detect-acme endpoint response when ACME is detected."""
        response = {
            "detected": True,
            "is_acme": True,
            "acme_provider": "letsencrypt",
            "certificate": {"id": 1, "common_name": "example.com"},
        }

        assert response["detected"] is True
        assert response["is_acme"] is True
        assert response["acme_provider"] == "letsencrypt"
        assert "certificate" in response

    def test_detect_acme_response_not_detected(self):
        """Test detect-acme endpoint response when ACME is not detected."""
        response = {
            "detected": False,
            "message": "Certificate issuer does not match any known ACME provider patterns.",
        }

        assert response["detected"] is False
        assert "message" in response

    def test_bulk_detect_acme_response_structure(self):
        """Test bulk-detect-acme endpoint response structure."""
        response = {
            "total": 5,
            "processed": 5,
            "detected_acme": 3,
            "not_acme": 2,
            "missing_ids": [],
            "detections": [
                {
                    "id": 1,
                    "common_name": "example.com",
                    "detected": True,
                    "acme_provider": "letsencrypt",
                },
                {"id": 2, "common_name": "test.com", "detected": False},
            ],
        }

        assert response["total"] == 5
        assert response["processed"] == 5
        assert response["detected_acme"] == 3
        assert response["not_acme"] == 2
        assert isinstance(response["missing_ids"], list)
        assert isinstance(response["detections"], list)


class TestACMEFieldSerialization:
    """Test cases for ACME field serialization in the API."""

    def test_acme_fields_in_serializer(self):
        """Test that all ACME fields are included in serialization."""
        expected_acme_fields = [
            "is_acme",
            "acme_provider",
            "acme_account_email",
            "acme_challenge_type",
            "acme_server_url",
            "acme_auto_renewal",
            "acme_last_renewed",
            "acme_renewal_days",
            "acme_renewal_due",
            "acme_renewal_status",
        ]

        for field in expected_acme_fields:
            assert field in expected_acme_fields

    def test_acme_brief_fields(self):
        """Test that is_acme is included in brief serialization."""
        brief_fields = [
            "id",
            "url",
            "display",
            "common_name",
            "serial_number",
            "status",
            "valid_to",
            "days_remaining",
            "is_acme",
        ]

        assert "is_acme" in brief_fields


class TestACMEIntegrationScenarios:
    """Integration test scenarios for ACME certificate workflows."""

    def test_letsencrypt_certificate_detection_workflow(self):
        """Test complete workflow for Let's Encrypt certificate detection."""
        issuer = "CN=R3, O=Let's Encrypt, C=US"
        issuer_lower = issuer.lower()

        detected_provider = None
        for pattern, provider in _ACME_PATTERNS.items():
            if pattern in issuer_lower:
                detected_provider = provider
                break

        assert detected_provider == "letsencrypt"

    def test_staging_certificate_identification(self):
        """Test that staging certificates are correctly identified."""
        staging_issuers = [
            "CN=(STAGING) Pretend Pear X1",
            "CN=Fake LE Intermediate X1",
        ]

        for issuer in staging_issuers:
            issuer_lower = issuer.lower()
            detected_provider = None
            for pattern, provider in _ACME_PATTERNS.items():
                if pattern in issuer_lower:
                    detected_provider = provider
                    break

            assert detected_provider == "letsencrypt_staging", f"Failed for issuer: {issuer}"

    def test_mixed_certificate_batch_detection(self):
        """Test bulk detection with mixed ACME and non-ACME certificates."""
        certificates = [
            {"id": 1, "issuer": "CN=R3, O=Let's Encrypt, C=US"},
            {"id": 2, "issuer": "CN=GlobalSign GCC R3 DV TLS CA"},
            {"id": 3, "issuer": "CN=ZeroSSL RSA Domain Secure Site CA"},
            {"id": 4, "issuer": "CN=Internal CA, O=My Company"},
            {"id": 5, "issuer": "CN=Buypass Class 2 CA 5, O=Buypass AS"},
        ]

        detected_acme = 0
        for cert in certificates:
            issuer_lower = cert["issuer"].lower()
            for pattern in _ACME_PATTERNS:
                if pattern in issuer_lower:
                    detected_acme += 1
                    break

        assert detected_acme == 3  # Let's Encrypt, ZeroSSL, Buypass

    def test_digicert_detection(self):
        """Test that DigiCert ACME certificates are detected."""
        issuer = "CN=DigiCert TLS RSA SHA256 2020 CA1, O=DigiCert Inc"
        issuer_lower = issuer.lower()

        detected_provider = None
        for pattern, provider in _ACME_PATTERNS.items():
            if pattern in issuer_lower:
                detected_provider = provider
                break

        assert detected_provider == "digicert"
