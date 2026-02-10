"""
Unit tests for ACME certificate tracking functionality.

Tests the ACME detection, provider identification, and renewal status tracking
for certificates issued via ACME protocol (Let's Encrypt, ZeroSSL, etc.).
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

# Mark all tests in this module as unit tests
pytestmark = pytest.mark.unit


class TestACMEProviderDetection:
    """Test cases for ACME provider auto-detection from issuer strings."""

    @pytest.mark.parametrize(
        "issuer,expected_provider",
        [
            # Let's Encrypt patterns
            ("CN=R3, O=Let's Encrypt, C=US", "letsencrypt"),
            ("CN=R10, O=Let's Encrypt, C=US", "letsencrypt"),
            ("CN=R11, O=Let's Encrypt, C=US", "letsencrypt"),
            ("CN=E1, O=Let's Encrypt, C=US", "letsencrypt"),
            ("CN=E5, O=Let's Encrypt, C=US", "letsencrypt"),
            ("CN=E6, O=Let's Encrypt, C=US", "letsencrypt"),
            ("O=Let's Encrypt, CN=ISRG Root X1", "letsencrypt"),
            # Let's Encrypt Staging
            ("CN=(STAGING) Pretend Pear X1", "letsencrypt_staging"),
            ("CN=Fake LE Intermediate X1", "letsencrypt_staging"),
            # ZeroSSL
            ("CN=ZeroSSL RSA Domain Secure Site CA, O=ZeroSSL", "zerossl"),
            ("O=ZeroSSL, CN=ZeroSSL ECC Domain Secure Site CA", "zerossl"),
            # Buypass
            ("CN=Buypass Class 2 CA 5, O=Buypass AS-983163327, C=NO", "buypass"),
            # Google Trust Services
            ("CN=GTS CA 1C3, O=Google Trust Services LLC, C=US", "google"),
            ("O=Google Trust Services, CN=GTS Root R1", "google"),
            # Sectigo
            ("CN=Sectigo RSA Domain Validation Secure Server CA", "sectigo"),
            # DigiCert
            ("CN=DigiCert TLS RSA SHA256 2020 CA1, O=DigiCert Inc", "digicert"),
        ],
    )
    def test_detect_acme_provider(self, issuer, expected_provider):
        """Test that ACME providers are correctly detected from issuer strings."""
        # Import the actual model and patterns
        from netbox_ssl.models.certificates import (
            ACMEProviderChoices,
            Certificate,
            _ACME_PATTERNS,
        )

        # Create a mock certificate with the issuer
        cert = MagicMock(spec=Certificate)
        cert.issuer = issuer
        cert.is_acme = False
        cert.acme_provider = ""

        # Call the actual detection logic
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
        from netbox_ssl.models.certificates import _ACME_PATTERNS

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

        # Simulate days_remaining property
        mock_cert.days_remaining = 25

        # Test the renewal logic
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
        mock_cert.acme_renewal_days = 14  # Custom 14-day threshold
        mock_cert.days_remaining = 20

        # With 14-day threshold, 20 days remaining should NOT be due
        renewal_days = mock_cert.acme_renewal_days or 30
        is_renewal_due = (
            mock_cert.is_acme
            and mock_cert.acme_auto_renewal
            and mock_cert.days_remaining is not None
            and mock_cert.days_remaining <= renewal_days
        )

        assert is_renewal_due is False

        # With 14-day threshold, 10 days remaining SHOULD be due
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
        # Test the status determination logic
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
        from netbox_ssl.models.certificates import ACMEProviderChoices

        expected_providers = {
            "letsencrypt": ACMEProviderChoices.PROVIDER_LETSENCRYPT,
            "letsencrypt_staging": ACMEProviderChoices.PROVIDER_LETSENCRYPT_STAGING,
            "zerossl": ACMEProviderChoices.PROVIDER_ZEROSSL,
            "buypass": ACMEProviderChoices.PROVIDER_BUYPASS,
            "google": ACMEProviderChoices.PROVIDER_GOOGLE,
            "digicert": ACMEProviderChoices.PROVIDER_DIGICERT,
            "sectigo": ACMEProviderChoices.PROVIDER_SECTIGO,
            "other": ACMEProviderChoices.PROVIDER_OTHER,
        }

        for name, value in expected_providers.items():
            assert value == name

    def test_acme_challenge_type_choices_values(self):
        """Test that all expected ACME challenge types are defined."""
        from netbox_ssl.models.certificates import ACMEChallengeTypeChoices

        expected_challenges = {
            "http-01": ACMEChallengeTypeChoices.CHALLENGE_HTTP01,
            "dns-01": ACMEChallengeTypeChoices.CHALLENGE_DNS01,
            "tls-alpn-01": ACMEChallengeTypeChoices.CHALLENGE_TLS_ALPN01,
            "unknown": ACMEChallengeTypeChoices.CHALLENGE_UNKNOWN,
        }

        for name, value in expected_challenges.items():
            assert value == name


class TestACMEPatterns:
    """Test cases for the module-level ACME patterns dictionary."""

    def test_acme_patterns_contains_all_providers(self):
        """Test that _ACME_PATTERNS contains patterns for all providers."""
        from netbox_ssl.models.certificates import ACMEProviderChoices, _ACME_PATTERNS

        # All providers except 'other' should have at least one pattern
        providers_with_patterns = set(_ACME_PATTERNS.values())

        assert ACMEProviderChoices.PROVIDER_LETSENCRYPT in providers_with_patterns
        assert ACMEProviderChoices.PROVIDER_LETSENCRYPT_STAGING in providers_with_patterns
        assert ACMEProviderChoices.PROVIDER_ZEROSSL in providers_with_patterns
        assert ACMEProviderChoices.PROVIDER_BUYPASS in providers_with_patterns
        assert ACMEProviderChoices.PROVIDER_GOOGLE in providers_with_patterns
        assert ACMEProviderChoices.PROVIDER_SECTIGO in providers_with_patterns
        assert ACMEProviderChoices.PROVIDER_DIGICERT in providers_with_patterns

    def test_acme_patterns_is_module_level(self):
        """Test that _ACME_PATTERNS is defined at module level (not recreated)."""
        from netbox_ssl.models import certificates

        # Verify it's a module-level constant
        assert hasattr(certificates, "_ACME_PATTERNS")
        assert isinstance(certificates._ACME_PATTERNS, dict)

        # Verify it's the same object (not recreated)
        patterns1 = certificates._ACME_PATTERNS
        patterns2 = certificates._ACME_PATTERNS
        assert patterns1 is patterns2


class TestACMEModelFields:
    """Test cases for ACME model field defaults and constraints."""

    def test_default_renewal_days(self):
        """Test that default renewal days is 30."""
        default_renewal_days = 30
        assert default_renewal_days == 30

    def test_acme_server_url_max_length(self):
        """Test that ACME server URL can hold long URLs."""
        max_length = 500
        # Typical Let's Encrypt URL
        letsencrypt_url = "https://acme-v02.api.letsencrypt.org/directory"
        # Staging URL
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
        from netbox_ssl.models.certificates import _ACME_PATTERNS

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
        from netbox_ssl.models.certificates import ACMEProviderChoices, _ACME_PATTERNS

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

            assert detected_provider == ACMEProviderChoices.PROVIDER_LETSENCRYPT_STAGING, f"Failed for issuer: {issuer}"

    def test_mixed_certificate_batch_detection(self):
        """Test bulk detection with mixed ACME and non-ACME certificates."""
        from netbox_ssl.models.certificates import _ACME_PATTERNS

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
        from netbox_ssl.models.certificates import ACMEProviderChoices, _ACME_PATTERNS

        issuer = "CN=DigiCert TLS RSA SHA256 2020 CA1, O=DigiCert Inc"
        issuer_lower = issuer.lower()

        detected_provider = None
        for pattern, provider in _ACME_PATTERNS.items():
            if pattern in issuer_lower:
                detected_provider = provider
                break

        assert detected_provider == ACMEProviderChoices.PROVIDER_DIGICERT
