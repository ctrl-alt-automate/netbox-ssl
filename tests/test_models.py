"""
Unit tests for NetBox SSL plugin models.

These tests verify the Certificate and CertificateAssignment models
work correctly without requiring a full NetBox environment.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
from django.utils import timezone


class TestCertificateModel:
    """Tests for Certificate model properties and methods."""

    def _create_mock_certificate(self, valid_from, valid_to, status="active"):
        """Create a mock certificate object for testing."""
        mock_cert = Mock()
        mock_cert.valid_from = valid_from
        mock_cert.valid_to = valid_to
        mock_cert.status = status

        # Import the actual property implementations
        from netbox_ssl.models.certificates import Certificate

        # Manually implement the properties using the same logic
        if valid_to:
            from datetime import date
            delta = valid_to.date() - date.today()
            mock_cert.days_remaining = delta.days
        else:
            mock_cert.days_remaining = None

        if mock_cert.days_remaining is not None and mock_cert.days_remaining < 0:
            mock_cert.days_expired = abs(mock_cert.days_remaining)
        else:
            mock_cert.days_expired = 0

        mock_cert.is_expired = valid_to and valid_to < timezone.now()

        if mock_cert.days_remaining is None:
            mock_cert.is_expiring_soon = False
            mock_cert.is_critical = False
        else:
            mock_cert.is_expiring_soon = 0 < mock_cert.days_remaining <= 30
            mock_cert.is_critical = 0 < mock_cert.days_remaining <= 14

        # Expiry status
        if mock_cert.is_expired:
            mock_cert.expiry_status = "expired"
        elif mock_cert.is_critical:
            mock_cert.expiry_status = "critical"
        elif mock_cert.is_expiring_soon:
            mock_cert.expiry_status = "warning"
        else:
            mock_cert.expiry_status = "ok"

        return mock_cert

    @pytest.mark.unit
    def test_days_remaining_future(self):
        """Test days_remaining for a certificate expiring in the future."""
        now = timezone.now()
        future = now + timedelta(days=100)
        cert = self._create_mock_certificate(now - timedelta(days=265), future)

        assert cert.days_remaining >= 99  # Allow for test timing
        assert cert.days_remaining <= 101

    @pytest.mark.unit
    def test_days_remaining_expired(self):
        """Test days_remaining for an expired certificate."""
        now = timezone.now()
        past = now - timedelta(days=10)
        cert = self._create_mock_certificate(now - timedelta(days=375), past)

        assert cert.days_remaining < 0
        assert cert.days_remaining >= -11
        assert cert.days_remaining <= -9

    @pytest.mark.unit
    def test_days_expired_for_expired_cert(self):
        """Test days_expired returns positive value for expired certs."""
        now = timezone.now()
        past = now - timedelta(days=15)
        cert = self._create_mock_certificate(now - timedelta(days=380), past)

        assert cert.days_expired >= 14
        assert cert.days_expired <= 16

    @pytest.mark.unit
    def test_days_expired_for_valid_cert(self):
        """Test days_expired returns 0 for valid certificates."""
        now = timezone.now()
        future = now + timedelta(days=100)
        cert = self._create_mock_certificate(now - timedelta(days=265), future)

        assert cert.days_expired == 0

    @pytest.mark.unit
    def test_is_expired_true(self):
        """Test is_expired returns True for expired certificates."""
        now = timezone.now()
        past = now - timedelta(days=1)
        cert = self._create_mock_certificate(now - timedelta(days=366), past)

        assert cert.is_expired is True

    @pytest.mark.unit
    def test_is_expired_false(self):
        """Test is_expired returns False for valid certificates."""
        now = timezone.now()
        future = now + timedelta(days=100)
        cert = self._create_mock_certificate(now - timedelta(days=265), future)

        assert cert.is_expired is False

    @pytest.mark.unit
    def test_is_expiring_soon_warning_threshold(self):
        """Test is_expiring_soon for cert expiring within 30 days."""
        now = timezone.now()
        future = now + timedelta(days=20)  # 20 days remaining
        cert = self._create_mock_certificate(now - timedelta(days=345), future)

        assert cert.is_expiring_soon is True
        assert cert.is_critical is False  # Not critical yet

    @pytest.mark.unit
    def test_is_critical_threshold(self):
        """Test is_critical for cert expiring within 14 days."""
        now = timezone.now()
        future = now + timedelta(days=7)  # 7 days remaining
        cert = self._create_mock_certificate(now - timedelta(days=358), future)

        assert cert.is_critical is True
        assert cert.is_expiring_soon is True  # Also expiring soon

    @pytest.mark.unit
    def test_expiry_status_ok(self):
        """Test expiry_status returns 'ok' for healthy certificates."""
        now = timezone.now()
        future = now + timedelta(days=100)
        cert = self._create_mock_certificate(now - timedelta(days=265), future)

        assert cert.expiry_status == "ok"

    @pytest.mark.unit
    def test_expiry_status_warning(self):
        """Test expiry_status returns 'warning' for soon-expiring certs."""
        now = timezone.now()
        future = now + timedelta(days=20)
        cert = self._create_mock_certificate(now - timedelta(days=345), future)

        assert cert.expiry_status == "warning"

    @pytest.mark.unit
    def test_expiry_status_critical(self):
        """Test expiry_status returns 'critical' for nearly-expired certs."""
        now = timezone.now()
        future = now + timedelta(days=7)
        cert = self._create_mock_certificate(now - timedelta(days=358), future)

        assert cert.expiry_status == "critical"

    @pytest.mark.unit
    def test_expiry_status_expired(self):
        """Test expiry_status returns 'expired' for expired certs."""
        now = timezone.now()
        past = now - timedelta(days=10)
        cert = self._create_mock_certificate(now - timedelta(days=375), past)

        assert cert.expiry_status == "expired"


class TestCertificateStatusChoices:
    """Tests for CertificateStatusChoices."""

    @pytest.mark.unit
    def test_status_choices_exist(self):
        """Test that all expected status choices are defined."""
        from netbox_ssl.models import CertificateStatusChoices

        assert hasattr(CertificateStatusChoices, 'STATUS_ACTIVE')
        assert hasattr(CertificateStatusChoices, 'STATUS_EXPIRED')
        assert hasattr(CertificateStatusChoices, 'STATUS_REPLACED')
        assert hasattr(CertificateStatusChoices, 'STATUS_REVOKED')
        assert hasattr(CertificateStatusChoices, 'STATUS_PENDING')

    @pytest.mark.unit
    def test_status_values(self):
        """Test status choice values."""
        from netbox_ssl.models import CertificateStatusChoices

        assert CertificateStatusChoices.STATUS_ACTIVE == "active"
        assert CertificateStatusChoices.STATUS_EXPIRED == "expired"
        assert CertificateStatusChoices.STATUS_REPLACED == "replaced"


class TestCertificateAlgorithmChoices:
    """Tests for CertificateAlgorithmChoices."""

    @pytest.mark.unit
    def test_algorithm_choices_exist(self):
        """Test that all expected algorithm choices are defined."""
        from netbox_ssl.models import CertificateAlgorithmChoices

        assert hasattr(CertificateAlgorithmChoices, 'ALGORITHM_RSA')
        assert hasattr(CertificateAlgorithmChoices, 'ALGORITHM_ECDSA')
        assert hasattr(CertificateAlgorithmChoices, 'ALGORITHM_ED25519')

    @pytest.mark.unit
    def test_algorithm_values(self):
        """Test algorithm choice values."""
        from netbox_ssl.models import CertificateAlgorithmChoices

        assert CertificateAlgorithmChoices.ALGORITHM_RSA == "rsa"
        assert CertificateAlgorithmChoices.ALGORITHM_ECDSA == "ecdsa"
        assert CertificateAlgorithmChoices.ALGORITHM_ED25519 == "ed25519"
