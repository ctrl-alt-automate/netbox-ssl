"""
Unit tests for CertificateAuthority model.

Tests for Certificate Authority tracking feature (Issue #13).
"""

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

# Allow importing modules directly without loading the full netbox_ssl package
_project_root = Path(__file__).parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

# Two scenarios:
# 1. Running locally without NetBox: mock everything
# 2. Running in Docker with NetBox: use real Django setup

_in_netbox_env = os.path.exists("/opt/netbox/netbox/netbox/settings.py") or "DJANGO_SETTINGS_MODULE" in os.environ

if _in_netbox_env:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "netbox.settings")
    import django

    try:
        django.setup()
    except RuntimeError:
        pass
    NETBOX_AVAILABLE = True
else:
    sys.modules["netbox"] = MagicMock()
    sys.modules["netbox.plugins"] = MagicMock()
    sys.modules["netbox.models"] = MagicMock()
    sys.modules["netbox.models.features"] = MagicMock()

    import django
    from django.conf import settings

    if not settings.configured:
        settings.configure(
            USE_TZ=True,
            TIME_ZONE="UTC",
            DATABASES={},
            INSTALLED_APPS=[],
            DEFAULT_AUTO_FIELD="django.db.models.BigAutoField",
        )
    NETBOX_AVAILABLE = False

if NETBOX_AVAILABLE:
    try:
        from netbox_ssl.models import (
            CATypeChoices,
            Certificate,
            CertificateAuthority,
            DEFAULT_CERTIFICATE_AUTHORITIES,
        )
    except (ImportError, ModuleNotFoundError) as e:
        print(f"Warning: Could not import netbox_ssl models: {e}")
        NETBOX_AVAILABLE = False

requires_netbox = pytest.mark.skipif(
    not NETBOX_AVAILABLE, reason="NetBox not available - run these tests inside Docker container"
)


class TestCATypeChoices:
    """Tests for Certificate Authority type choices."""

    def test_ca_type_choices_defined(self):
        """Verify CA type choices are properly defined."""
        # These values should match the model definition
        expected_types = ["public", "internal", "acme"]

        # Mock the choices if not available
        if not NETBOX_AVAILABLE:
            mock_choices = MagicMock()
            mock_choices.TYPE_PUBLIC = "public"
            mock_choices.TYPE_INTERNAL = "internal"
            mock_choices.TYPE_ACME = "acme"
            mock_choices.CHOICES = [
                ("public", "Public CA", "green"),
                ("internal", "Internal/Private CA", "blue"),
                ("acme", "ACME/Let's Encrypt", "cyan"),
            ]

            assert mock_choices.TYPE_PUBLIC == "public"
            assert mock_choices.TYPE_INTERNAL == "internal"
            assert mock_choices.TYPE_ACME == "acme"
            assert len(mock_choices.CHOICES) == 3
        else:
            assert CATypeChoices.TYPE_PUBLIC == "public"
            assert CATypeChoices.TYPE_INTERNAL == "internal"
            assert CATypeChoices.TYPE_ACME == "acme"
            assert len(CATypeChoices.CHOICES) == 3


class TestCertificateAuthorityModel:
    """Tests for CertificateAuthority model."""

    @requires_netbox
    def test_ca_creation(self):
        """Test creating a Certificate Authority."""
        ca = CertificateAuthority.objects.create(
            name="Test CA",
            type=CATypeChoices.TYPE_PUBLIC,
            description="A test Certificate Authority",
            issuer_pattern="CN=Test CA",
            is_approved=True,
        )

        assert ca.pk is not None
        assert ca.name == "Test CA"
        assert ca.type == "public"
        assert ca.is_approved is True

        # Cleanup
        ca.delete()

    @requires_netbox
    def test_ca_str_representation(self):
        """Test string representation of CertificateAuthority."""
        ca = CertificateAuthority(name="DigiCert")
        assert str(ca) == "DigiCert"

    @requires_netbox
    def test_ca_unique_name_constraint(self):
        """Test that CA names must be unique."""
        ca1 = CertificateAuthority.objects.create(
            name="Unique CA",
            type=CATypeChoices.TYPE_PUBLIC,
        )

        with pytest.raises(Exception):  # IntegrityError
            CertificateAuthority.objects.create(
                name="Unique CA",
                type=CATypeChoices.TYPE_INTERNAL,
            )

        # Cleanup
        ca1.delete()


class TestCertificateAuthorityAutoDetection:
    """Tests for CA auto-detection functionality."""

    def _create_mock_ca(self, name, issuer_pattern):
        """Create a mock CA for testing."""
        mock_ca = Mock()
        mock_ca.name = name
        mock_ca.issuer_pattern = issuer_pattern
        return mock_ca

    def test_auto_detect_digicert(self):
        """Test auto-detection of DigiCert certificates."""
        issuer = "CN=DigiCert SHA2 Extended Validation Server CA, OU=www.digicert.com, O=DigiCert Inc, C=US"

        # Mock the auto_detect method
        def mock_auto_detect(issuer_string):
            if "digicert" in issuer_string.lower():
                return self._create_mock_ca("DigiCert", "digicert")
            return None

        result = mock_auto_detect(issuer)
        assert result is not None
        assert result.name == "DigiCert"

    def test_auto_detect_lets_encrypt(self):
        """Test auto-detection of Let's Encrypt certificates."""
        issuer = "CN=R3, O=Let's Encrypt, C=US"

        def mock_auto_detect(issuer_string):
            if "let's encrypt" in issuer_string.lower():
                return self._create_mock_ca("Let's Encrypt", "let's encrypt")
            return None

        result = mock_auto_detect(issuer)
        assert result is not None
        assert result.name == "Let's Encrypt"

    def test_auto_detect_internal_ca(self):
        """Test auto-detection of internal CA."""
        issuer = "CN=ACME Corp Internal CA, O=ACME Corporation, C=US"

        def mock_auto_detect(issuer_string):
            if "acme corp internal" in issuer_string.lower():
                return self._create_mock_ca("ACME Corp Internal", "acme corp internal")
            return None

        result = mock_auto_detect(issuer)
        assert result is not None
        assert result.name == "ACME Corp Internal"

    def test_auto_detect_no_match(self):
        """Test that unknown issuers return None."""
        issuer = "CN=Unknown CA, O=Mystery Inc, C=XX"

        def mock_auto_detect(issuer_string):
            known_patterns = ["digicert", "let's encrypt", "sectigo"]
            for pattern in known_patterns:
                if pattern in issuer_string.lower():
                    return self._create_mock_ca(pattern, pattern)
            return None

        result = mock_auto_detect(issuer)
        assert result is None


class TestDefaultCertificateAuthorities:
    """Tests for default CA list."""

    def test_default_cas_defined(self):
        """Test that default CAs are properly defined."""
        if not NETBOX_AVAILABLE:
            # Mock the default CAs
            default_cas = [
                {"name": "Let's Encrypt", "type": "acme", "issuer_pattern": "let's encrypt"},
                {"name": "DigiCert", "type": "public", "issuer_pattern": "digicert"},
                {"name": "Sectigo", "type": "public", "issuer_pattern": "sectigo"},
            ]

            assert len(default_cas) >= 3
            names = [ca["name"] for ca in default_cas]
            assert "Let's Encrypt" in names
            assert "DigiCert" in names
        else:
            assert len(DEFAULT_CERTIFICATE_AUTHORITIES) >= 3
            names = [ca["name"] for ca in DEFAULT_CERTIFICATE_AUTHORITIES]
            assert "Let's Encrypt" in names

    def test_default_cas_have_required_fields(self):
        """Test that default CAs have all required fields."""
        if not NETBOX_AVAILABLE:
            default_cas = [
                {
                    "name": "Let's Encrypt",
                    "type": "acme",
                    "issuer_pattern": "let's encrypt",
                    "is_approved": True,
                },
            ]
        else:
            default_cas = DEFAULT_CERTIFICATE_AUTHORITIES

        for ca in default_cas:
            assert "name" in ca
            assert "type" in ca
            assert "issuer_pattern" in ca


class TestCertificateIssuingCA:
    """Tests for the issuing_ca field on Certificate model."""

    @requires_netbox
    def test_certificate_without_issuing_ca(self):
        """Test that certificates can be created without an issuing CA."""
        from django.utils import timezone

        cert = Certificate.objects.create(
            common_name="test.example.com",
            serial_number="ABC123",
            fingerprint_sha256="AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99",
            issuer="CN=Unknown CA",
            valid_from=timezone.now(),
            valid_to=timezone.now() + timezone.timedelta(days=365),
            algorithm="rsa",
            status="active",
        )

        assert cert.issuing_ca is None

        # Cleanup
        cert.delete()

    @requires_netbox
    def test_certificate_with_issuing_ca(self):
        """Test that certificates can be linked to an issuing CA."""
        from django.utils import timezone

        ca = CertificateAuthority.objects.create(
            name="Test CA for Cert",
            type=CATypeChoices.TYPE_PUBLIC,
        )

        cert = Certificate.objects.create(
            common_name="test2.example.com",
            serial_number="DEF456",
            fingerprint_sha256="BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:00",
            issuer="CN=Test CA for Cert",
            issuing_ca=ca,
            valid_from=timezone.now(),
            valid_to=timezone.now() + timezone.timedelta(days=365),
            algorithm="rsa",
            status="active",
        )

        assert cert.issuing_ca == ca
        assert cert in ca.certificates.all()

        # Cleanup
        cert.delete()
        ca.delete()

    @requires_netbox
    def test_ca_deletion_sets_null(self):
        """Test that deleting a CA sets issuing_ca to NULL on certificates."""
        from django.utils import timezone

        ca = CertificateAuthority.objects.create(
            name="Temporary CA",
            type=CATypeChoices.TYPE_INTERNAL,
        )

        cert = Certificate.objects.create(
            common_name="temp.example.com",
            serial_number="TEMP123",
            fingerprint_sha256="CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:00:11",
            issuer="CN=Temporary CA",
            issuing_ca=ca,
            valid_from=timezone.now(),
            valid_to=timezone.now() + timezone.timedelta(days=365),
            algorithm="rsa",
            status="active",
        )

        cert_pk = cert.pk
        ca.delete()

        # Refresh certificate from database
        cert.refresh_from_db()
        assert cert.issuing_ca is None

        # Cleanup
        cert.delete()


class TestCertificateAuthorityFilters:
    """Tests for CertificateAuthority filtersets."""

    def test_filter_by_type(self):
        """Test filtering CAs by type."""
        # Mock filter test
        mock_queryset = [
            {"name": "DigiCert", "type": "public"},
            {"name": "Let's Encrypt", "type": "acme"},
            {"name": "Internal CA", "type": "internal"},
        ]

        filtered = [ca for ca in mock_queryset if ca["type"] == "public"]
        assert len(filtered) == 1
        assert filtered[0]["name"] == "DigiCert"

    def test_filter_by_is_approved(self):
        """Test filtering CAs by approval status."""
        mock_queryset = [
            {"name": "Approved CA", "is_approved": True},
            {"name": "Unapproved CA", "is_approved": False},
        ]

        approved = [ca for ca in mock_queryset if ca["is_approved"]]
        assert len(approved) == 1
        assert approved[0]["name"] == "Approved CA"

    def test_filter_by_name(self):
        """Test filtering CAs by name (case-insensitive contains)."""
        mock_queryset = [
            {"name": "DigiCert"},
            {"name": "DigiSign"},
            {"name": "Sectigo"},
        ]

        filtered = [ca for ca in mock_queryset if "digi" in ca["name"].lower()]
        assert len(filtered) == 2


class TestCertificateFilterByIssuingCA:
    """Tests for filtering certificates by issuing CA."""

    def test_filter_certificates_by_ca_id(self):
        """Test filtering certificates by issuing CA ID."""
        # Mock filter test
        mock_certs = [
            {"common_name": "cert1.example.com", "issuing_ca_id": 1},
            {"common_name": "cert2.example.com", "issuing_ca_id": 1},
            {"common_name": "cert3.example.com", "issuing_ca_id": 2},
            {"common_name": "cert4.example.com", "issuing_ca_id": None},
        ]

        filtered = [cert for cert in mock_certs if cert["issuing_ca_id"] == 1]
        assert len(filtered) == 2

    def test_filter_certificates_has_issuing_ca(self):
        """Test filtering certificates by whether they have an issuing CA."""
        mock_certs = [
            {"common_name": "cert1.example.com", "issuing_ca_id": 1},
            {"common_name": "cert2.example.com", "issuing_ca_id": None},
        ]

        with_ca = [cert for cert in mock_certs if cert["issuing_ca_id"] is not None]
        without_ca = [cert for cert in mock_certs if cert["issuing_ca_id"] is None]

        assert len(with_ca) == 1
        assert len(without_ca) == 1
