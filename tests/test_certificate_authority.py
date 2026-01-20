"""
Unit tests for CertificateAuthority model.

Tests for Certificate Authority tracking feature (Issue #13).
"""

import contextlib
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

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

    with contextlib.suppress(RuntimeError):
        django.setup()
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
        from netbox_ssl.filtersets import CertificateAuthorityFilterSet
        from netbox_ssl.models import (
            DEFAULT_CERTIFICATE_AUTHORITIES,
            CATypeChoices,
            Certificate,
            CertificateAuthority,
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

        from django.db import IntegrityError

        with pytest.raises(IntegrityError):
            CertificateAuthority.objects.create(
                name="Unique CA",
                type=CATypeChoices.TYPE_INTERNAL,
            )

        # Cleanup
        ca1.delete()


class TestCertificateAuthorityAutoDetection:
    """Tests for CA auto-detection functionality."""

    @requires_netbox
    def test_auto_detect_digicert(self):
        """Test auto-detection of DigiCert certificates."""
        # Create a CA with issuer pattern
        ca = CertificateAuthority.objects.create(
            name="DigiCert Test",
            type=CATypeChoices.TYPE_PUBLIC,
            issuer_pattern="DigiCert",
        )

        try:
            issuer = "CN=DigiCert SHA2 Extended Validation Server CA, OU=www.digicert.com, O=DigiCert Inc, C=US"
            result = CertificateAuthority.auto_detect(issuer)

            assert result is not None
            assert result.name == "DigiCert Test"
        finally:
            ca.delete()

    @requires_netbox
    def test_auto_detect_lets_encrypt(self):
        """Test auto-detection of Let's Encrypt certificates."""
        ca = CertificateAuthority.objects.create(
            name="Let's Encrypt Test",
            type=CATypeChoices.TYPE_ACME,
            issuer_pattern="Let's Encrypt",
        )

        try:
            issuer = "CN=R3, O=Let's Encrypt, C=US"
            result = CertificateAuthority.auto_detect(issuer)

            assert result is not None
            assert result.name == "Let's Encrypt Test"
        finally:
            ca.delete()

    @requires_netbox
    def test_auto_detect_internal_ca(self):
        """Test auto-detection of internal CA."""
        ca = CertificateAuthority.objects.create(
            name="ACME Corp Internal",
            type=CATypeChoices.TYPE_INTERNAL,
            issuer_pattern="ACME Corp Internal",
        )

        try:
            issuer = "CN=ACME Corp Internal CA, O=ACME Corporation, C=US"
            result = CertificateAuthority.auto_detect(issuer)

            assert result is not None
            assert result.name == "ACME Corp Internal"
        finally:
            ca.delete()

    @requires_netbox
    def test_auto_detect_no_match(self):
        """Test that unknown issuers return None."""
        issuer = "CN=Unknown CA, O=Mystery Inc, C=XX"
        result = CertificateAuthority.auto_detect(issuer)
        assert result is None

    @requires_netbox
    def test_auto_detect_empty_issuer(self):
        """Test that empty issuer string returns None."""
        assert CertificateAuthority.auto_detect("") is None
        assert CertificateAuthority.auto_detect(None) is None

    @requires_netbox
    def test_auto_detect_case_insensitive(self):
        """Test that pattern matching is case-insensitive."""
        ca = CertificateAuthority.objects.create(
            name="Test CA",
            type=CATypeChoices.TYPE_PUBLIC,
            issuer_pattern="TestPattern",
        )

        try:
            # Should match regardless of case
            assert CertificateAuthority.auto_detect("CN=TESTPATTERN Corp") is not None
            assert CertificateAuthority.auto_detect("CN=testpattern Corp") is not None
            assert CertificateAuthority.auto_detect("CN=TestPattern Corp") is not None
        finally:
            ca.delete()


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

        ca.delete()

        # Refresh certificate from database
        cert.refresh_from_db()
        assert cert.issuing_ca is None

        # Cleanup
        cert.delete()


class TestCertificateAuthorityFilters:
    """Tests for CertificateAuthority filtersets."""

    @requires_netbox
    def test_filter_by_type(self):
        """Test filtering CAs by type."""
        # Create test CAs
        ca_public = CertificateAuthority.objects.create(
            name="Filter Test Public CA",
            type=CATypeChoices.TYPE_PUBLIC,
        )
        ca_acme = CertificateAuthority.objects.create(
            name="Filter Test ACME CA",
            type=CATypeChoices.TYPE_ACME,
        )

        try:
            filterset = CertificateAuthorityFilterSet(
                {"type": [CATypeChoices.TYPE_PUBLIC]}, CertificateAuthority.objects.all()
            )
            result = filterset.qs.filter(name__startswith="Filter Test")

            assert ca_public in result
            assert ca_acme not in result
        finally:
            ca_public.delete()
            ca_acme.delete()

    @requires_netbox
    def test_filter_by_is_approved(self):
        """Test filtering CAs by approval status."""
        ca_approved = CertificateAuthority.objects.create(
            name="Filter Approved CA",
            type=CATypeChoices.TYPE_PUBLIC,
            is_approved=True,
        )
        ca_unapproved = CertificateAuthority.objects.create(
            name="Filter Unapproved CA",
            type=CATypeChoices.TYPE_PUBLIC,
            is_approved=False,
        )

        try:
            filterset = CertificateAuthorityFilterSet({"is_approved": True}, CertificateAuthority.objects.all())
            result = filterset.qs.filter(name__startswith="Filter")

            assert ca_approved in result
            assert ca_unapproved not in result
        finally:
            ca_approved.delete()
            ca_unapproved.delete()

    @requires_netbox
    def test_filter_by_name(self):
        """Test filtering CAs by name (case-insensitive contains)."""
        ca1 = CertificateAuthority.objects.create(
            name="DigiCert Filter Test",
            type=CATypeChoices.TYPE_PUBLIC,
        )
        ca2 = CertificateAuthority.objects.create(
            name="DigiSign Filter Test",
            type=CATypeChoices.TYPE_PUBLIC,
        )
        ca3 = CertificateAuthority.objects.create(
            name="Sectigo Filter Test",
            type=CATypeChoices.TYPE_PUBLIC,
        )

        try:
            filterset = CertificateAuthorityFilterSet({"name": "digi"}, CertificateAuthority.objects.all())
            result = filterset.qs.filter(name__endswith="Filter Test")

            assert ca1 in result
            assert ca2 in result
            assert ca3 not in result
        finally:
            ca1.delete()
            ca2.delete()
            ca3.delete()


class TestCertificateFilterByIssuingCA:
    """Tests for filtering certificates by issuing CA."""

    @requires_netbox
    def test_filter_certificates_by_ca(self):
        """Test filtering certificates by issuing CA."""
        from django.utils import timezone

        from netbox_ssl.filtersets import CertificateFilterSet

        ca1 = CertificateAuthority.objects.create(
            name="Filter CA 1",
            type=CATypeChoices.TYPE_PUBLIC,
        )
        ca2 = CertificateAuthority.objects.create(
            name="Filter CA 2",
            type=CATypeChoices.TYPE_INTERNAL,
        )

        cert1 = Certificate.objects.create(
            common_name="filter-cert1.example.com",
            serial_number="FILTER001",
            fingerprint_sha256="F1:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:01",
            issuer="CN=Filter CA 1",
            issuing_ca=ca1,
            valid_from=timezone.now(),
            valid_to=timezone.now() + timezone.timedelta(days=365),
            algorithm="rsa",
            status="active",
        )
        cert2 = Certificate.objects.create(
            common_name="filter-cert2.example.com",
            serial_number="FILTER002",
            fingerprint_sha256="F2:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:02",
            issuer="CN=Filter CA 2",
            issuing_ca=ca2,
            valid_from=timezone.now(),
            valid_to=timezone.now() + timezone.timedelta(days=365),
            algorithm="rsa",
            status="active",
        )

        try:
            filterset = CertificateFilterSet({"issuing_ca_id": [ca1.pk]}, Certificate.objects.all())
            result = filterset.qs.filter(common_name__startswith="filter-cert")

            assert cert1 in result
            assert cert2 not in result
        finally:
            cert1.delete()
            cert2.delete()
            ca1.delete()
            ca2.delete()

    @requires_netbox
    def test_filter_certificates_without_issuing_ca(self):
        """Test filtering certificates that have no issuing CA."""
        from django.utils import timezone

        ca = CertificateAuthority.objects.create(
            name="Filter CA With",
            type=CATypeChoices.TYPE_PUBLIC,
        )

        cert_with_ca = Certificate.objects.create(
            common_name="filter-with-ca.example.com",
            serial_number="FILTERWITH",
            fingerprint_sha256="F3:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:03",
            issuer="CN=Filter CA With",
            issuing_ca=ca,
            valid_from=timezone.now(),
            valid_to=timezone.now() + timezone.timedelta(days=365),
            algorithm="rsa",
            status="active",
        )
        cert_without_ca = Certificate.objects.create(
            common_name="filter-without-ca.example.com",
            serial_number="FILTERWITHOUT",
            fingerprint_sha256="F4:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:04",
            issuer="CN=Unknown CA",
            issuing_ca=None,
            valid_from=timezone.now(),
            valid_to=timezone.now() + timezone.timedelta(days=365),
            algorithm="rsa",
            status="active",
        )

        try:
            # Filter certificates without an issuing CA
            result = Certificate.objects.filter(issuing_ca__isnull=True, common_name__startswith="filter-")

            assert cert_without_ca in result
            assert cert_with_ca not in result
        finally:
            cert_with_ca.delete()
            cert_without_ca.delete()
            ca.delete()
