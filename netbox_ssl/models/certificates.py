"""
Certificate model for storing TLS/SSL certificate metadata.

This model represents a unique certificate as a "Library Item" that can be
assigned to multiple services, devices, or virtual machines.
"""

from datetime import date

from django.contrib.postgres.fields import ArrayField
from django.contrib.postgres.indexes import GinIndex
from django.db import models
from django.urls import reverse
from django.utils import timezone
from netbox.models import NetBoxModel
from utilities.choices import ChoiceSet


class CertificateStatusChoices(ChoiceSet):
    """Status choices for certificates."""

    STATUS_ACTIVE = "active"
    STATUS_EXPIRED = "expired"
    STATUS_REPLACED = "replaced"
    STATUS_REVOKED = "revoked"
    STATUS_PENDING = "pending"

    CHOICES = [
        (STATUS_ACTIVE, "Active", "green"),
        (STATUS_EXPIRED, "Expired", "red"),
        (STATUS_REPLACED, "Replaced", "gray"),
        (STATUS_REVOKED, "Revoked", "orange"),
        (STATUS_PENDING, "Pending", "blue"),
    ]


class CertificateAlgorithmChoices(ChoiceSet):
    """Key algorithm choices."""

    ALGORITHM_RSA = "rsa"
    ALGORITHM_ECDSA = "ecdsa"
    ALGORITHM_ED25519 = "ed25519"

    CHOICES = [
        (ALGORITHM_RSA, "RSA", "blue"),
        (ALGORITHM_ECDSA, "ECDSA", "green"),
        (ALGORITHM_ED25519, "Ed25519", "purple"),
    ]


class ACMEProviderChoices(ChoiceSet):
    """ACME provider choices."""

    PROVIDER_LETSENCRYPT = "letsencrypt"
    PROVIDER_LETSENCRYPT_STAGING = "letsencrypt_staging"
    PROVIDER_ZEROSSL = "zerossl"
    PROVIDER_BUYPASS = "buypass"
    PROVIDER_GOOGLE = "google"
    PROVIDER_DIGICERT = "digicert"
    PROVIDER_SECTIGO = "sectigo"
    PROVIDER_OTHER = "other"

    CHOICES = [
        (PROVIDER_LETSENCRYPT, "Let's Encrypt", "green"),
        (PROVIDER_LETSENCRYPT_STAGING, "Let's Encrypt (Staging)", "yellow"),
        (PROVIDER_ZEROSSL, "ZeroSSL", "blue"),
        (PROVIDER_BUYPASS, "Buypass", "cyan"),
        (PROVIDER_GOOGLE, "Google Trust Services", "red"),
        (PROVIDER_DIGICERT, "DigiCert", "purple"),
        (PROVIDER_SECTIGO, "Sectigo", "orange"),
        (PROVIDER_OTHER, "Other", "gray"),
    ]


class ACMEChallengeTypeChoices(ChoiceSet):
    """ACME challenge type choices."""

    CHALLENGE_HTTP01 = "http-01"
    CHALLENGE_DNS01 = "dns-01"
    CHALLENGE_TLS_ALPN01 = "tls-alpn-01"
    CHALLENGE_UNKNOWN = "unknown"

    CHOICES = [
        (CHALLENGE_HTTP01, "HTTP-01", "blue"),
        (CHALLENGE_DNS01, "DNS-01", "green"),
        (CHALLENGE_TLS_ALPN01, "TLS-ALPN-01", "purple"),
        (CHALLENGE_UNKNOWN, "Unknown", "gray"),
    ]


class Certificate(NetBoxModel):
    """
    A TLS/SSL certificate.

    This model stores certificate metadata extracted from X.509 certificates.
    Private keys are never stored; only a location hint is provided.
    """

    # Primary identification
    common_name = models.CharField(
        max_length=255,
        help_text="Primary Common Name (CN) of the certificate",
    )
    serial_number = models.CharField(
        max_length=255,
        help_text="Certificate serial number (hex format)",
    )
    fingerprint_sha256 = models.CharField(
        max_length=95,  # SHA256 with colons: 64 hex + 31 colons
        unique=True,
        help_text="SHA256 fingerprint for quick verification",
    )

    # Issuer information
    issuer = models.CharField(
        max_length=512,
        help_text="Certificate issuer (CA) distinguished name",
    )
    issuer_chain = models.TextField(
        blank=True,
        help_text="Full certificate chain (PEM format, intermediates + root)",
    )

    # Validity period
    valid_from = models.DateTimeField(
        help_text="Certificate validity start date",
    )
    valid_to = models.DateTimeField(
        help_text="Certificate expiration date",
    )

    # Subject Alternative Names
    sans = ArrayField(
        models.CharField(max_length=255),
        blank=True,
        default=list,
        help_text="Subject Alternative Names (DNS names, IPs, etc.)",
    )

    # Key information
    key_size = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text="Key size in bits (e.g., 2048, 4096)",
    )
    algorithm = models.CharField(
        max_length=20,
        choices=CertificateAlgorithmChoices,
        help_text="Key algorithm (RSA, ECDSA, Ed25519)",
    )

    # Status tracking
    status = models.CharField(
        max_length=20,
        choices=CertificateStatusChoices,
        default=CertificateStatusChoices.STATUS_ACTIVE,
        help_text="Current status of the certificate",
    )

    # Private key location hint (never store actual keys!)
    private_key_location = models.CharField(
        max_length=512,
        blank=True,
        help_text="Hint for private key location (e.g., Vault path)",
    )

    # Renewal tracking (Janus workflow)
    replaced_by = models.ForeignKey(
        "self",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="replaces",
        help_text="Successor certificate (for renewal tracking)",
    )

    # Multi-tenancy support
    tenant = models.ForeignKey(
        to="tenancy.Tenant",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="certificates",
        help_text="Tenant this certificate belongs to",
    )

    # Raw certificate data (PEM without private key)
    pem_content = models.TextField(
        blank=True,
        help_text="Certificate in PEM format (public certificate only)",
    )

    # ACME certificate tracking
    is_acme = models.BooleanField(
        default=False,
        help_text="Whether this certificate was issued via ACME protocol",
    )
    acme_provider = models.CharField(
        max_length=30,
        choices=ACMEProviderChoices,
        blank=True,
        help_text="ACME provider (e.g., Let's Encrypt, ZeroSSL)",
    )
    acme_account_email = models.EmailField(
        blank=True,
        help_text="Email address associated with the ACME account",
    )
    acme_challenge_type = models.CharField(
        max_length=20,
        choices=ACMEChallengeTypeChoices,
        blank=True,
        help_text="Challenge type used for domain validation",
    )
    acme_server_url = models.URLField(
        blank=True,
        max_length=500,
        help_text="ACME server URL (e.g., https://acme-v02.api.letsencrypt.org/directory)",
    )
    acme_auto_renewal = models.BooleanField(
        default=False,
        help_text="Whether automatic renewal is configured",
    )
    acme_last_renewed = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When this certificate was last renewed via ACME",
    )
    acme_renewal_days = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        default=30,
        help_text="Days before expiry to attempt renewal",
    )

    class Meta:
        ordering = ["-valid_to", "common_name"]
        constraints = [
            models.UniqueConstraint(
                fields=["serial_number", "issuer"],
                name="unique_serial_issuer",
            ),
        ]
        indexes = [
            GinIndex(fields=["sans"], name="netbox_ssl_cert_sans_gin"),
        ]

    def __str__(self):
        if self.valid_to:
            return f"{self.common_name} (expires: {self.valid_to.strftime('%Y-%m-%d')})"
        return self.common_name

    def get_absolute_url(self):
        return reverse("plugins:netbox_ssl:certificate", args=[self.pk])

    @property
    def days_remaining(self):
        """Calculate days until expiration."""
        if self.valid_to:
            delta = self.valid_to.date() - date.today()
            return delta.days
        return None

    @property
    def days_expired(self):
        """Calculate days since expiration (absolute value for display)."""
        if self.days_remaining is not None and self.days_remaining < 0:
            return abs(self.days_remaining)
        return 0

    @property
    def is_expired(self):
        """Check if the certificate has expired."""
        return self.valid_to and self.valid_to < timezone.now()

    @property
    def is_expiring_soon(self):
        """Check if the certificate expires within warning threshold."""
        if self.days_remaining is None:
            return False
        # Default warning threshold: 30 days
        return 0 < self.days_remaining <= 30

    @property
    def is_critical(self):
        """Check if the certificate is in critical expiry state."""
        if self.days_remaining is None:
            return False
        # Default critical threshold: 14 days
        return 0 < self.days_remaining <= 14

    @property
    def expiry_status(self):
        """Get expiry status category for dashboard."""
        if self.is_expired:
            return "expired"
        if self.is_critical:
            return "critical"
        if self.is_expiring_soon:
            return "warning"
        return "ok"

    def clean(self):
        """Validate the certificate data."""

        # Auto-update status based on expiry
        if self.is_expired and self.status == CertificateStatusChoices.STATUS_ACTIVE:
            self.status = CertificateStatusChoices.STATUS_EXPIRED

    def get_assignments(self):
        """Get all certificate assignments."""
        return self.assignments.all()

    def has_assignments(self):
        """Check if certificate has any assignments."""
        return self.assignments.exists()

    @property
    def acme_renewal_due(self):
        """Check if ACME renewal is due based on renewal_days setting."""
        if not self.is_acme or not self.acme_auto_renewal:
            return False
        if self.days_remaining is None:
            return False
        renewal_days = self.acme_renewal_days or 30
        return self.days_remaining <= renewal_days

    @property
    def acme_renewal_status(self):
        """Get ACME renewal status."""
        if not self.is_acme:
            return "not_acme"
        if not self.acme_auto_renewal:
            return "manual"
        if self.is_expired:
            return "expired"
        if self.acme_renewal_due:
            return "due"
        return "ok"

    def auto_detect_acme(self, save: bool = True):
        """
        Auto-detect if this certificate is ACME-issued based on the issuer.

        Updates is_acme and acme_provider fields based on known ACME CA patterns.

        Args:
            save: If True, save the changes to the database

        Returns:
            Tuple of (is_acme, provider) or None if not detectable
        """
        issuer_lower = self.issuer.lower()

        # Known ACME provider patterns
        acme_patterns = {
            # Let's Encrypt
            "let's encrypt": ACMEProviderChoices.PROVIDER_LETSENCRYPT,
            "letsencrypt": ACMEProviderChoices.PROVIDER_LETSENCRYPT,
            "r3, o=let's encrypt": ACMEProviderChoices.PROVIDER_LETSENCRYPT,
            "r10, o=let's encrypt": ACMEProviderChoices.PROVIDER_LETSENCRYPT,
            "r11, o=let's encrypt": ACMEProviderChoices.PROVIDER_LETSENCRYPT,
            "e1, o=let's encrypt": ACMEProviderChoices.PROVIDER_LETSENCRYPT,
            "e5, o=let's encrypt": ACMEProviderChoices.PROVIDER_LETSENCRYPT,
            "e6, o=let's encrypt": ACMEProviderChoices.PROVIDER_LETSENCRYPT,
            # Let's Encrypt Staging
            "(staging)": ACMEProviderChoices.PROVIDER_LETSENCRYPT_STAGING,
            "fake le": ACMEProviderChoices.PROVIDER_LETSENCRYPT_STAGING,
            # ZeroSSL
            "zerossl": ACMEProviderChoices.PROVIDER_ZEROSSL,
            # Buypass
            "buypass": ACMEProviderChoices.PROVIDER_BUYPASS,
            # Google Trust Services (ACME)
            "google trust services": ACMEProviderChoices.PROVIDER_GOOGLE,
            "gts ca": ACMEProviderChoices.PROVIDER_GOOGLE,
            # Sectigo (has ACME services)
            "sectigo": ACMEProviderChoices.PROVIDER_SECTIGO,
        }

        detected_provider = None
        for pattern, provider in acme_patterns.items():
            if pattern in issuer_lower:
                detected_provider = provider
                break

        if detected_provider:
            self.is_acme = True
            self.acme_provider = detected_provider
            if save:
                self.save(update_fields=["is_acme", "acme_provider"])
            return (True, detected_provider)

        return None

    @classmethod
    def get_acme_certificates(cls):
        """Get all ACME certificates."""
        return cls.objects.filter(is_acme=True)

    @classmethod
    def get_acme_renewal_due(cls):
        """Get ACME certificates due for renewal."""
        from django.db.models import F

        return cls.objects.filter(
            is_acme=True,
            acme_auto_renewal=True,
            status=CertificateStatusChoices.STATUS_ACTIVE,
        ).annotate(
            days_to_expiry=(F("valid_to") - timezone.now())
        ).filter(
            valid_to__lte=timezone.now() + timezone.timedelta(days=30)
        )
