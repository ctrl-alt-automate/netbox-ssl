"""
Certificate Authority model for tracking CAs used by the organization.

This model stores metadata about Certificate Authorities, enabling
auto-detection of issuing CAs and filtering certificates by CA.
"""

from django.db import models
from django.urls import reverse
from netbox.models import NetBoxModel
from utilities.choices import ChoiceSet


class CATypeChoices(ChoiceSet):
    """Type choices for Certificate Authorities."""

    TYPE_PUBLIC = "public"
    TYPE_INTERNAL = "internal"
    TYPE_ACME = "acme"

    CHOICES = [
        (TYPE_PUBLIC, "Public CA", "blue"),
        (TYPE_INTERNAL, "Internal CA", "green"),
        (TYPE_ACME, "ACME Provider", "purple"),
    ]


class CertificateAuthority(NetBoxModel):
    """
    A Certificate Authority used by the organization.

    This model tracks CA metadata for organizational purposes.
    It does NOT store CA certificates - chain validation uses
    the certificate's own issuer_chain field.
    """

    name = models.CharField(
        max_length=100,
        unique=True,
        help_text="CA display name (e.g., 'Let's Encrypt', 'DigiCert')",
    )

    type = models.CharField(
        max_length=20,
        choices=CATypeChoices,
        default=CATypeChoices.TYPE_PUBLIC,
        help_text="Type of Certificate Authority",
    )

    description = models.TextField(
        blank=True,
        help_text="Additional information about this CA",
    )

    # Identification - for auto-matching certificates to CAs
    issuer_pattern = models.CharField(
        max_length=255,
        blank=True,
        help_text="Pattern to match in certificate issuer field (case-insensitive)",
    )

    # Contact & links
    website_url = models.URLField(
        blank=True,
        help_text="CA website URL",
    )

    portal_url = models.URLField(
        blank=True,
        help_text="Certificate management portal URL",
    )

    contact_email = models.EmailField(
        blank=True,
        help_text="Contact email for CA issues",
    )

    # Status
    is_approved = models.BooleanField(
        default=True,
        help_text="Whether this CA is approved for use in the organization",
    )

    class Meta:
        ordering = ["name"]
        verbose_name = "Certificate Authority"
        verbose_name_plural = "Certificate Authorities"

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("plugins:netbox_ssl:certificateauthority", args=[self.pk])

    @property
    def certificate_count(self):
        """Return the number of certificates issued by this CA."""
        return self.certificates.count()

    @classmethod
    def auto_detect(cls, issuer_string):
        """
        Try to match an issuer string to a known CA.

        Args:
            issuer_string: The issuer DN from a certificate

        Returns:
            CertificateAuthority instance or None
        """
        if not issuer_string:
            return None

        issuer_lower = issuer_string.lower()
        for ca in cls.objects.filter(issuer_pattern__isnull=False).exclude(issuer_pattern=""):
            if ca.issuer_pattern.lower() in issuer_lower:
                return ca
        return None


# Default CAs to pre-populate on plugin install
DEFAULT_CERTIFICATE_AUTHORITIES = [
    {
        "name": "Let's Encrypt",
        "type": CATypeChoices.TYPE_ACME,
        "issuer_pattern": "Let's Encrypt",
        "website_url": "https://letsencrypt.org",
        "description": "Free, automated, and open Certificate Authority",
        "is_approved": True,
    },
    {
        "name": "DigiCert",
        "type": CATypeChoices.TYPE_PUBLIC,
        "issuer_pattern": "DigiCert",
        "website_url": "https://www.digicert.com",
        "description": "Commercial Certificate Authority",
        "is_approved": True,
    },
    {
        "name": "Sectigo",
        "type": CATypeChoices.TYPE_PUBLIC,
        "issuer_pattern": "Sectigo",
        "website_url": "https://www.sectigo.com",
        "description": "Commercial Certificate Authority (formerly Comodo CA)",
        "is_approved": True,
    },
    {
        "name": "GlobalSign",
        "type": CATypeChoices.TYPE_PUBLIC,
        "issuer_pattern": "GlobalSign",
        "website_url": "https://www.globalsign.com",
        "description": "Commercial Certificate Authority",
        "is_approved": True,
    },
    {
        "name": "ZeroSSL",
        "type": CATypeChoices.TYPE_ACME,
        "issuer_pattern": "ZeroSSL",
        "website_url": "https://zerossl.com",
        "description": "Free SSL certificates with ACME support",
        "is_approved": True,
    },
    {
        "name": "Google Trust Services",
        "type": CATypeChoices.TYPE_PUBLIC,
        "issuer_pattern": "Google Trust Services",
        "website_url": "https://pki.goog",
        "description": "Google's Certificate Authority",
        "is_approved": True,
    },
]
