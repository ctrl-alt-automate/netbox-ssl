"""
Certificate Authority detection utilities.

Provides functionality to automatically detect and match Certificate Authorities
based on certificate issuer strings.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from netbox_ssl.models import CertificateAuthority

logger = logging.getLogger(__name__)


def detect_issuing_ca(issuer: str) -> CertificateAuthority | None:
    """
    Find a CertificateAuthority that matches the given issuer string.

    Searches all CertificateAuthority records with a non-empty issuer_pattern
    and returns the first one where the pattern is found in the issuer string.
    Matching is case-insensitive.

    Args:
        issuer: The issuer Distinguished Name from a certificate.

    Returns:
        The matching CertificateAuthority, or None if no match is found.

    Example:
        >>> issuer = "C=US, O=Let's Encrypt, CN=E7"
        >>> ca = detect_issuing_ca(issuer)
        >>> ca.name
        "Let's Encrypt"
    """
    # Import here to avoid circular imports
    from netbox_ssl.models import CertificateAuthority

    if not issuer:
        return None

    issuer_lower = issuer.lower()

    # Find CAs with issuer patterns
    cas_with_patterns = CertificateAuthority.objects.exclude(
        issuer_pattern__isnull=True
    ).exclude(issuer_pattern="")

    for ca in cas_with_patterns:
        if ca.issuer_pattern.lower() in issuer_lower:
            logger.debug(
                "Detected CA '%s' for issuer '%s' (pattern: '%s')",
                ca.name,
                issuer,
                ca.issuer_pattern,
            )
            return ca

    logger.debug("No CA detected for issuer '%s'", issuer)
    return None


def get_or_create_ca_from_issuer(issuer: str) -> CertificateAuthority | None:
    """
    Find or create a CertificateAuthority based on the issuer string.

    First attempts to detect an existing CA using detect_issuing_ca().
    If no match is found and auto-creation is enabled, creates a new CA
    with a best-guess name and pattern extracted from the issuer.

    Note: Auto-creation is disabled by default and must be enabled via
    plugin configuration: auto_create_ca_on_import = True

    Args:
        issuer: The issuer Distinguished Name from a certificate.

    Returns:
        The matching or newly created CertificateAuthority, or None.
    """
    from django.conf import settings

    # First try to detect existing CA
    ca = detect_issuing_ca(issuer)
    if ca:
        return ca

    # Check if auto-creation is enabled
    plugin_settings = settings.PLUGINS_CONFIG.get("netbox_ssl", {})
    if not plugin_settings.get("auto_create_ca_on_import", False):
        return None

    # Auto-create CA from issuer
    from netbox_ssl.models import CertificateAuthority

    # Extract CN from issuer for the CA name
    ca_name = _extract_cn_from_issuer(issuer)
    if not ca_name:
        # Fallback: use first part of issuer
        ca_name = issuer[:100] if len(issuer) > 100 else issuer

    # Create pattern from the extracted name (lowercase for matching)
    pattern = ca_name.lower()

    # Determine CA type based on common patterns
    ca_type = _guess_ca_type(issuer)

    # Create the CA
    ca, created = CertificateAuthority.objects.get_or_create(
        name=ca_name,
        defaults={
            "type": ca_type,
            "issuer_pattern": pattern,
            "description": f"Auto-created from certificate issuer: {issuer[:200]}",
            "is_approved": False,  # Not approved by default for auto-created CAs
        },
    )

    if created:
        logger.info("Auto-created CA '%s' from issuer '%s'", ca_name, issuer)
    else:
        logger.debug("Found existing CA '%s' by name", ca_name)

    return ca


def _extract_cn_from_issuer(issuer: str) -> str | None:
    """
    Extract the Common Name (CN) from an issuer Distinguished Name.

    Args:
        issuer: The issuer DN string (e.g., "C=US, O=Let's Encrypt, CN=E7")

    Returns:
        The CN value, or None if not found.
    """
    # Try to find CN= in the issuer (handles both "CN=" and "CN = ")
    parts = issuer.split(",")
    for part in parts:
        part = part.strip()
        part_upper = part.upper()
        if part_upper.startswith("CN=") or part_upper.startswith("CN ="):
            # Find the = and return everything after it
            eq_pos = part.find("=")
            if eq_pos != -1:
                return part[eq_pos + 1:].strip()

    # Also try O= (Organization) as fallback
    for part in parts:
        part = part.strip()
        part_upper = part.upper()
        if part_upper.startswith("O=") or part_upper.startswith("O ="):
            eq_pos = part.find("=")
            if eq_pos != -1:
                return part[eq_pos + 1:].strip()

    return None


def _guess_ca_type(issuer: str) -> str:
    """
    Guess the CA type based on the issuer string.

    Args:
        issuer: The issuer DN string.

    Returns:
        CA type: 'acme', 'public', or 'internal'
    """
    issuer_lower = issuer.lower()

    # ACME/Let's Encrypt patterns
    acme_patterns = ["let's encrypt", "letsencrypt", "acme", "zerossl", "buypass"]
    if any(pattern in issuer_lower for pattern in acme_patterns):
        return "acme"

    # Known public CA patterns
    public_patterns = [
        "digicert",
        "sectigo",
        "comodo",
        "globalsign",
        "godaddy",
        "entrust",
        "geotrust",
        "thawte",
        "rapidssl",
        "symantec",
        "verisign",
        "amazon",
        "google trust",
        "microsoft",
        "apple",
        "baltimore",
        "usertrust",
    ]
    if any(pattern in issuer_lower for pattern in public_patterns):
        return "public"

    # Default to internal for unknown CAs
    return "internal"
