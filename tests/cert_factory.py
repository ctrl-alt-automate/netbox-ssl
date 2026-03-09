"""
Certificate factory for generating self-signed X.509 certificates in tests.

Uses the `cryptography` library to generate certificates with configurable
properties. No Django dependency — can be used in any test context.

Usage:
    from cert_factory import CertFactory

    # Single certificate
    pem = CertFactory.create(cn="example.com", sans=["www.example.com"])

    # Renewal pair (same CN, different serial/dates)
    old_pem, new_pem = CertFactory.create_renewal_pair(cn="renew.example.com")
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


class CertFactory:
    """Generate self-signed X.509 certificates for testing."""

    @staticmethod
    def create(
        cn: str = "test.example.com",
        sans: list[str] | None = None,
        valid_days: int = 365,
        expired: bool = False,
        key_size: int = 2048,
        issuer_cn: str = "Test CA",
        issuer_o: str = "Test Organization",
    ) -> str:
        """Generate a self-signed certificate and return PEM string.

        Args:
            cn: Common Name for the certificate subject.
            sans: Subject Alternative Names (DNS names). Defaults to [cn].
            valid_days: Number of days the certificate is valid.
            expired: If True, generate an already-expired certificate.
            key_size: RSA key size in bits.
            issuer_cn: Common Name for the issuer.
            issuer_o: Organization for the issuer.

        Returns:
            PEM-encoded certificate as a string.
        """
        if sans is None:
            sans = [cn]

        # Generate RSA key pair
        key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

        # Build subject
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "NL"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Organization"),
                x509.NameAttribute(NameOID.COMMON_NAME, cn),
            ]
        )

        # Build issuer
        issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "NL"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuer_o),
                x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn),
            ]
        )

        # Calculate validity period
        now = datetime.now(timezone.utc)
        if expired:
            not_before = now - timedelta(days=400)
            not_after = now - timedelta(days=35)
        else:
            not_before = now - timedelta(hours=1)
            not_after = now + timedelta(days=valid_days)

        # Unique serial number per invocation
        serial = int.from_bytes(os.urandom(16), byteorder="big")

        # Build SAN extension
        san_names = [x509.DNSName(name) for name in sans]

        # Build certificate
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(serial)
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.SubjectAlternativeName(san_names), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )

        return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")

    @staticmethod
    def create_renewal_pair(
        cn: str = "renew.example.com",
        sans: list[str] | None = None,
    ) -> tuple[str, str]:
        """Generate a pair of certificates for renewal testing.

        Both certificates have the same CN but different serial numbers and dates.
        The old certificate expires in 10 days (triggering renewal detection).
        The new certificate is valid for 365 days.

        Args:
            cn: Common Name shared by both certificates.
            sans: Subject Alternative Names. Defaults to [cn].

        Returns:
            Tuple of (old_pem, new_pem).
        """
        old_pem = CertFactory.create(
            cn=cn,
            sans=sans,
            valid_days=10,  # Expires soon — triggers renewal detection
        )

        new_pem = CertFactory.create(
            cn=cn,
            sans=sans,
            valid_days=365,
        )

        return old_pem, new_pem
