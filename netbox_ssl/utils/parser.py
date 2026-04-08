"""
Certificate parsing utilities using the cryptography library.

Handles PEM, DER, and PKCS#7 parsing, validation, and X.509 attribute extraction.
IMPORTANT: Private keys are rejected for security reasons.
"""

import re
from dataclasses import dataclass
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs7 as x509_pkcs7
from cryptography.x509.oid import ExtensionOID, NameOID
from django.utils import timezone


class CertificateParseError(Exception):
    """Exception raised when certificate parsing fails."""

    pass


class PrivateKeyDetectedError(CertificateParseError):
    """Exception raised when a private key is detected in the input."""

    pass


@dataclass
class ParsedCertificate:
    """Container for parsed certificate data."""

    common_name: str
    serial_number: str
    fingerprint_sha256: str
    issuer: str
    valid_from: datetime
    valid_to: datetime
    sans: list[str]
    key_size: int | None
    algorithm: str
    pem_content: str
    issuer_chain: str = ""


class CertificateParser:
    """
    Parser for X.509 certificates in PEM format.

    Security: Rejects any input containing private keys.
    """

    MAX_PEM_INPUT_BYTES = 65536

    # Patterns to detect private keys
    PRIVATE_KEY_PATTERNS = [
        r"-----BEGIN\s+(?:\w+\s+)*PRIVATE\s+KEY-----",
    ]

    # Pattern to extract individual certificates
    CERT_PATTERN = re.compile(
        r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)",
        re.DOTALL,
    )

    @classmethod
    def contains_private_key(cls, pem_text: str) -> bool:
        """Check if the input contains any private key material."""
        return any(re.search(pattern, pem_text, re.IGNORECASE) for pattern in cls.PRIVATE_KEY_PATTERNS)

    @classmethod
    def extract_certificates(cls, pem_text: str) -> list[str]:
        """Extract all certificate blocks from PEM text."""
        return cls.CERT_PATTERN.findall(pem_text)

    @classmethod
    def parse(cls, pem_text: str) -> ParsedCertificate:
        """
        Parse a PEM certificate and extract all metadata.

        Args:
            pem_text: Raw PEM text (may contain certificate chain)

        Returns:
            ParsedCertificate with extracted metadata

        Raises:
            PrivateKeyDetectedError: If private key material is found
            CertificateParseError: If parsing fails
        """
        # Size guard: reject oversized input
        if len(pem_text) > cls.MAX_PEM_INPUT_BYTES:
            raise CertificateParseError(
                f"Input too large ({len(pem_text)} bytes). Maximum is {cls.MAX_PEM_INPUT_BYTES} bytes."
            )

        # Security check: reject private keys
        if cls.contains_private_key(pem_text):
            raise PrivateKeyDetectedError(
                "Private key detected in input. For security reasons, "
                "private keys cannot be stored. Please remove the private "
                "key and try again."
            )

        # Extract certificate blocks
        cert_blocks = cls.extract_certificates(pem_text)
        if not cert_blocks:
            raise CertificateParseError(
                "No valid certificate found in input. Please provide a certificate in PEM format."
            )

        # Parse the leaf certificate (first one)
        leaf_pem = cert_blocks[0]
        try:
            cert = x509.load_pem_x509_certificate(leaf_pem.encode("utf-8"))
        except Exception as e:
            raise CertificateParseError(f"Failed to parse certificate: {e}") from e

        # Extract chain (remaining certificates)
        chain_pem = "\n".join(cert_blocks[1:]) if len(cert_blocks) > 1 else ""

        return cls._build_parsed(cert, leaf_pem, chain_pem)

    @classmethod
    def _build_parsed(cls, cert: x509.Certificate, pem_content: str, chain: str) -> ParsedCertificate:
        """Build a ParsedCertificate from a cryptography x509.Certificate object."""
        common_name = cls._extract_common_name(cert)
        issuer = cls._extract_issuer(cert)
        sans = cls._extract_sans(cert)
        key_size, algorithm = cls._extract_key_info(cert)
        fingerprint = cls._calculate_fingerprint(cert)

        serial_hex = format(cert.serial_number, "x").upper()
        serial_formatted = ":".join(serial_hex[i : i + 2] for i in range(0, len(serial_hex), 2))

        return ParsedCertificate(
            common_name=common_name,
            serial_number=serial_formatted,
            fingerprint_sha256=fingerprint,
            issuer=issuer,
            valid_from=cert.not_valid_before_utc,
            valid_to=cert.not_valid_after_utc,
            sans=sans,
            key_size=key_size,
            algorithm=algorithm,
            pem_content=pem_content,
            issuer_chain=chain,
        )

    @classmethod
    def detect_format(cls, raw_data: bytes) -> str:
        """
        Auto-detect certificate format from raw bytes.

        Returns one of: 'pem', 'der', 'pkcs7_pem', 'pkcs7_der', 'unknown'.
        """
        # Try to decode as text for PEM detection
        try:
            text = raw_data.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            text = None

        if text:
            if "-----BEGIN PKCS7-----" in text or "-----BEGIN CMS-----" in text:
                return "pkcs7_pem"
            if "-----BEGIN CERTIFICATE-----" in text:
                return "pem"

        # Binary format detection: DER SEQUENCE tag
        if raw_data[:1] == b"\x30":
            # Try PKCS#7 DER first
            try:
                x509_pkcs7.load_der_pkcs7_certificates(raw_data)
                return "pkcs7_der"
            except Exception:
                pass
            # Try plain DER certificate
            try:
                x509.load_der_x509_certificate(raw_data)
                return "der"
            except Exception:
                pass

        return "unknown"

    @classmethod
    def parse_der(cls, der_data: bytes) -> ParsedCertificate:
        """
        Parse a DER-encoded X.509 certificate.

        Args:
            der_data: Raw DER bytes

        Returns:
            ParsedCertificate with extracted metadata

        Raises:
            CertificateParseError: If parsing fails
        """
        if len(der_data) > cls.MAX_PEM_INPUT_BYTES:
            raise CertificateParseError(
                f"Input too large ({len(der_data)} bytes). Maximum is {cls.MAX_PEM_INPUT_BYTES} bytes."
            )

        try:
            cert = x509.load_der_x509_certificate(der_data)
        except Exception as e:
            raise CertificateParseError(f"Failed to parse DER certificate: {e}") from e

        # Convert to PEM for storage
        pem_content = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        return cls._build_parsed(cert, pem_content, "")

    @classmethod
    def parse_pkcs7(cls, data: bytes, is_pem: bool = True) -> list[ParsedCertificate]:
        """
        Parse a PKCS#7 container and extract all certificates.

        Args:
            data: PKCS#7 data (PEM or DER encoded)
            is_pem: True for PEM, False for DER encoding

        Returns:
            List of ParsedCertificate objects

        Raises:
            CertificateParseError: If parsing fails or container is empty
        """
        if len(data) > cls.MAX_PEM_INPUT_BYTES:
            raise CertificateParseError(
                f"Input too large ({len(data)} bytes). Maximum is {cls.MAX_PEM_INPUT_BYTES} bytes."
            )

        # Check for private keys in PEM input
        if is_pem:
            text = data.decode("utf-8", errors="replace")
            if cls.contains_private_key(text):
                raise PrivateKeyDetectedError("Private key detected in PKCS#7 input. Private keys cannot be stored.")

        try:
            if is_pem:
                certs = x509_pkcs7.load_pem_pkcs7_certificates(data)
            else:
                certs = x509_pkcs7.load_der_pkcs7_certificates(data)
        except Exception as e:
            raise CertificateParseError(f"Failed to parse PKCS#7 container: {e}") from e

        if not certs:
            raise CertificateParseError("PKCS#7 container contains no certificates")

        results = []
        for cert in certs:
            pem_content = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
            results.append(cls._build_parsed(cert, pem_content, ""))

        return results

    @classmethod
    def parse_auto(cls, raw_data: bytes) -> list[ParsedCertificate]:
        """
        Auto-detect format and parse certificate(s).

        Args:
            raw_data: Raw certificate data in any supported format

        Returns:
            List of ParsedCertificate objects

        Raises:
            CertificateParseError: If format is unknown or parsing fails
        """
        fmt = cls.detect_format(raw_data)

        if fmt == "pem":
            return [cls.parse(raw_data.decode("utf-8", errors="replace"))]
        elif fmt == "der":
            return [cls.parse_der(raw_data)]
        elif fmt == "pkcs7_pem":
            return cls.parse_pkcs7(raw_data, is_pem=True)
        elif fmt == "pkcs7_der":
            return cls.parse_pkcs7(raw_data, is_pem=False)
        else:
            raise CertificateParseError("Unrecognized certificate format. Supported formats: PEM, DER, PKCS#7.")

    @classmethod
    def _extract_common_name(cls, cert: x509.Certificate) -> str:
        """Extract the Common Name from the certificate subject."""
        try:
            cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if cn_attrs:
                return cn_attrs[0].value
        except (AttributeError, ValueError, UnicodeDecodeError, TypeError):
            pass
        return "Unknown"

    @classmethod
    def _extract_issuer(cls, cert: x509.Certificate) -> str:
        """Extract the issuer distinguished name."""
        try:
            # Build a readable issuer string
            parts = []
            for attr in cert.issuer:
                oid_name = attr.oid._name if hasattr(attr.oid, "_name") else str(attr.oid)
                parts.append(f"{oid_name}={attr.value}")
            return ", ".join(parts)
        except (AttributeError, ValueError, UnicodeDecodeError, TypeError):
            return str(cert.issuer)

    @classmethod
    def _extract_sans(cls, cert: x509.Certificate) -> list[str]:
        """Extract Subject Alternative Names."""
        sans = []
        try:
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for name in ext.value:
                if isinstance(name, x509.DNSName):
                    sans.append(f"DNS:{name.value}")
                elif isinstance(name, x509.IPAddress):
                    sans.append(f"IP:{name.value}")
                elif isinstance(name, x509.RFC822Name):
                    sans.append(f"Email:{name.value}")
                elif isinstance(name, x509.UniformResourceIdentifier):
                    sans.append(f"URI:{name.value}")
                else:
                    sans.append(str(name.value))
        except x509.ExtensionNotFound:
            pass
        except (AttributeError, ValueError, UnicodeDecodeError, TypeError):
            pass
        return sans

    @classmethod
    def _extract_key_info(cls, cert: x509.Certificate) -> tuple[int | None, str]:
        """Extract key size and algorithm."""
        public_key = cert.public_key()

        if isinstance(public_key, rsa.RSAPublicKey):
            return public_key.key_size, "rsa"
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            return public_key.key_size, "ecdsa"
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            return None, "ed25519"
        else:
            return None, "unknown"

    @classmethod
    def _calculate_fingerprint(cls, cert: x509.Certificate) -> str:
        """Calculate SHA256 fingerprint with colons."""
        fingerprint_bytes = cert.fingerprint(hashes.SHA256())
        return ":".join(f"{b:02X}" for b in fingerprint_bytes)

    @classmethod
    def find_renewal_candidate(
        cls,
        common_name: str,
        certificate_model,
        warning_days: int | None = None,
        tenant=None,
    ) -> object | None:
        """
        Find an existing certificate that this might be renewing.

        Looks for an active certificate with the same Common Name
        that is expiring soon or already expired.

        Args:
            common_name: The CN of the new certificate
            certificate_model: The Certificate model class
            warning_days: Optional days threshold to limit candidates to expiring soon
            tenant: Optional tenant to scope the search

        Returns:
            An existing Certificate instance if found, None otherwise
        """
        # Find active certificates with same CN
        candidates = certificate_model.objects.filter(
            common_name=common_name,
            status__in=["active", "expired"],
        )

        if tenant is not None:
            candidates = candidates.filter(tenant=tenant)

        if warning_days is not None:
            now = timezone.now()
            warning_threshold = now + timedelta(days=warning_days)
            candidates = candidates.filter(valid_to__lte=warning_threshold)

        candidates = candidates.order_by("-valid_to")

        if candidates.exists():
            return candidates.first()

        return None
