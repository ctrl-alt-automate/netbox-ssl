"""
Certificate Signing Request (CSR) parsing utilities.

Handles PEM parsing and attribute extraction for CSRs.
"""

import re
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, NameOID


class CSRParseError(Exception):
    """Exception raised when CSR parsing fails."""

    pass


@dataclass
class ParsedCSR:
    """Container for parsed CSR data."""

    common_name: str
    organization: str
    organizational_unit: str
    locality: str
    state: str
    country: str
    sans: list[str]
    key_size: int | None
    algorithm: str
    fingerprint_sha256: str
    pem_content: str


class CSRParser:
    """
    Parser for Certificate Signing Requests in PEM format.
    """

    # Pattern to detect CSR blocks
    CSR_PATTERN = re.compile(
        r"(-----BEGIN CERTIFICATE REQUEST-----.*?-----END CERTIFICATE REQUEST-----)",
        re.DOTALL,
    )

    # Alternative pattern for "NEW CERTIFICATE REQUEST"
    CSR_NEW_PATTERN = re.compile(
        r"(-----BEGIN NEW CERTIFICATE REQUEST-----.*?-----END NEW CERTIFICATE REQUEST-----)",
        re.DOTALL,
    )

    @classmethod
    def extract_csr(cls, pem_text: str) -> str | None:
        """Extract the first CSR block from PEM text."""
        match = cls.CSR_PATTERN.search(pem_text)
        if match:
            return match.group(1)
        match = cls.CSR_NEW_PATTERN.search(pem_text)
        if match:
            return match.group(1)
        return None

    @classmethod
    def parse(cls, pem_text: str) -> ParsedCSR:
        """
        Parse a PEM CSR and extract all metadata.

        Args:
            pem_text: Raw PEM text containing a CSR

        Returns:
            ParsedCSR with extracted metadata

        Raises:
            CSRParseError: If parsing fails
        """
        # Extract CSR block
        csr_pem = cls.extract_csr(pem_text)
        if not csr_pem:
            raise CSRParseError(
                "No valid CSR found in input. Please provide a CSR in PEM format "
                "(-----BEGIN CERTIFICATE REQUEST----- ... -----END CERTIFICATE REQUEST-----)."
            )

        # Parse the CSR
        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
        except Exception as e:
            raise CSRParseError(f"Failed to parse CSR: {e}") from e

        # Extract subject fields
        subject_fields = cls._extract_subject_fields(csr)

        # Extract SANs
        sans = cls._extract_sans(csr)

        # Extract key info
        key_size, algorithm = cls._extract_key_info(csr)

        # Calculate fingerprint
        fingerprint = cls._calculate_fingerprint(csr_pem)

        return ParsedCSR(
            common_name=subject_fields.get("common_name", ""),
            organization=subject_fields.get("organization", ""),
            organizational_unit=subject_fields.get("organizational_unit", ""),
            locality=subject_fields.get("locality", ""),
            state=subject_fields.get("state", ""),
            country=subject_fields.get("country", ""),
            sans=sans,
            key_size=key_size,
            algorithm=algorithm,
            fingerprint_sha256=fingerprint,
            pem_content=csr_pem,
        )

    @classmethod
    def _extract_subject_fields(cls, csr: x509.CertificateSigningRequest) -> dict:
        """Extract subject fields from the CSR."""
        fields = {
            "common_name": "",
            "organization": "",
            "organizational_unit": "",
            "locality": "",
            "state": "",
            "country": "",
        }

        oid_mapping = {
            NameOID.COMMON_NAME: "common_name",
            NameOID.ORGANIZATION_NAME: "organization",
            NameOID.ORGANIZATIONAL_UNIT_NAME: "organizational_unit",
            NameOID.LOCALITY_NAME: "locality",
            NameOID.STATE_OR_PROVINCE_NAME: "state",
            NameOID.COUNTRY_NAME: "country",
        }

        for oid, field_name in oid_mapping.items():
            try:
                attrs = csr.subject.get_attributes_for_oid(oid)
                if attrs:
                    fields[field_name] = attrs[0].value
            except Exception:
                pass

        return fields

    @classmethod
    def _extract_sans(cls, csr: x509.CertificateSigningRequest) -> list[str]:
        """Extract Subject Alternative Names from CSR extensions."""
        sans = []
        try:
            # CSR extensions are in the attributes
            for attribute in csr.attributes:
                if attribute.oid == x509.oid.AttributeOID.EXTENSION_REQUEST:
                    for ext in attribute.value:
                        if ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
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
        except Exception:
            pass
        return sans

    @classmethod
    def _extract_key_info(cls, csr: x509.CertificateSigningRequest) -> tuple[int | None, str]:
        """Extract key size and algorithm."""
        public_key = csr.public_key()

        if isinstance(public_key, rsa.RSAPublicKey):
            return public_key.key_size, "rsa"
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            return public_key.key_size, "ecdsa"
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            return None, "ed25519"
        else:
            return None, "unknown"

    @classmethod
    def _calculate_fingerprint(cls, pem_content: str) -> str:
        """Calculate SHA256 fingerprint of the CSR."""
        import hashlib

        from cryptography.hazmat.primitives.serialization import Encoding

        # Calculate fingerprint from the DER-encoded CSR
        csr = x509.load_pem_x509_csr(pem_content.encode("utf-8"))
        der_bytes = csr.public_bytes(Encoding.DER)

        fingerprint = hashlib.sha256(der_bytes).hexdigest().upper()
        return ":".join(fingerprint[i : i + 2] for i in range(0, len(fingerprint), 2))
