"""
Certificate chain validation utilities.

Validates that certificate chains are complete and properly signed.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec, ed25519


class ChainValidationStatus(str, Enum):
    """Status codes for chain validation."""

    VALID = "valid"
    INCOMPLETE = "incomplete"
    INVALID_SIGNATURE = "invalid_signature"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    SELF_SIGNED = "self_signed"
    PARSE_ERROR = "parse_error"
    NO_CHAIN = "no_chain"


@dataclass
class ChainValidationResult:
    """Result of certificate chain validation."""

    status: ChainValidationStatus
    is_valid: bool
    message: str
    chain_depth: int
    certificates: list[dict]  # List of certificate info dicts
    errors: list[str]
    validated_at: datetime


class ChainValidationError(Exception):
    """Exception raised during chain validation."""

    pass


class ChainValidator:
    """
    Validator for X.509 certificate chains.

    Verifies:
    - Chain completeness (each cert signed by next)
    - Signature validity
    - Validity periods
    - Self-signed root detection
    """

    @classmethod
    def validate(cls, leaf_pem: str, chain_pem: str = "") -> ChainValidationResult:
        """
        Validate a certificate chain.

        Args:
            leaf_pem: The leaf (end-entity) certificate in PEM format
            chain_pem: The intermediate/root certificates in PEM format

        Returns:
            ChainValidationResult with detailed validation information
        """
        errors = []
        certificates = []
        validated_at = datetime.now(timezone.utc)

        # Parse leaf certificate
        try:
            leaf_cert = x509.load_pem_x509_certificate(leaf_pem.encode("utf-8"))
            certificates.append(cls._cert_to_dict(leaf_cert, is_leaf=True))
        except Exception as e:
            return ChainValidationResult(
                status=ChainValidationStatus.PARSE_ERROR,
                is_valid=False,
                message=f"Failed to parse leaf certificate: {e}",
                chain_depth=0,
                certificates=[],
                errors=[str(e)],
                validated_at=validated_at,
            )

        # Check if leaf is self-signed
        if cls._is_self_signed(leaf_cert):
            return ChainValidationResult(
                status=ChainValidationStatus.SELF_SIGNED,
                is_valid=True,
                message="Certificate is self-signed (no chain required)",
                chain_depth=1,
                certificates=certificates,
                errors=[],
                validated_at=validated_at,
            )

        # No chain provided
        if not chain_pem or not chain_pem.strip():
            return ChainValidationResult(
                status=ChainValidationStatus.NO_CHAIN,
                is_valid=False,
                message="Certificate requires a chain but none provided",
                chain_depth=1,
                certificates=certificates,
                errors=["No intermediate/root certificates provided"],
                validated_at=validated_at,
            )

        # Parse chain certificates
        chain_certs = cls._parse_chain(chain_pem)
        if not chain_certs:
            return ChainValidationResult(
                status=ChainValidationStatus.PARSE_ERROR,
                is_valid=False,
                message="Failed to parse chain certificates",
                chain_depth=1,
                certificates=certificates,
                errors=["No valid certificates found in chain"],
                validated_at=validated_at,
            )

        for cert in chain_certs:
            certificates.append(cls._cert_to_dict(cert, is_leaf=False))

        # Build and validate the full chain
        full_chain = [leaf_cert] + chain_certs
        chain_depth = len(full_chain)

        # Validate each link in the chain
        for i in range(len(full_chain) - 1):
            child_cert = full_chain[i]
            parent_cert = full_chain[i + 1]

            # Check if parent is the issuer
            if child_cert.issuer != parent_cert.subject:
                errors.append(f"Certificate #{i + 1} issuer does not match certificate #{i + 2} subject")
                return ChainValidationResult(
                    status=ChainValidationStatus.INCOMPLETE,
                    is_valid=False,
                    message="Chain is incomplete - issuer mismatch",
                    chain_depth=chain_depth,
                    certificates=certificates,
                    errors=errors,
                    validated_at=validated_at,
                )

            # Verify signature
            try:
                cls._verify_signature(child_cert, parent_cert)
            except InvalidSignature:
                errors.append(f"Invalid signature: certificate #{i + 1} not signed by certificate #{i + 2}")
                return ChainValidationResult(
                    status=ChainValidationStatus.INVALID_SIGNATURE,
                    is_valid=False,
                    message="Chain has invalid signatures",
                    chain_depth=chain_depth,
                    certificates=certificates,
                    errors=errors,
                    validated_at=validated_at,
                )
            except Exception as e:
                errors.append(f"Signature verification error: {e}")
                return ChainValidationResult(
                    status=ChainValidationStatus.INVALID_SIGNATURE,
                    is_valid=False,
                    message=f"Signature verification failed: {e}",
                    chain_depth=chain_depth,
                    certificates=certificates,
                    errors=errors,
                    validated_at=validated_at,
                )

        # Check validity periods
        now = datetime.now(timezone.utc)
        for i, cert in enumerate(full_chain):
            if cert.not_valid_before_utc > now:
                errors.append(f"Certificate #{i + 1} is not yet valid")
                return ChainValidationResult(
                    status=ChainValidationStatus.NOT_YET_VALID,
                    is_valid=False,
                    message=f"Certificate #{i + 1} in chain is not yet valid",
                    chain_depth=chain_depth,
                    certificates=certificates,
                    errors=errors,
                    validated_at=validated_at,
                )
            if cert.not_valid_after_utc < now:
                errors.append(f"Certificate #{i + 1} has expired")
                return ChainValidationResult(
                    status=ChainValidationStatus.EXPIRED,
                    is_valid=False,
                    message=f"Certificate #{i + 1} in chain has expired",
                    chain_depth=chain_depth,
                    certificates=certificates,
                    errors=errors,
                    validated_at=validated_at,
                )

        # Check if root is self-signed
        root_cert = full_chain[-1]
        if not cls._is_self_signed(root_cert):
            # Chain doesn't end at a self-signed root, but all signatures are valid
            # This is still a valid chain - just doesn't end at a root we can verify
            return ChainValidationResult(
                status=ChainValidationStatus.VALID,
                is_valid=True,
                message="Chain is valid (does not end at self-signed root)",
                chain_depth=chain_depth,
                certificates=certificates,
                errors=[],
                validated_at=validated_at,
            )

        # Verify root's self-signature
        try:
            cls._verify_signature(root_cert, root_cert)
        except Exception as e:
            errors.append(f"Root certificate self-signature verification failed: {e}")
            return ChainValidationResult(
                status=ChainValidationStatus.INVALID_SIGNATURE,
                is_valid=False,
                message="Root certificate self-signature is invalid",
                chain_depth=chain_depth,
                certificates=certificates,
                errors=errors,
                validated_at=validated_at,
            )

        return ChainValidationResult(
            status=ChainValidationStatus.VALID,
            is_valid=True,
            message="Certificate chain is complete and valid",
            chain_depth=chain_depth,
            certificates=certificates,
            errors=[],
            validated_at=validated_at,
        )

    @classmethod
    def _parse_chain(cls, chain_pem: str) -> list[x509.Certificate]:
        """Parse multiple certificates from PEM text."""
        import re

        pattern = re.compile(
            r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)",
            re.DOTALL,
        )
        blocks = pattern.findall(chain_pem)

        certs = []
        for block in blocks:
            try:
                cert = x509.load_pem_x509_certificate(block.encode("utf-8"))
                certs.append(cert)
            except Exception:
                continue

        return certs

    @classmethod
    def _is_self_signed(cls, cert: x509.Certificate) -> bool:
        """Check if a certificate is self-signed (issuer == subject)."""
        return cert.issuer == cert.subject

    @classmethod
    def _verify_signature(cls, child: x509.Certificate, parent: x509.Certificate) -> None:
        """
        Verify that child certificate was signed by parent.

        Raises:
            InvalidSignature: If signature is invalid
        """
        parent_public_key = parent.public_key()

        if isinstance(parent_public_key, rsa.RSAPublicKey):
            parent_public_key.verify(
                child.signature,
                child.tbs_certificate_bytes,
                padding.PKCS1v15(),
                child.signature_hash_algorithm,
            )
        elif isinstance(parent_public_key, ec.EllipticCurvePublicKey):
            parent_public_key.verify(
                child.signature,
                child.tbs_certificate_bytes,
                ec.ECDSA(child.signature_hash_algorithm),
            )
        elif isinstance(parent_public_key, ed25519.Ed25519PublicKey):
            parent_public_key.verify(
                child.signature,
                child.tbs_certificate_bytes,
            )
        else:
            raise ChainValidationError(f"Unsupported key type: {type(parent_public_key)}")

    @classmethod
    def _cert_to_dict(cls, cert: x509.Certificate, is_leaf: bool = False) -> dict:
        """Convert certificate to a dictionary for results."""
        from cryptography.x509.oid import NameOID

        # Extract common name
        cn = "Unknown"
        try:
            cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if cn_attrs:
                cn = cn_attrs[0].value
        except Exception:
            pass

        # Calculate fingerprint
        fingerprint_bytes = cert.fingerprint(hashes.SHA256())
        fingerprint = ":".join(f"{b:02X}" for b in fingerprint_bytes)

        return {
            "common_name": cn,
            "subject": str(cert.subject),
            "issuer": str(cert.issuer),
            "serial_number": format(cert.serial_number, "x").upper(),
            "fingerprint_sha256": fingerprint,
            "valid_from": cert.not_valid_before_utc.isoformat(),
            "valid_to": cert.not_valid_after_utc.isoformat(),
            "is_leaf": is_leaf,
            "is_self_signed": cls._is_self_signed(cert),
        }
