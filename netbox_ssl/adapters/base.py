"""Base adapter class and shared data structures."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger("netbox_ssl.adapters")

# Fields that must never be accepted from external sources
PROHIBITED_SYNC_FIELDS: frozenset[str] = frozenset(
    {
        "private_key",
        "key_material",
        "p12",
        "pfx",
        "pkcs12",
    }
)

# Maximum response size (10 MB)
MAX_SYNC_RESPONSE_BYTES: int = 10 * 1024 * 1024

# HTTP request timeouts
CONNECT_TIMEOUT: int = 5
READ_TIMEOUT: int = 30


@dataclass(frozen=True)
class FetchedCertificate:
    """Normalized certificate data from an external source."""

    external_id: str
    common_name: str
    serial_number: str
    fingerprint_sha256: str
    issuer: str
    valid_from: datetime
    valid_to: datetime
    sans: list[str] = field(default_factory=list)
    key_size: int | None = None
    algorithm: str = "unknown"
    pem_content: str = ""
    issuer_chain: str = ""


class BaseAdapter(ABC):
    """Abstract base class for external source adapters."""

    def __init__(self, source) -> None:
        self.source = source
        self._credentials: str | None = None

    def resolve_credentials(self) -> str:
        """Resolve the credential reference to an actual value.

        Returns:
            The resolved credential string.
        """
        if self._credentials is None:
            from ..utils.credential_resolver import CredentialResolver

            self._credentials = CredentialResolver.resolve(self.source.auth_credentials_reference)
        return self._credentials

    def _get_headers(self) -> dict[str, str]:
        """Build HTTP headers with authentication.

        Returns:
            Dictionary of HTTP headers including auth and accept headers.
        """
        cred = self.resolve_credentials()
        if self.source.auth_method == "bearer":
            return {"Authorization": f"Bearer {cred}", "Accept": "application/json"}
        elif self.source.auth_method == "api_key":
            return {"X-API-Key": cred, "Accept": "application/json"}
        return {"Accept": "application/json"}

    @abstractmethod
    def test_connection(self) -> tuple[bool, str]:
        """Test connectivity to the external source.

        Returns:
            Tuple of (success, message).
        """
        ...

    @abstractmethod
    def fetch_certificates(self) -> list[FetchedCertificate]:
        """Fetch all certificates from the source.

        Returns:
            List of FetchedCertificate objects.
        """
        ...

    @abstractmethod
    def get_certificate_detail(self, external_id: str) -> FetchedCertificate | None:
        """Fetch a single certificate by its external ID.

        Args:
            external_id: The identifier in the external system.

        Returns:
            FetchedCertificate or None if not found.
        """
        ...
