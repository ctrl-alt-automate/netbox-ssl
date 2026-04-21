"""Base adapter class and shared data structures."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone

import requests

logger = logging.getLogger("netbox_ssl.adapters")

# Fields that must never be accepted from external sources.
# Enforcement lives in each adapter's response-parsing code; this list
# is the single source of truth consulted by those assertions.
PROHIBITED_SYNC_FIELDS: frozenset[str] = frozenset(
    {
        # Pre-v1.1 entries
        "private_key",
        "key_material",
        "p12",
        "pfx",
        "pkcs12",
        # v1.1 additions for AWS ACM and Azure Key Vault parity
        "pem_bundle",  # AWS ACM export-certificate bundle form
        "secret_value",  # Azure Key Vault secret attribute
        "key",  # Azure Key Vault certificate.key shortcut
    }
)

# Maximum response size (10 MB)
MAX_SYNC_RESPONSE_BYTES: int = 10 * 1024 * 1024

# HTTP request timeouts
CONNECT_TIMEOUT: int = 5
READ_TIMEOUT: int = 30

# Chunk size for streaming response reads
_STREAM_CHUNK_SIZE: int = 8192


@dataclass(frozen=True)
class CredentialField:
    """Metadata for one credential component declared by an adapter.

    Adapters use a mapping of name -> CredentialField to describe the
    credentials required for a given auth_method. The form and serializer
    consume this mapping to validate user-submitted auth_credentials.

    Attributes:
        required: Must be present in auth_credentials at form-save time.
        label:    User-facing label used by the form / UI.
        secret:   If True, component is high-sensitivity — drives UI
                  masking and may restrict allowed reference schemes.
        help_text: Short description shown by the form.

    Note:
        ``required=True`` is the default because required components are the
        common case. There is intentionally no ``default`` attribute:
        credential values must always be explicit; a silent default would
        mask misconfiguration at form-save time and is incompatible with
        the validator's missing-required = error assumption.
    """

    required: bool = True
    label: str = ""
    secret: bool = False
    help_text: str = ""


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
    sans: tuple[str, ...] = field(default_factory=tuple)
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

    def _make_request(self, url: str, params: dict | None = None) -> requests.Response:
        """Make an authenticated HTTP request with streaming size check.

        Checks the Content-Length header first, then streams the response
        body with a byte cap to avoid reading oversized responses into memory.

        Args:
            url: Full URL to request.
            params: Optional query parameters.

        Returns:
            The HTTP response.

        Raises:
            requests.RequestException: On network or HTTP errors.
            ValueError: If response exceeds size limit.
        """
        headers = self._get_headers()
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            allow_redirects=False,
            verify=self.source.verify_ssl,
            stream=True,
        )
        # Check Content-Length header first (fast path)
        content_length_header = response.headers.get("Content-Length")
        if content_length_header:
            try:
                declared_size = int(content_length_header)
                if declared_size > MAX_SYNC_RESPONSE_BYTES:
                    response.close()
                    raise ValueError(
                        f"Response Content-Length ({declared_size} bytes) "
                        f"exceeds maximum ({MAX_SYNC_RESPONSE_BYTES} bytes)"
                    )
            except (ValueError, TypeError):
                pass  # Invalid header — fall through to streaming check

        # Stream response body with byte cap
        chunks: list[bytes] = []
        total_bytes = 0
        for chunk in response.iter_content(chunk_size=_STREAM_CHUNK_SIZE):
            total_bytes += len(chunk)
            if total_bytes > MAX_SYNC_RESPONSE_BYTES:
                response.close()
                raise ValueError(f"Response size exceeds maximum ({MAX_SYNC_RESPONSE_BYTES} bytes)")
            chunks.append(chunk)

        # Reassemble the content so response.content / response.json() work
        response._content = b"".join(chunks)

        response.raise_for_status()
        return response

    @staticmethod
    def _parse_datetime(value: str) -> datetime | None:
        """Parse a datetime string from an external API.

        Args:
            value: ISO 8601 datetime string.

        Returns:
            datetime object or None if parsing fails.
        """
        if not value:
            return None
        try:
            # Try ISO format first (Python 3.11+)
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, AttributeError):
            pass
        # Try common date formats
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%S.%f"):
            try:
                dt = datetime.strptime(value, fmt)
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None

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
