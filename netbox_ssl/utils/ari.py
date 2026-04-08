"""
ACME Renewal Information (ARI) utilities — RFC 9773.

Provides CertID construction, ACME directory discovery, and ARI polling
for CA-recommended renewal windows. This is monitoring-only: no certificate
issuance or private key operations.
"""

import base64
import ipaddress
import logging
import socket
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlparse

import requests
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

logger = logging.getLogger("netbox_ssl.ari")

# Known ACME directory URLs for ARI-capable providers
ARI_DIRECTORIES: dict[str, str] = {
    "letsencrypt": "https://acme-v02.api.letsencrypt.org/directory",
    "letsencrypt_staging": "https://acme-staging-v02.api.letsencrypt.org/directory",
    "google": "https://dv.acme-v02.api.pki.goog/directory",
}

# Request timeout for all outbound HTTP calls
_REQUEST_TIMEOUT = 10


class ARIError(Exception):
    """Base exception for ARI operations."""

    pass


def _validate_url(url: str) -> None:
    """Validate URL is HTTPS and not targeting private IP ranges."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ARIError(f"Only HTTPS URLs are allowed, got: {parsed.scheme}")

    hostname = parsed.hostname
    if not hostname:
        raise ARIError("URL has no hostname")

    # Resolve and check for private IPs
    try:
        addrs = socket.getaddrinfo(hostname, None)
        for _, _, _, _, sockaddr in addrs:
            ip = ipaddress.ip_address(sockaddr[0])
            if ip.is_private or ip.is_loopback or ip.is_reserved:
                raise ARIError(f"URL resolves to private/reserved IP: {ip}")
    except socket.gaierror as e:
        raise ARIError(f"DNS resolution failed for {hostname}: {e}") from e


def build_cert_id(pem_content: str) -> str:
    """
    Build ARI CertID from certificate PEM content.

    CertID = base64url(AKI) + "." + base64url(DER serial)
    Per RFC 9773, Section 4.1.

    Args:
        pem_content: PEM-encoded certificate

    Returns:
        CertID string

    Raises:
        ARIError: If certificate lacks Authority Key Identifier
    """
    cert = x509.load_pem_x509_certificate(pem_content.encode("utf-8"))

    # Extract Authority Key Identifier
    try:
        aki_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        aki_bytes = aki_ext.value.key_identifier
        if aki_bytes is None:
            raise ARIError("Authority Key Identifier has no key_identifier value")
    except x509.ExtensionNotFound as e:
        raise ARIError("Certificate has no Authority Key Identifier extension") from e

    # Serial number as unsigned big-endian bytes
    serial = cert.serial_number
    byte_length = (serial.bit_length() + 7) // 8
    serial_bytes = serial.to_bytes(byte_length, byteorder="big")

    # base64url encoding without padding
    aki_b64 = base64.urlsafe_b64encode(aki_bytes).rstrip(b"=").decode("ascii")
    serial_b64 = base64.urlsafe_b64encode(serial_bytes).rstrip(b"=").decode("ascii")

    return f"{aki_b64}.{serial_b64}"


def discover_ari_endpoint(directory_url: str) -> str | None:
    """
    Discover ARI renewalInfo endpoint from ACME directory.

    Args:
        directory_url: ACME directory URL (e.g., Let's Encrypt directory)

    Returns:
        The renewalInfo URL or None if ARI is not supported
    """
    _validate_url(directory_url)

    try:
        resp = requests.get(directory_url, timeout=_REQUEST_TIMEOUT, allow_redirects=False)
        resp.raise_for_status()
        directory = resp.json()
        return directory.get("renewalInfo")
    except Exception as e:
        logger.warning("Failed to discover ARI endpoint from %s: %s", directory_url, e)
        return None


def poll_ari(ari_endpoint: str, cert_id: str) -> dict[str, Any]:
    """
    Poll ARI endpoint for renewal information.

    Args:
        ari_endpoint: The renewalInfo base URL from the directory
        cert_id: CertID string (from build_cert_id)

    Returns:
        Dict with keys:
        - suggested_window_start: datetime (UTC)
        - suggested_window_end: datetime (UTC)
        - explanation_url: str (optional)
        - retry_after: datetime (UTC, from Retry-After header)

    Raises:
        ARIError: If the request fails or response is invalid
    """
    url = f"{ari_endpoint}/{cert_id}"
    _validate_url(url)

    try:
        resp = requests.get(url, timeout=_REQUEST_TIMEOUT, allow_redirects=False)
    except Exception as e:
        raise ARIError(f"ARI request failed: {e}") from e

    if resp.status_code == 404:
        raise ARIError("Certificate not found in ARI (provider may not track this cert)")

    resp.raise_for_status()

    data = resp.json()
    result: dict[str, Any] = {}

    # Parse suggestedWindow
    window = data.get("suggestedWindow", {})
    if "start" in window:
        result["suggested_window_start"] = _parse_rfc3339(window["start"])
    if "end" in window:
        result["suggested_window_end"] = _parse_rfc3339(window["end"])

    if "explanationURL" in data:
        result["explanation_url"] = data["explanationURL"]

    # Parse Retry-After header
    retry_after = resp.headers.get("Retry-After")
    if retry_after:
        result["retry_after"] = _parse_retry_after(retry_after)

    return result


def _parse_rfc3339(timestamp: str) -> datetime:
    """Parse RFC 3339 timestamp to timezone-aware datetime."""
    # Handle 'Z' suffix
    normalized = timestamp.replace("Z", "+00:00")
    return datetime.fromisoformat(normalized)


def _parse_retry_after(value: str) -> datetime:
    """Parse Retry-After header value (seconds or HTTP-date)."""
    try:
        seconds = int(value)
        return datetime.now(tz=timezone.utc) + timedelta(seconds=seconds)
    except ValueError:
        return parsedate_to_datetime(value)
