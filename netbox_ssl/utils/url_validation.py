"""
Shared URL validation utilities for SSRF protection.

Used by both the External Source Framework and ARI polling
to enforce HTTPS-only and reject private/loopback addresses.
"""

import ipaddress
import socket
from urllib.parse import urlparse


class URLValidationError(Exception):
    """Raised when a URL fails security validation."""

    pass


def validate_https_url(url: str) -> None:
    """
    Validate that a URL uses HTTPS and does not resolve to a private/loopback address.

    Args:
        url: The URL to validate

    Raises:
        URLValidationError: If the URL fails validation
    """
    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise URLValidationError("Invalid URL.") from exc

    if parsed.scheme != "https":
        raise URLValidationError(f"Only HTTPS URLs are allowed, got: {parsed.scheme}")

    hostname = parsed.hostname
    if not hostname:
        raise URLValidationError("URL has no hostname")

    # Check for well-known loopback names
    blocked = {"localhost", "127.0.0.1", "::1"}
    if hostname in blocked:
        raise URLValidationError("URL must not point to a loopback address.")

    # Check if hostname is a literal IP
    try:
        addr = ipaddress.ip_address(hostname)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            raise URLValidationError(f"URL points to a private/loopback address: {addr}")
        return  # Valid literal IP
    except ValueError:
        pass  # Not a literal IP, resolve hostname

    # DNS resolution — check all resolved addresses
    try:
        addrs = socket.getaddrinfo(hostname, None)
        for _family, _type, _proto, _canonname, sockaddr in addrs:
            try:
                resolved_addr = ipaddress.ip_address(sockaddr[0])
                if resolved_addr.is_private or resolved_addr.is_loopback or resolved_addr.is_link_local:
                    raise URLValidationError(f"URL resolves to private/loopback address: {resolved_addr}")
            except ValueError:
                continue
    except socket.gaierror as e:
        raise URLValidationError(f"DNS resolution failed for {hostname}: {e}") from e
