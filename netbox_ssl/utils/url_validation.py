"""
Shared URL validation utilities for SSRF protection.

Used by the External Source Framework, ARI polling, and the URL Certificate
Import feature (#106) to enforce HTTPS-only and reject private/loopback
addresses — with an optional, admin-gated CIDR allowlist for known-safe
internal ranges.
"""

import ipaddress
import socket
from urllib.parse import urlparse

# Loopback / "this host" ranges. These ALWAYS block, even when an address falls
# inside an allowlisted CIDR — loopback can never be reached via URL import.
_LOOPBACK_BLOCKS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("0.0.0.0/8"),
)


class URLValidationError(Exception):
    """Raised when a URL fails security validation."""

    pass


def _check_address(addr: ipaddress._BaseAddress, allowlist: list[ipaddress._BaseNetwork] | None) -> None:
    """Raise URLValidationError if ``addr`` is not permitted.

    Precedence (security-critical): loopback is rejected unconditionally, even
    if it falls inside an allowlisted network. Otherwise a private/link-local
    address is permitted only when it is a member of an allowlisted CIDR.
    """
    if any(addr in net for net in _LOOPBACK_BLOCKS):
        raise URLValidationError(f"URL points to a loopback address: {addr}")

    if addr.is_private or addr.is_loopback or addr.is_link_local:
        if allowlist and any(addr in net for net in allowlist):
            return  # explicitly allowlisted internal range
        raise URLValidationError(f"URL points to a private/loopback address: {addr}")


def _parse_allowlist(cidr_allowlist: list[str] | None) -> list[ipaddress._BaseNetwork]:
    """Parse string CIDRs into network objects, raising on malformed entries."""
    if not cidr_allowlist:
        return []
    networks = []
    for entry in cidr_allowlist:
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError as exc:
            raise URLValidationError(f"Invalid CIDR in allowlist: {entry!r}") from exc
    return networks


def validate_https_url(url: str, cidr_allowlist: list[str] | None = None) -> None:
    """
    Validate that a URL uses HTTPS and does not resolve to a private/loopback address.

    Args:
        url: The URL to validate.
        cidr_allowlist: Optional list of CIDR strings (e.g. ``["10.0.0.0/8"]``).
            Private/link-local addresses inside one of these networks are
            permitted; loopback is always blocked regardless. Defaults to None
            (no private ranges permitted) so existing callers are unaffected.

    Raises:
        URLValidationError: If the URL fails validation.
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

    allowlist = _parse_allowlist(cidr_allowlist)

    # Check for well-known loopback names (fast pre-DNS reject).
    if hostname in {"localhost", "127.0.0.1", "::1"}:
        raise URLValidationError("URL must not point to a loopback address.")

    # Check if hostname is a literal IP
    try:
        addr = ipaddress.ip_address(hostname)
        _check_address(addr, allowlist)
        return  # Valid literal IP
    except ValueError:
        pass  # Not a literal IP, resolve hostname

    # DNS resolution — check all resolved addresses
    try:
        addrs = socket.getaddrinfo(hostname, None)
        for _family, _type, _proto, _canonname, sockaddr in addrs:
            try:
                resolved_addr = ipaddress.ip_address(sockaddr[0])
            except ValueError:
                continue
            _check_address(resolved_addr, allowlist)
    except socket.gaierror as e:
        raise URLValidationError(f"DNS resolution failed for {hostname}: {e}") from e
