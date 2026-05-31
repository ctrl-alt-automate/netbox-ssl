"""
TLS certificate scraper for the URL Certificate Import feature (#106, PR 1).

Connects to a server over TLS and returns the server-presented certificate chain
(leaf + intermediates) as a concatenated PEM string, suitable for feeding to
``CertificateParser.parse()``.

Security model:
- **DNS-rebinding defense:** the caller validates the URL/hostname *and resolves
  it to an IP* via ``url_validation.validate_https_url`` first, then passes that
  validated ``ip`` here. We connect to that exact IP and never re-resolve the
  hostname, so an attacker cannot swap the DNS answer between validation and
  connect (TOCTOU). ``host``/``sni`` are used only for SNI + certificate
  hostname verification.
- **Hard timeout caps:** 5 s connect + handshake (socket timeout) and a 10 s
  total budget — not user-configurable.
- **Max chain size:** reuses ``CertificateParser.MAX_PEM_INPUT_BYTES`` (64 KB);
  an oversized chain raises rather than being silently truncated.
- **No private-key acceptance:** a TLS handshake never exposes private keys, but
  we re-check with ``CertificateParser.contains_private_key`` as belt-and-braces.
"""

from __future__ import annotations

import socket
import ssl
import time

from .parser import CertificateParser

# Single source of truth for the chain-size cap (same 64 KB the parser enforces).
MAX_CHAIN_BYTES = CertificateParser.MAX_PEM_INPUT_BYTES

# Hard, non-configurable budgets (seconds).
_CONNECT_TIMEOUT = 5.0
_TOTAL_BUDGET = 10.0


class TLSScrapeError(Exception):
    """Raised when a TLS certificate scrape fails (unreachable, handshake, caps)."""

    pass


def scrape_tls_certificate(
    ip: str,
    host: str,
    port: int = 443,
    *,
    sni: str | None = None,
    verify_chain: bool = True,
    timeout: float = _CONNECT_TIMEOUT,
) -> str:
    """Scrape the server-presented certificate chain over TLS as concatenated PEM.

    Args:
        ip: The PRE-VALIDATED IP address to connect to (DNS-rebinding defense —
            never re-resolved here).
        host: The hostname (for error messages / default SNI).
        port: TCP port (default 443).
        sni: SNI / certificate-verification hostname; defaults to ``host``.
        verify_chain: If True (default), the chain must verify against the system
            trust store. If False, an untrusted/self-signed chain is still
            scraped (caller flags it ``untrusted``).
        timeout: Connect + handshake socket timeout (default 5 s).

    Returns:
        The leaf + intermediate certificates as a concatenated PEM string.

    Raises:
        TLSScrapeError: connection refused/timeout, handshake failure, an
            oversized chain, or (defensively) private-key material in the result.
    """
    server_hostname = sni or host
    deadline = time.monotonic() + _TOTAL_BUDGET

    context = ssl.create_default_context()
    if not verify_chain:
        # Intentional, opt-in, scoped: this is a certificate *inventory* scraper,
        # not a data channel. We open the connection solely to read the cert the
        # server presents, then disconnect — we transmit and receive no
        # application data, so the usual MITM risk of disabling verification does
        # not apply (there is nothing to intercept). Verification cannot be left
        # on here because a self-signed/untrusted chain would abort the handshake
        # before we could read the cert at all, and inventorying internal
        # self-signed certs is the explicit, user-confirmed use case (#106).
        # Only reachable when the caller passes verify_chain=False per CSV row;
        # the default is full verification, and the result is flagged "untrusted".
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # noqa: S501 - see rationale above

    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw_sock:
            if time.monotonic() > deadline:
                raise TLSScrapeError(f"Total time budget exceeded connecting to {host}:{port}")
            raw_sock.settimeout(timeout)
            with context.wrap_socket(raw_sock, server_hostname=server_hostname) as tls_sock:
                der_chain = _get_verified_chain_der(tls_sock)
    except ssl.SSLError as exc:
        raise TLSScrapeError(f"TLS handshake failed for {host}:{port}: {exc}") from exc
    except TimeoutError as exc:
        raise TLSScrapeError(f"Timeout connecting to {host}:{port}") from exc
    except OSError as exc:
        raise TLSScrapeError(f"Unable to connect to {host}:{port}: {exc}") from exc

    if time.monotonic() > deadline:
        raise TLSScrapeError(f"Total time budget exceeded scraping {host}:{port}")

    pem = "".join(ssl.DER_cert_to_PEM_cert(der) for der in der_chain)

    if len(pem.encode("utf-8")) > MAX_CHAIN_BYTES:
        raise TLSScrapeError(f"Certificate chain from {host}:{port} exceeds {MAX_CHAIN_BYTES} bytes")

    # Defense in depth: a TLS chain never carries private keys, but never store one.
    if CertificateParser.contains_private_key(pem):
        raise TLSScrapeError(f"Unexpected private key material in chain from {host}:{port}")

    return pem


def _get_verified_chain_der(tls_sock: ssl.SSLSocket) -> list[bytes]:
    """Return the presented certificate chain (leaf first) as a list of DER bytes.

    Prefers the full chain via ``get_verified_chain``/``get_unverified_chain``
    when available (Python 3.13+); these return a sequence of DER ``bytes``.
    Falls back to just the leaf certificate (``getpeercert(binary_form=True)``)
    on older interpreters, where intermediates are unavailable via stdlib ssl.
    """
    # Python 3.13+: full chain accessors return a tuple of DER byte strings.
    for accessor in ("get_verified_chain", "get_unverified_chain"):
        getter = getattr(tls_sock, accessor, None)
        if getter is not None:
            try:
                chain = getter()
            except (ssl.SSLError, ValueError):
                continue
            if chain:
                return [_as_der(cert) for cert in chain]

    # Fallback: leaf only (older Python — intermediates unavailable via stdlib).
    leaf = tls_sock.getpeercert(binary_form=True)
    if not leaf:
        raise TLSScrapeError("Server presented no certificate")
    return [leaf]


def _as_der(cert: object) -> bytes:
    """Coerce a chain entry to DER bytes.

    ``SSLSocket.get_verified_chain()`` yields raw DER ``bytes`` on CPython, but
    guard for builds that hand back objects exposing ``public_bytes(DER)``.
    """
    if isinstance(cert, (bytes, bytearray)):
        return bytes(cert)
    public_bytes = getattr(cert, "public_bytes", None)
    if public_bytes is not None:
        from cryptography.hazmat.primitives.serialization import Encoding

        return public_bytes(Encoding.DER)
    raise TLSScrapeError("Unrecognised certificate object in TLS chain")
