"""Shared 'scrape a URL -> parse -> import-or-match' service.

Extracted from views/url_import.py so both the #106 URL import and the #149
endpoint poll use one code path. Raises on failure (callers map to their own
outcome shapes); never swallows.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass

from django.db import transaction
from django.utils import timezone

from ..models import Certificate, CertificateStatusChoices
from .ca_detector import detect_issuing_ca
from .parser import CertificateParseError, CertificateParser  # noqa: F401 (re-exported for callers)
from .tls_scraper import TLSScrapeError, scrape_tls_certificate  # noqa: F401 (re-exported for callers)
from .url_validation import URLValidationError, validate_https_url  # noqa: F401 (re-exported for callers)


@dataclass(frozen=True)
class ImportOutcome:
    certificate: Certificate
    created: bool


def scrape_and_import(
    url: str,
    host: str,
    port: int,
    *,
    sni: str | None = None,
    verify_chain: bool = True,
    allowlist,
    tenant=None,
    set_discovered_url: bool = True,
) -> ImportOutcome:
    """Validate, scrape, parse, and import-or-match the cert presented at a URL.

    Raises URLValidationError / TLSScrapeError / CertificateParseError.
    Does NOT swallow — callers map exceptions to their own outcome shapes.
    """
    validate_https_url(url, cidr_allowlist=allowlist)
    try:
        resolved_ip = socket.getaddrinfo(host, port)[0][4][0]
    except OSError as exc:
        raise TLSScrapeError(f"DNS failed for {host}:{port}: {exc}") from exc
    pem = scrape_tls_certificate(resolved_ip, host, port, sni=sni, verify_chain=verify_chain)
    parsed = CertificateParser.parse(pem)

    existing = Certificate.objects.filter(
        serial_number=parsed.serial_number, issuer=parsed.issuer
    ).first()
    if existing:
        existing.last_seen_at = timezone.now()
        if set_discovered_url and not existing.discovered_via_url:
            existing.discovered_via_url = url
        existing.save(update_fields=["last_seen_at", "discovered_via_url"])
        return ImportOutcome(certificate=existing, created=False)

    with transaction.atomic():
        create_kwargs = {
            "common_name": parsed.common_name,
            "serial_number": parsed.serial_number,
            "fingerprint_sha256": parsed.fingerprint_sha256,
            "issuer": parsed.issuer,
            "issuing_ca": detect_issuing_ca(parsed.issuer),
            "valid_from": parsed.valid_from,
            "valid_to": parsed.valid_to,
            "sans": parsed.sans or [],
            "key_size": parsed.key_size,
            "algorithm": parsed.algorithm,
            "status": CertificateStatusChoices.STATUS_ACTIVE,
            "pem_content": parsed.pem_content,
            "issuer_chain": parsed.issuer_chain,
            "tenant": tenant,
            "last_seen_at": timezone.now(),
        }
        if set_discovered_url:
            create_kwargs["discovered_via_url"] = url
        cert = Certificate.objects.create(**create_kwargs)
        cert.auto_detect_acme(save=True)
    return ImportOutcome(certificate=cert, created=True)
