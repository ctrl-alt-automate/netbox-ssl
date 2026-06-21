"""Poll a MonitoredEndpoint: scrape its cert, link it, track rotation, fire events."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from django.db import transaction
from django.utils import timezone

if TYPE_CHECKING:
    from ..models import MonitoredEndpoint

from ..models import MonitoredEndpointCertificate, MonitoredEndpointStatusChoices
from .events import (
    EVENT_ENDPOINT_CERT_ROTATED,
    EVENT_ENDPOINT_UNREACHABLE,
    EVENT_ENDPOINT_UNTRUSTED_CERT,
    fire_endpoint_event,
)
from .tls_scraper import TLSScrapeError
from .url_cert_import import scrape_and_import
from .url_validation import URLValidationError


@dataclass(frozen=True)
class PollResult:
    endpoint: MonitoredEndpoint
    status: str
    rotated: bool
    events_fired: tuple[str, ...]


def _host_port(url: str) -> tuple[str, int]:
    parts = urlsplit(url)
    return parts.hostname or "", parts.port or 443


def poll_endpoint(endpoint: MonitoredEndpoint, *, allowlist: list[str]) -> PollResult:
    """Scrape the endpoint's current cert and reconcile the endpoint record.

    Two-attempt trust detection:
    - First attempt with verify_chain=True (trusted chain required).
    - On TLSScrapeError/URLValidationError, retry with verify_chain=False.
      - If the unverified attempt succeeds → status UNTRUSTED + fire endpoint_untrusted_cert.
      - If it also fails → status UNREACHABLE + last_error + fire endpoint_unreachable.
    - Any other exception (e.g. parse error) → UNREACHABLE + fire endpoint_unreachable.

    On success (either trusted or untrusted):
    - endpoint.certificate, last_checked, last_seen, last_error updated atomically.
    - MonitoredEndpointCertificate history row upserted (get_or_create + bump last_seen).
    - Rotation detected when the previous cert pk differs from the new one.
    """
    host, port = _host_port(endpoint.url)
    sni = endpoint.sni or None
    prev_cert_id = endpoint.certificate_id
    events: list[str] = []
    now = timezone.now()

    def _do(verify: bool):
        return scrape_and_import(
            endpoint.url,
            host,
            port,
            sni=sni,
            verify_chain=verify,
            allowlist=allowlist,
            tenant=endpoint.tenant,
            set_discovered_url=True,
        )

    untrusted = False
    try:
        outcome = _do(True)
    except (TLSScrapeError, URLValidationError):
        try:
            outcome = _do(False)
            untrusted = True
        except (TLSScrapeError, URLValidationError) as exc:
            endpoint.status = MonitoredEndpointStatusChoices.STATUS_UNREACHABLE
            endpoint.last_checked = now
            endpoint.last_error = str(exc)
            endpoint.save(update_fields=["status", "last_checked", "last_error"])
            fire_endpoint_event(endpoint, EVENT_ENDPOINT_UNREACHABLE)
            return PollResult(endpoint, endpoint.status, False, (EVENT_ENDPOINT_UNREACHABLE,))
    except Exception as exc:  # noqa: BLE001 – record and continue (e.g. parse error)
        endpoint.status = MonitoredEndpointStatusChoices.STATUS_UNREACHABLE
        endpoint.last_checked = now
        endpoint.last_error = str(exc)
        endpoint.save(update_fields=["status", "last_checked", "last_error"])
        fire_endpoint_event(endpoint, EVENT_ENDPOINT_UNREACHABLE)
        return PollResult(endpoint, endpoint.status, False, (EVENT_ENDPOINT_UNREACHABLE,))

    cert = outcome.certificate
    rotated = prev_cert_id is not None and prev_cert_id != cert.pk

    with transaction.atomic():
        endpoint.certificate = cert
        endpoint.last_checked = now
        endpoint.last_seen = now
        endpoint.last_error = ""
        endpoint.status = (
            MonitoredEndpointStatusChoices.STATUS_UNTRUSTED if untrusted else MonitoredEndpointStatusChoices.STATUS_OK
        )
        endpoint.save(update_fields=["certificate", "last_checked", "last_seen", "last_error", "status"])

        hist, created = MonitoredEndpointCertificate.objects.get_or_create(
            endpoint=endpoint,
            certificate=cert,
            defaults={"first_seen": now, "last_seen": now},
        )
        if not created:
            hist.last_seen = now
            hist.save(update_fields=["last_seen"])

    if untrusted:
        events.append(EVENT_ENDPOINT_UNTRUSTED_CERT)
        fire_endpoint_event(endpoint, EVENT_ENDPOINT_UNTRUSTED_CERT)
    if rotated:
        events.append(EVENT_ENDPOINT_CERT_ROTATED)
        fire_endpoint_event(endpoint, EVENT_ENDPOINT_CERT_ROTATED, extra={"previous_certificate_id": prev_cert_id})

    return PollResult(endpoint, endpoint.status, rotated, tuple(events))
