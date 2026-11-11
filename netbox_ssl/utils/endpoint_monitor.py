"""Poll a MonitoredEndpoint: scrape its cert, link it, track rotation, fire events."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from django.db import transaction
from django.utils import timezone

if TYPE_CHECKING:
    from ..models import Certificate

from ..models import (
    CertificateStatusChoices,
    MonitoredEndpoint,
    MonitoredEndpointCertificate,
    MonitoredEndpointStatusChoices,
)
from .events import (
    EVENT_CERTIFICATE_RENEWED,
    EVENT_ENDPOINT_CERT_ROTATED,
    EVENT_ENDPOINT_UNREACHABLE,
    EVENT_ENDPOINT_UNTRUSTED_CERT,
    fire_endpoint_event,
)
from .renewal import shares_a_name, supersede_certificate
from .tls_scraper import TLSScrapeError
from .url_cert_import import scrape_and_import
from .url_validation import URLValidationError

logger = logging.getLogger("netbox_ssl.endpoint_monitor")

# A certificate in any other state was already dealt with by an operator
# (revoked, archived) or by an earlier renewal (replaced).
_SUPERSEDABLE_STATUSES = (CertificateStatusChoices.STATUS_ACTIVE, CertificateStatusChoices.STATUS_EXPIRED)


@dataclass(frozen=True)
class PollResult:
    endpoint: MonitoredEndpoint
    status: str
    rotated: bool
    events_fired: tuple[str, ...]
    replaced_certificate_ids: tuple[int, ...] = ()


def _host_port(url: str) -> tuple[str, int]:
    parts = urlsplit(url)
    return parts.hostname or "", parts.port or 443


def _supersede_previous_certificates(endpoint: MonitoredEndpoint, current: Certificate) -> tuple[int, ...]:
    """Run the Janus renewal for certificates this endpoint has stopped serving.

    A renewal done outside NetBox (ACME, a load balancer) shows up here as the
    endpoint presenting a new certificate. Without this step the predecessor
    stays Active forever, next to its successor (#184).

    Only call this for a poll whose chain verified. Retiring a certificate is a
    change to the inventory made on the word of a remote host, so that host has
    to be authenticated: anyone on the network path can answer an unverified
    handshake with a self-signed certificate for the right name.

    Candidates are the certificates in the endpoint's history, i.e. the ones the
    poll itself has seen this endpoint serve. That history is written nowhere
    else, a completed handshake proves the server held the private key, and the
    import only maps a presented certificate onto an inventory record when the
    fingerprints are equal — so a history row cannot be faked for a certificate
    the server does not own. The
    certificate the endpoint merely *points at* is deliberately not a candidate:
    that link is set on a form, and whoever may edit an endpoint must not be
    able to nominate an arbitrary certificate for retirement. Working from the
    whole history also means a rotation an older plugin version left unlinked
    is healed on the next poll.

    A Replaced certificate drops out of expiry alerting, so a predecessor is
    only retired when all of this holds:

    - ``current`` is Active, i.e. a usable successor;
    - the predecessor is Active or Expired;
    - it was issued before ``current`` — falling back to an older certificate
      is a rollback, or a second node behind the same name, not a renewal;
    - the two share a name — otherwise the host now answers with an unrelated
      certificate, which is drift;
    - both are in the same tenant, or both in none;
    - no other monitored endpoint still serves it.

    Returns the pks of the certificates that were marked Replaced.
    """
    from ..models import Certificate

    if current.status != CertificateStatusChoices.STATUS_ACTIVE:
        return ()

    candidate_ids = set(
        MonitoredEndpointCertificate.objects.filter(endpoint=endpoint).values_list("certificate_id", flat=True)
    )
    candidate_ids.discard(current.pk)
    if not candidate_ids:
        return ()

    predecessors = Certificate.objects.filter(
        pk__in=candidate_ids,
        status__in=_SUPERSEDABLE_STATUSES,
        valid_from__lt=current.valid_from,
    ).order_by("valid_from")

    replaced: list[int] = []
    for predecessor in predecessors:
        if not shares_a_name(predecessor, current):
            continue
        if predecessor.tenant_id != current.tenant_id:
            continue
        if MonitoredEndpoint.objects.filter(certificate=predecessor).exclude(pk=endpoint.pk).exists():
            continue
        try:
            supersede_certificate(
                predecessor,
                current,
                actor=f"endpoint_monitor:{endpoint.name}",
                reason=f"Detected by the poll of monitored endpoint '{endpoint.name}' ({endpoint.url}).",
            )
        except Exception:  # noqa: BLE001 – one failed renewal must not abort the poll run
            logger.exception(
                "Could not mark certificate pk=%s as replaced by pk=%s for endpoint '%s'",
                predecessor.pk,
                current.pk,
                endpoint.name,
            )
            continue
        replaced.append(predecessor.pk)
    return tuple(replaced)


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
    - On a trusted poll, certificates the endpoint no longer serves are renewed
      onto the current one (see ``_supersede_previous_certificates``).
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

    # An endpoint the poll could not authenticate gets its certificate recorded,
    # but is not believed about what that certificate replaces.
    replaced_ids = () if untrusted else _supersede_previous_certificates(endpoint, cert)

    if untrusted:
        events.append(EVENT_ENDPOINT_UNTRUSTED_CERT)
        fire_endpoint_event(endpoint, EVENT_ENDPOINT_UNTRUSTED_CERT)
    if rotated:
        events.append(EVENT_ENDPOINT_CERT_ROTATED)
        fire_endpoint_event(endpoint, EVENT_ENDPOINT_CERT_ROTATED, extra={"previous_certificate_id": prev_cert_id})
    if replaced_ids:
        events.append(EVENT_CERTIFICATE_RENEWED)

    return PollResult(endpoint, endpoint.status, rotated, tuple(events), replaced_ids)
