"""The Janus renewal hand-over: retire a certificate in favour of its successor.

Every renewal ends the same way — the successor inherits what the operator
maintained on the predecessor, the predecessor becomes ``Replaced`` and points
at the successor. This module is that tail, for callers that already hold both
certificates (the endpoint poll, #184).

The import view and the external-source sync engine still carry their own
copies of these steps; they create the successor and hand over in one
transaction.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from django.core.exceptions import ValidationError
from django.db import transaction

from .events import EVENT_CERTIFICATE_RENEWED, fire_certificate_event

if TYPE_CHECKING:
    from ..models import Certificate

logger = logging.getLogger("netbox_ssl.renewal")

# Fields an operator maintains by hand and that describe the deployment rather
# than the X.509 document, so they outlive a renewal.
_CARRIED_FIELDS: tuple[str, ...] = ("private_key_location", "renewal_note")

# ACME bookkeeping, carried only when the predecessor was an ACME certificate.
_CARRIED_ACME_FIELDS: tuple[str, ...] = (
    "acme_provider",
    "acme_account_email",
    "acme_challenge_type",
    "acme_server_url",
    "acme_auto_renewal",
    "acme_renewal_days",
)


@dataclass(frozen=True)
class RenewalOutcome:
    """What a hand-over changed."""

    old_certificate_id: int
    new_certificate_id: int
    assignments_transferred: int
    fields_carried: tuple[str, ...]


def certificate_names(certificate: Certificate) -> frozenset[str]:
    """Every name a certificate is valid for: its CN plus its SAN values."""
    names = {certificate.common_name.lower()} if certificate.common_name else set()
    for san in certificate.sans or []:
        # SANs are stored typed ("DNS:example.com", "IP:2001:db8::1").
        _kind, separator, value = str(san).partition(":")
        names.add((value if separator else _kind).lower())
    return frozenset(names)


def shares_a_name(first: Certificate, second: Certificate) -> bool:
    """Whether two certificates cover at least one common name."""
    return not certificate_names(first).isdisjoint(certificate_names(second))


def _is_untouched(certificate: Certificate, field_name: str) -> bool:
    """Whether a field still holds its model default, i.e. nobody filled it in."""
    return getattr(certificate, field_name) == certificate._meta.get_field(field_name).get_default()


def _carry_metadata(old: Certificate, new: Certificate) -> tuple[str, ...]:
    """Copy operator-maintained metadata onto ``new`` without overwriting any."""
    carried: list[str] = []
    field_names = list(_CARRIED_FIELDS)

    if old.is_acme:
        field_names.extend(_CARRIED_ACME_FIELDS)
        if not new.is_acme:
            new.is_acme = True
            carried.append("is_acme")

    for field_name in field_names:
        value = getattr(old, field_name)
        if _is_untouched(new, field_name) and value != getattr(new, field_name):
            setattr(new, field_name, value)
            carried.append(field_name)

    if new.tenant_id is None and old.tenant_id is not None:
        new.tenant_id = old.tenant_id
        carried.append("tenant")

    if carried:
        new.save(update_fields=carried)
    return tuple(carried)


def _copy_assignments(old: Certificate, new: Certificate) -> int:
    """Give ``new`` every assignment of ``old`` it does not already have."""
    from ..models import CertificateAssignment

    present = set(
        CertificateAssignment.objects.filter(certificate=new).values_list(
            "assigned_object_type_id", "assigned_object_id"
        )
    )
    transferred = 0
    for assignment in CertificateAssignment.objects.filter(certificate=old):
        if (assignment.assigned_object_type_id, assignment.assigned_object_id) in present:
            continue
        copy = CertificateAssignment(
            certificate=new,
            assigned_object_type_id=assignment.assigned_object_type_id,
            assigned_object_id=assignment.assigned_object_id,
            is_primary=assignment.is_primary,
            notes=assignment.notes,
        )
        try:
            # full_clean() enforces the tenant boundary between certificate and target.
            copy.full_clean()
        except ValidationError as exc:
            logger.warning(
                "Not copying assignment (object_type=%s, object_id=%s) from certificate pk=%s to pk=%s: %s",
                assignment.assigned_object_type_id,
                assignment.assigned_object_id,
                old.pk,
                new.pk,
                exc,
            )
            continue
        copy.save()
        transferred += 1
    return transferred


def supersede_certificate(old: Certificate, new: Certificate, *, actor: str = "", reason: str = "") -> RenewalOutcome:
    """Retire ``old`` in favour of ``new``: the Janus "Replace & Archive" step.

    Atomically: carries operator-maintained metadata onto ``new`` (never
    overwriting a value already set there), copies the assignments ``new`` does
    not have yet, marks ``old`` as Replaced with ``replaced_by`` pointing at
    ``new``, and records a ``renewed`` lifecycle event on ``new``. Once that has
    committed, fires ``certificate_renewed``.

    Deciding *whether* ``new`` really succeeds ``old`` is the caller's job.

    Args:
        old: The certificate being retired.
        new: Its successor, already saved.
        actor: Who triggered the renewal, for the lifecycle event.
        reason: Extra context appended to the lifecycle event description.
    """
    from ..models import CertificateLifecycleEvent, CertificateStatusChoices, LifecycleEventTypeChoices

    with transaction.atomic():
        fields_carried = _carry_metadata(old, new)
        transferred = _copy_assignments(old, new)

        old.status = CertificateStatusChoices.STATUS_REPLACED
        old.replaced_by = new
        old.save()

        description = (
            f"Renewal of {old.common_name} (serial {old.serial_number}); {transferred} assignment(s) transferred."
        )
        CertificateLifecycleEvent.objects.create(
            certificate=new,
            event_type=LifecycleEventTypeChoices.EVENT_RENEWED,
            new_status=new.status,
            related_certificate=old,
            description=f"{description} {reason}".strip(),
            actor=actor,
        )

    fire_certificate_event(
        new,
        EVENT_CERTIFICATE_RENEWED,
        extra={
            "old_certificate_id": old.pk,
            "old_certificate_cn": old.common_name,
            "assignments_transferred": transferred,
        },
    )
    logger.info(
        "Certificate pk=%s (%s) superseded by pk=%s; %s assignment(s) transferred, carried: %s",
        old.pk,
        old.common_name,
        new.pk,
        transferred,
        ", ".join(fields_carried) or "nothing",
    )
    return RenewalOutcome(
        old_certificate_id=old.pk,
        new_certificate_id=new.pk,
        assignments_transferred=transferred,
        fields_carried=fields_carried,
    )
