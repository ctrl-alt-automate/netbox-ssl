"""
Certificate event utilities for firing events through NetBox's Event Rules system.

NetBox Event Rules trigger on standard model changes (create/update/delete).
This module provides helpers to build enriched event payloads and fire events
by creating annotated ObjectChange records.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("netbox_ssl.events")

# Custom event type constants (stored in ObjectChange snapshot data for consumers)
EVENT_CERTIFICATE_EXPIRED = "certificate_expired"
EVENT_CERTIFICATE_EXPIRING_SOON = "certificate_expiring_soon"
EVENT_CERTIFICATE_RENEWED = "certificate_renewed"
EVENT_CERTIFICATE_REVOKED = "certificate_revoked"
EVENT_CERTIFICATE_ARCHIVED = "certificate_archived"


def build_certificate_event_payload(
    certificate: Any,
    event_type: str,
    threshold_days: int | None = None,
    extra: dict | None = None,
) -> dict:
    """
    Build a standardized event payload for a certificate event.

    This payload is included in the ObjectChange snapshot data so webhook
    consumers can extract rich context about the event.

    Args:
        certificate: Certificate model instance.
        event_type: One of the EVENT_* constants.
        threshold_days: The threshold that triggered this event (for expiring_soon).
        extra: Additional key-value pairs to include in the payload.

    Returns:
        Dictionary with event metadata suitable for JSON serialization.
    """
    payload = {
        "event_type": event_type,
        "certificate_id": certificate.pk,
        "common_name": certificate.common_name,
        "serial_number": certificate.serial_number,
        "status": certificate.status,
        "days_remaining": certificate.days_remaining,
        "valid_to": certificate.valid_to.isoformat() if certificate.valid_to else None,
        "issuer": certificate.issuer,
        "tenant": certificate.tenant.name if certificate.tenant else None,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
    }

    if threshold_days is not None:
        payload["threshold_days"] = threshold_days

    # Add assigned objects summary
    try:
        assignments = certificate.assignments.select_related("assigned_object_type").all()
        payload["assigned_objects"] = [
            {
                "type": a.assigned_object_type.model,
                "id": a.assigned_object_id,
                "name": str(a.assigned_object) if a.assigned_object else "Unknown",
            }
            for a in assignments
        ]
        payload["assignment_count"] = len(payload["assigned_objects"])
    except Exception as e:
        logger.warning("Failed to retrieve assignments for certificate %s: %s", certificate.pk, e)
        payload["assigned_objects"] = []
        payload["assignment_count"] = 0

    # Renewal instructions fallback: cert note > CA instructions > empty
    renewal_instructions = ""
    if hasattr(certificate, "renewal_note") and certificate.renewal_note:
        renewal_instructions = certificate.renewal_note
    elif hasattr(certificate, "issuing_ca") and certificate.issuing_ca:
        ca = certificate.issuing_ca
        if hasattr(ca, "renewal_instructions") and ca.renewal_instructions:
            renewal_instructions = ca.renewal_instructions
    if renewal_instructions:
        payload["renewal_instructions"] = renewal_instructions

    if extra:
        payload.update(extra)

    return payload


def fire_certificate_event(
    certificate: Any,
    event_type: str,
    threshold_days: int | None = None,
    extra: dict | None = None,
) -> dict:
    """
    Fire a certificate event by updating the certificate's last_updated timestamp.

    This triggers NetBox's standard object_updated Event Rules. The event payload
    is logged for audit purposes and returned for further use (e.g., by the scan script).

    Args:
        certificate: Certificate model instance.
        event_type: One of the EVENT_* constants.
        threshold_days: The threshold that triggered this event.
        extra: Additional context to include.

    Returns:
        The event payload dictionary.
    """
    payload = build_certificate_event_payload(
        certificate,
        event_type,
        threshold_days=threshold_days,
        extra=extra,
    )

    # Touch the certificate's last_updated to trigger NetBox's object_updated Event Rules.
    # This causes the ChangeLogging middleware to create an ObjectChange record,
    # which in turn fires any matching Event Rules (webhooks, scripts, etc.).
    try:
        from django.utils import timezone as dj_timezone

        type(certificate).objects.filter(pk=certificate.pk).update(last_updated=dj_timezone.now())
    except Exception as e:
        # Don't fail the entire operation if the update fails (e.g., in tests)
        logger.warning("Could not update last_updated for certificate %s: %s", certificate.pk, e)

    logger.info(
        "Certificate event fired: %s for %s (id=%s, days_remaining=%s)",
        event_type,
        certificate.common_name,
        certificate.pk,
        certificate.days_remaining,
    )

    return payload
