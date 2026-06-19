"""Service for assigning one certificate to many infrastructure objects.

Single source of truth for the "one cert → many objects" direction, used by
both the REST API action and the UI view. Idempotent: targets already assigned
to the certificate are silently skipped (mirrors the inverse ``bulk_assign``
action).
"""

import logging
from collections.abc import Sequence
from dataclasses import dataclass

from django.contrib.contenttypes.models import ContentType
from django.db import DatabaseError, IntegrityError, transaction

from ..models import CertificateAssignment

logger = logging.getLogger("netbox_ssl.assignments")

# Content-type model names that may receive a certificate assignment.
ALLOWED_ASSIGN_MODELS = ("device", "service", "virtualmachine")


class AssignmentError(Exception):
    """Raised when a bulk assignment cannot be completed. Message is user-safe."""


@dataclass(frozen=True)
class AssignResult:
    created: int
    skipped: int
    created_targets: tuple[str, ...]
    skipped_targets: tuple[str, ...]


def assign_certificate_to_targets(
    certificate,
    targets: Sequence[tuple[ContentType, int]],
    *,
    is_primary: bool = False,
) -> AssignResult:
    """Assign ``certificate`` to each ``(content_type, object_id)`` target.

    Existing assignments are skipped. Raises ``AssignmentError`` on an empty
    target list, an unsupported content type, a missing object, or a database
    error.
    """
    if not targets:
        raise AssignmentError("No assignment targets provided.")

    created = 0
    skipped = 0
    created_targets: list[str] = []
    skipped_targets: list[str] = []

    try:
        with transaction.atomic():
            for content_type, object_id in targets:
                if content_type.model not in ALLOWED_ASSIGN_MODELS:
                    raise AssignmentError(f"Unsupported assignment type: {content_type.app_label}.{content_type.model}")

                model_class = content_type.model_class()
                if not model_class.objects.filter(pk=object_id).exists():
                    raise AssignmentError(f"{content_type.model} with id {object_id} does not exist.")

                label = f"{content_type.model}:{object_id}"
                already = CertificateAssignment.objects.filter(
                    certificate=certificate,
                    assigned_object_type=content_type,
                    assigned_object_id=object_id,
                ).exists()
                if already:
                    skipped += 1
                    skipped_targets.append(label)
                    continue

                CertificateAssignment.objects.create(
                    certificate=certificate,
                    assigned_object_type=content_type,
                    assigned_object_id=object_id,
                    is_primary=is_primary,
                )
                created += 1
                created_targets.append(label)
    except (IntegrityError, DatabaseError) as exc:
        logger.error("assign_certificate_to_targets failed: %s", exc)
        raise AssignmentError("A database error occurred during assignment.") from exc

    return AssignResult(created, skipped, tuple(created_targets), tuple(skipped_targets))
