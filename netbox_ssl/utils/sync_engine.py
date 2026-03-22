"""Sync engine for external source certificate synchronization.

Implements a 4-phase sync process: FETCH -> DIFF -> APPLY -> LOG.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from django.utils import timezone

from ..adapters.base import FetchedCertificate

logger = logging.getLogger("netbox_ssl.sync_engine")


@dataclass(frozen=True)
class SyncAction:
    """A single action to perform during sync."""

    action: str  # "create", "update", "renew", "mark_removed"
    external_id: str
    fetched: FetchedCertificate | None
    local_cert_id: int | None
    reason: str


@dataclass
class SyncPlan:
    """Plan of all actions to perform during a sync run."""

    creates: list[SyncAction] = field(default_factory=list)
    updates: list[SyncAction] = field(default_factory=list)
    renewals: list[SyncAction] = field(default_factory=list)
    removals: list[SyncAction] = field(default_factory=list)
    unchanged: int = 0

    @property
    def total_changes(self) -> int:
        """Total number of changes in the plan."""
        return len(self.creates) + len(self.updates) + len(self.renewals) + len(self.removals)


def build_plan(fetched_certs: list[FetchedCertificate], local_certs_qs, source) -> SyncPlan:
    """Build a sync plan by comparing fetched certificates with local state.

    Args:
        fetched_certs: List of certificates from the external source.
        local_certs_qs: QuerySet of Certificate objects already linked to this source.
        source: The ExternalSource instance.

    Returns:
        SyncPlan with categorized actions.
    """
    plan = SyncPlan()

    # Build lookup maps for local certificates
    local_by_ext_id: dict[str, object] = {}
    local_by_fingerprint: dict[str, object] = {}

    for cert in local_certs_qs:
        if cert.external_id:
            local_by_ext_id[cert.external_id] = cert
        if cert.fingerprint_sha256:
            local_by_fingerprint[cert.fingerprint_sha256] = cert

    # Track which local certs were seen in the fetched set
    seen_local_ids: set[int] = set()

    for fetched in fetched_certs:
        # 1. Match by (external_source, external_id)
        local = local_by_ext_id.get(fetched.external_id)

        # 2. Fallback match by fingerprint_sha256
        if local is None:
            local = local_by_fingerprint.get(fetched.fingerprint_sha256)

        if local is not None:
            seen_local_ids.add(local.pk)

            # Same external_id + different serial -> renewal
            if local.external_id == fetched.external_id and local.serial_number != fetched.serial_number:
                plan.renewals.append(
                    SyncAction(
                        action="renew",
                        external_id=fetched.external_id,
                        fetched=fetched,
                        local_cert_id=local.pk,
                        reason=f"Serial changed: {local.serial_number[:20]} -> {fetched.serial_number[:20]}",
                    )
                )
            # Same external_id + same serial + metadata diff -> update
            elif _has_metadata_diff(local, fetched):
                plan.updates.append(
                    SyncAction(
                        action="update",
                        external_id=fetched.external_id,
                        fetched=fetched,
                        local_cert_id=local.pk,
                        reason="Metadata changed",
                    )
                )
            else:
                plan.unchanged += 1
        else:
            # New certificate
            plan.creates.append(
                SyncAction(
                    action="create",
                    external_id=fetched.external_id,
                    fetched=fetched,
                    local_cert_id=None,
                    reason="New certificate from external source",
                )
            )

    # Local certs from this source not in fetched -> mark_removed
    for cert in local_certs_qs:
        if cert.pk not in seen_local_ids and not cert.source_removed:
            plan.removals.append(
                SyncAction(
                    action="mark_removed",
                    external_id=cert.external_id,
                    fetched=None,
                    local_cert_id=cert.pk,
                    reason="No longer present in external source",
                )
            )

    return plan


def _has_metadata_diff(local, fetched: FetchedCertificate) -> bool:
    """Check if there are metadata differences between local and fetched cert.

    Args:
        local: Local Certificate model instance.
        fetched: FetchedCertificate from the external source.

    Returns:
        True if there are meaningful differences.
    """
    if local.common_name != fetched.common_name:
        return True
    if local.issuer != fetched.issuer:
        return True
    if local.fingerprint_sha256 != fetched.fingerprint_sha256:
        return True
    if fetched.pem_content and local.pem_content != fetched.pem_content:
        return True
    if fetched.issuer_chain and local.issuer_chain != fetched.issuer_chain:
        return True
    if fetched.key_size is not None and local.key_size != fetched.key_size:
        return True
    return fetched.algorithm != "unknown" and local.algorithm != fetched.algorithm


def execute_plan(plan: SyncPlan, source, dry_run: bool = False):
    """Execute a sync plan, applying changes to the database.

    Args:
        plan: The SyncPlan to execute.
        source: The ExternalSource instance.
        dry_run: If True, no database changes are made.

    Returns:
        ExternalSourceSyncLog instance with sync results.
    """
    from ..models import Certificate
    from ..models.external_source import ExternalSourceSyncLog

    log = ExternalSourceSyncLog(
        source=source,
        dry_run=dry_run,
        certificates_fetched=(len(plan.creates) + len(plan.updates) + len(plan.renewals) + plan.unchanged),
    )

    errors: list[dict[str, str]] = []

    # Process creates
    for action in plan.creates:
        if dry_run:
            log.certificates_created += 1
            continue
        try:
            _create_certificate(action.fetched, source)
            log.certificates_created += 1
        except Exception as e:
            logger.error("Failed to create certificate %s: %s", action.external_id, e)
            errors.append({"external_id": action.external_id, "error": str(e), "action": "create"})

    # Process updates
    for action in plan.updates:
        if dry_run:
            log.certificates_updated += 1
            continue
        try:
            _update_certificate(action.local_cert_id, action.fetched)
            log.certificates_updated += 1
        except Exception as e:
            logger.error("Failed to update certificate %s: %s", action.external_id, e)
            errors.append({"external_id": action.external_id, "error": str(e), "action": "update"})

    # Process renewals (Janus pattern)
    for action in plan.renewals:
        if dry_run:
            log.certificates_renewed += 1
            continue
        try:
            _renew_certificate(action.local_cert_id, action.fetched, source)
            log.certificates_renewed += 1
        except Exception as e:
            logger.error("Failed to renew certificate %s: %s", action.external_id, e)
            errors.append({"external_id": action.external_id, "error": str(e), "action": "renew"})

    # Process removals
    for action in plan.removals:
        if dry_run:
            log.certificates_removed += 1
            continue
        try:
            cert = Certificate.objects.get(pk=action.local_cert_id)
            cert.source_removed = True
            cert.save(update_fields=["source_removed", "last_updated"])
            log.certificates_removed += 1
        except Exception as e:
            logger.error("Failed to mark certificate %s as removed: %s", action.external_id, e)
            errors.append({"external_id": action.external_id, "error": str(e), "action": "mark_removed"})

    log.certificates_unchanged = plan.unchanged
    log.errors = errors
    log.success = len(errors) == 0
    log.finished_at = timezone.now()
    log.message = _build_summary_message(log)

    if not dry_run:
        log.save()

        # Update source status
        source.sync_status = "ok" if log.success else "error"
        source.last_synced = log.finished_at
        source.last_sync_message = log.message
        source.save(update_fields=["sync_status", "last_synced", "last_sync_message", "last_updated"])

    return log


def _create_certificate(fetched: FetchedCertificate, source) -> None:
    """Create a new Certificate from a FetchedCertificate.

    Args:
        fetched: The fetched certificate data.
        source: The ExternalSource instance.
    """
    from ..models import Certificate, CertificateStatusChoices

    cert = Certificate(
        common_name=fetched.common_name,
        serial_number=fetched.serial_number,
        fingerprint_sha256=fetched.fingerprint_sha256,
        issuer=fetched.issuer,
        valid_from=fetched.valid_from,
        valid_to=fetched.valid_to,
        sans=fetched.sans,
        key_size=fetched.key_size,
        algorithm=fetched.algorithm,
        pem_content=fetched.pem_content,
        issuer_chain=fetched.issuer_chain,
        external_source=source,
        external_id=fetched.external_id,
        tenant=source.tenant,
        status=CertificateStatusChoices.STATUS_ACTIVE,
    )
    # Set sync actor for lifecycle tracking
    if hasattr(cert, "_sync_actor"):
        cert._sync_actor = f"external_sync:{source.name}"
    cert.save()

    # Auto-detect CA and ACME
    cert.auto_detect_ca()
    cert.auto_detect_acme(save=True)

    logger.info(
        "Created certificate '%s' (ext_id=%s) from source '%s'",
        fetched.common_name,
        fetched.external_id,
        source.name,
    )


def _update_certificate(local_cert_id: int, fetched: FetchedCertificate) -> None:
    """Update an existing Certificate with new metadata.

    Args:
        local_cert_id: The pk of the local Certificate.
        fetched: The fetched certificate data.
    """
    from ..models import Certificate

    cert = Certificate.objects.get(pk=local_cert_id)
    cert.common_name = fetched.common_name
    cert.issuer = fetched.issuer
    cert.fingerprint_sha256 = fetched.fingerprint_sha256
    if fetched.pem_content:
        cert.pem_content = fetched.pem_content
    if fetched.issuer_chain:
        cert.issuer_chain = fetched.issuer_chain
    if fetched.key_size is not None:
        cert.key_size = fetched.key_size
    if fetched.algorithm != "unknown":
        cert.algorithm = fetched.algorithm
    cert.source_removed = False
    cert.save()

    logger.info("Updated certificate '%s' (pk=%s)", fetched.common_name, local_cert_id)


def _renew_certificate(old_cert_id: int, fetched: FetchedCertificate, source) -> None:
    """Renew a certificate using the Janus pattern.

    Creates a new certificate, copies assignments from the old one,
    and marks the old certificate as Replaced.

    Args:
        old_cert_id: The pk of the old Certificate to be replaced.
        fetched: The fetched certificate data for the new cert.
        source: The ExternalSource instance.
    """
    from ..models import Certificate, CertificateAssignment, CertificateStatusChoices

    old_cert = Certificate.objects.get(pk=old_cert_id)

    # Create new certificate
    new_cert = Certificate(
        common_name=fetched.common_name,
        serial_number=fetched.serial_number,
        fingerprint_sha256=fetched.fingerprint_sha256,
        issuer=fetched.issuer,
        valid_from=fetched.valid_from,
        valid_to=fetched.valid_to,
        sans=fetched.sans,
        key_size=fetched.key_size,
        algorithm=fetched.algorithm,
        pem_content=fetched.pem_content,
        issuer_chain=fetched.issuer_chain,
        external_source=source,
        external_id=fetched.external_id,
        tenant=source.tenant or old_cert.tenant,
        status=CertificateStatusChoices.STATUS_ACTIVE,
    )
    if hasattr(new_cert, "_sync_actor"):
        new_cert._sync_actor = f"external_sync:{source.name}"
    new_cert.save()

    # Copy assignments from old cert to new cert
    old_assignments = CertificateAssignment.objects.filter(certificate=old_cert)
    for assignment in old_assignments:
        CertificateAssignment.objects.create(
            certificate=new_cert,
            assigned_object_type=assignment.assigned_object_type,
            assigned_object_id=assignment.assigned_object_id,
        )

    # Mark old cert as replaced
    old_cert.status = CertificateStatusChoices.STATUS_REPLACED
    old_cert.replaced_by = new_cert
    old_cert.save()

    logger.info(
        "Renewed certificate '%s': old pk=%s -> new pk=%s",
        fetched.common_name,
        old_cert_id,
        new_cert.pk,
    )


def _build_summary_message(log) -> str:
    """Build a human-readable summary message for a sync log.

    Args:
        log: ExternalSourceSyncLog instance.

    Returns:
        Summary string.
    """
    parts = []
    if log.certificates_created:
        parts.append(f"{log.certificates_created} created")
    if log.certificates_updated:
        parts.append(f"{log.certificates_updated} updated")
    if log.certificates_renewed:
        parts.append(f"{log.certificates_renewed} renewed")
    if log.certificates_removed:
        parts.append(f"{log.certificates_removed} removed")
    if log.certificates_unchanged:
        parts.append(f"{log.certificates_unchanged} unchanged")
    if log.errors:
        parts.append(f"{len(log.errors)} errors")

    prefix = "Dry run: " if log.dry_run else ""
    return f"{prefix}{', '.join(parts)}" if parts else f"{prefix}No changes"
