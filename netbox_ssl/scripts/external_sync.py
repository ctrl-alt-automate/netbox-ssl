"""
External Source Sync Script.

Syncs certificates from configured external sources into NetBox.
Supports dry-run mode, per-source targeting, and forced sync
regardless of interval.

Can be scheduled via NetBox's job scheduler or triggered manually.
"""

import logging

from django.utils import timezone
from extras.scripts import BooleanVar, ObjectVar, Script

logger = logging.getLogger("netbox_ssl.scripts.external_sync")


class ExternalSourceSync(Script):
    """
    Sync certificates from configured external sources.

    This script connects to external certificate management systems
    (e.g., Lemur, generic REST APIs) and synchronizes their certificates
    into NetBox. It supports:

    - Per-source targeting (or sync all enabled sources)
    - Dry-run mode for previewing changes
    - Force sync to ignore interval schedules
    - Automatic renewal detection (Janus pattern)
    """

    class Meta:
        name = "External Source Sync"
        description = "Sync certificates from configured external sources"
        commit_default = True
        job_timeout = 1800

    source = ObjectVar(
        model="netbox_ssl.ExternalSource",
        description="Sync a specific source (leave empty for all enabled sources)",
        required=False,
    )
    dry_run = BooleanVar(
        description="Preview mode: show what changes would be made without applying them",
        default=False,
    )
    force = BooleanVar(
        description="Ignore sync interval and force sync now",
        default=False,
    )

    def run(self, data, commit):
        """Execute the external source sync."""
        now = timezone.now()
        source = data.get("source")
        dry_run = data.get("dry_run", False)
        force = data.get("force", False)

        self.log_info(f"External Source Sync — {now.strftime('%Y-%m-%d %H:%M:%S %Z')}")
        if dry_run:
            self.log_warning("  DRY RUN MODE — no changes will be applied")

        from netbox_ssl.adapters import get_adapter_for_source
        from netbox_ssl.models import ExternalSource
        from netbox_ssl.models.certificates import Certificate
        from netbox_ssl.utils.sync_engine import build_plan, execute_plan

        # Determine which sources to sync
        if source:
            sources = [source]
            self.log_info(f"  Target source: {source.name}")
        else:
            sources = list(ExternalSource.objects.filter(enabled=True))
            self.log_info(f"  Syncing all enabled sources ({len(sources)} found)")

        if not sources:
            self.log_warning("  No sources to sync.")
            return {"synced": 0, "skipped": 0}

        total_synced = 0
        total_skipped = 0
        results = []

        for src in sources:
            self.log_info(f"\n{'=' * 50}")
            self.log_info(f"Source: {src.name} ({src.get_source_type_display()})")

            # Check if sync is due
            if not force and not src.is_sync_due:
                self.log_info("  Skipping: sync not due yet")
                total_skipped += 1
                results.append({"source": src.name, "status": "skipped", "reason": "not due"})
                continue

            try:
                # Update status to syncing
                if not dry_run and commit:
                    src.sync_status = "syncing"
                    src.save(update_fields=["sync_status", "last_updated"])

                # Fetch certificates
                adapter = get_adapter_for_source(src)
                self.log_info("  Fetching certificates...")
                fetched_certs = adapter.fetch_certificates()
                self.log_info(f"  Fetched {len(fetched_certs)} certificates")

                # Build plan
                local_certs = Certificate.objects.filter(external_source=src)
                plan = build_plan(fetched_certs, local_certs, src)

                self.log_info(
                    f"  Plan: {len(plan.creates)} create, "
                    f"{len(plan.updates)} update, "
                    f"{len(plan.renewals)} renew, "
                    f"{len(plan.removals)} remove, "
                    f"{plan.unchanged} unchanged"
                )

                # Execute plan
                sync_log = execute_plan(plan, src, dry_run=dry_run or not commit)

                if sync_log.success:
                    self.log_success(f"  Sync completed: {sync_log.message}")
                else:
                    self.log_failure(f"  Sync completed with errors: {sync_log.message}")

                total_synced += 1
                results.append(
                    {
                        "source": src.name,
                        "status": "success" if sync_log.success else "error",
                        "creates": len(plan.creates),
                        "updates": len(plan.updates),
                        "renewals": len(plan.renewals),
                        "removals": len(plan.removals),
                        "unchanged": plan.unchanged,
                        "errors": len(sync_log.errors),
                    }
                )

            except Exception as e:
                self.log_failure(f"  Sync failed: {e}")
                logger.error("Sync failed for source '%s': %s", src.name, e)
                if not dry_run and commit:
                    src.sync_status = "error"
                    src.last_sync_message = f"Sync failed: {type(e).__name__}"
                    src.save(update_fields=["sync_status", "last_sync_message", "last_updated"])
                total_synced += 1
                results.append(
                    {
                        "source": src.name,
                        "status": "error",
                        "error": str(e),
                    }
                )

        # Summary
        self.log_info(f"\n{'=' * 50}")
        self.log_info("SYNC SUMMARY")
        self.log_info(f"{'=' * 50}")
        self.log_info(f"  Sources synced: {total_synced}")
        self.log_info(f"  Sources skipped: {total_skipped}")
        if dry_run:
            self.log_warning("  DRY RUN — no changes were applied")

        return {
            "synced_at": now.isoformat(),
            "sources_synced": total_synced,
            "sources_skipped": total_skipped,
            "dry_run": dry_run,
            "force": force,
            "results": results,
        }
