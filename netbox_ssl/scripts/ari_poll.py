"""
ACME Renewal Information (ARI) Polling Script — RFC 9773.

Polls ARI endpoints for all eligible ACME certificates and updates
their suggested renewal windows. Fires events when windows shift
unexpectedly (possible revocation signal).

Designed to be run as a scheduled job. Respects Retry-After headers
from ARI endpoints. Only polls certificates where the retry window
has elapsed.
"""

from django.db import models
from django.utils import timezone
from extras.scripts import BooleanVar, ObjectVar, Script

from netbox_ssl.models import Certificate
from netbox_ssl.utils.ari import ARI_DIRECTORIES, ARIError, build_cert_id, discover_ari_endpoint, poll_ari
from netbox_ssl.utils.events import EVENT_ARI_WINDOW_SHIFTED, fire_certificate_event


class CertificateARIPoll(Script):
    """
    Poll ACME Renewal Information for suggested renewal windows.

    Checks all active ACME certificates against their CA's ARI endpoint.
    Updates ari_suggested_start/end fields and fires events when the
    renewal window shifts earlier than expected.
    """

    class Meta:
        name = "ARI Renewal Window Poll"
        description = "Poll ACME Renewal Information (RFC 9773) for renewal windows"
        commit_default = True
        job_timeout = 600

    tenant = ObjectVar(
        model="tenancy.Tenant",
        description="Filter by tenant (empty = all)",
        required=False,
    )
    dry_run = BooleanVar(
        description="Preview mode — show what would change without saving",
        default=False,
    )

    def run(self, data, commit):
        now = timezone.now()

        # Get eligible ACME certificates
        qs = Certificate.objects.filter(is_acme=True, status="active")

        if data.get("tenant"):
            qs = qs.filter(tenant=data["tenant"])

        # Only poll if retry_after has passed (or never checked)
        qs = qs.filter(models.Q(ari_retry_after__isnull=True) | models.Q(ari_retry_after__lte=now))

        total = qs.count()
        self.log_info(f"Found {total} eligible ACME certificates for ARI polling")

        if total == 0:
            return

        # Cache ARI endpoints per provider to avoid repeated directory fetches
        ari_endpoints: dict[str, str | None] = {}
        updated = 0
        skipped = 0
        errors = 0

        for cert in qs.iterator():
            try:
                # Build CertID if not cached
                if not cert.ari_cert_id and cert.pem_content:
                    try:
                        cert.ari_cert_id = build_cert_id(cert.pem_content)
                    except ARIError as e:
                        self.log_warning(f"{cert.common_name}: Cannot build CertID — {e}")
                        skipped += 1
                        continue

                if not cert.ari_cert_id:
                    skipped += 1
                    continue

                # Discover ARI endpoint for this provider
                provider = cert.acme_provider
                if provider not in ari_endpoints:
                    directory_url = cert.acme_server_url or ARI_DIRECTORIES.get(provider)
                    if directory_url:
                        ari_endpoints[provider] = discover_ari_endpoint(directory_url)
                    else:
                        ari_endpoints[provider] = None

                endpoint = ari_endpoints.get(provider)
                if not endpoint:
                    skipped += 1
                    continue

                # Poll ARI
                result = poll_ari(endpoint, cert.ari_cert_id)

                # Detect unexpected window shift (possible revocation signal)
                old_start = cert.ari_suggested_start
                new_start = result.get("suggested_window_start")

                # Update certificate fields
                cert.ari_suggested_start = new_start
                cert.ari_suggested_end = result.get("suggested_window_end")
                cert.ari_explanation_url = result.get("explanation_url", "")
                cert.ari_last_checked = now
                cert.ari_retry_after = result.get("retry_after")

                if not data.get("dry_run") and commit:
                    cert.save(
                        update_fields=[
                            "ari_cert_id",
                            "ari_suggested_start",
                            "ari_suggested_end",
                            "ari_explanation_url",
                            "ari_last_checked",
                            "ari_retry_after",
                        ]
                    )

                    # Fire event if window shifted earlier than expected
                    if old_start and new_start and new_start < old_start:
                        fire_certificate_event(
                            cert,
                            EVENT_ARI_WINDOW_SHIFTED,
                            extra={
                                "old_start": old_start.isoformat(),
                                "new_start": new_start.isoformat(),
                                "explanation_url": cert.ari_explanation_url,
                            },
                        )
                        self.log_warning(
                            f"{cert.common_name}: ARI window shifted earlier! {old_start.date()} → {new_start.date()}"
                        )

                window_str = ""
                if new_start:
                    end = result.get("suggested_window_end")
                    window_str = f" (window: {new_start.date()} — {end.date() if end else '?'})"

                updated += 1
                self.log_success(f"{cert.common_name}: ARI updated{window_str}")

            except ARIError as e:
                errors += 1
                self.log_warning(f"{cert.common_name}: {e}")
            except Exception as e:
                errors += 1
                self.log_failure(f"{cert.common_name}: unexpected error — {type(e).__name__}")

        self.log_info(f"ARI poll complete: {updated} updated, {skipped} skipped, {errors} errors")
