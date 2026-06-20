"""NetBox Script: re-poll all MonitoredEndpoints and reconcile their certs."""

from django.conf import settings
from extras.scripts import BooleanVar, ObjectVar, Script
from tenancy.models import Tenant

from netbox_ssl.models import MonitoredEndpoint, MonitoredEndpointStatusChoices
from netbox_ssl.utils.endpoint_monitor import poll_endpoint


class MonitoredEndpointPoll(Script):
    """Re-scrape each monitored endpoint and update its certificate, status, and history."""

    class Meta:
        name = "Monitored Endpoint Poll"
        description = "Re-scrape each monitored endpoint and update its certificate, status, and history."
        commit_default = True
        job_timeout = 600

    tenant = ObjectVar(
        model=Tenant,
        required=False,
        description="Limit to one tenant (optional).",
    )
    dry_run = BooleanVar(
        default=False,
        description="Log actions without saving.",
    )

    def get_plugin_setting(self, name: str, default=None):
        """Return a single plugin config value."""
        return settings.PLUGINS_CONFIG.get("netbox_ssl", {}).get(name, default)

    def run(self, data, commit):  # noqa: ANN001,ANN201
        """Iterate over MonitoredEndpoints, poll each one, and return a summary string."""
        allowlist: list[str] = self.get_plugin_setting("url_import_private_cidr_allowlist", [])
        dry_run: bool = bool(data.get("dry_run", False))
        tenant = data.get("tenant")

        endpoints = MonitoredEndpoint.objects.all()
        if tenant:
            endpoints = endpoints.filter(tenant=tenant)

        # Materialise counts keyed by status value (all choices start at 0).
        counts: dict[str, int] = {choice[0]: 0 for choice in MonitoredEndpointStatusChoices.CHOICES}
        rotated = 0

        for endpoint in endpoints:
            if dry_run:
                self.log_info(f"[dry-run] would poll {endpoint.name} ({endpoint.url})")
                continue

            result = poll_endpoint(endpoint, allowlist=allowlist)
            counts[result.status] = counts.get(result.status, 0) + 1
            if result.rotated:
                rotated += 1
            suffix = " (rotated)" if result.rotated else ""
            self.log_info(f"{endpoint.name}: {result.status}{suffix}")

        # Build compact summary string, omitting zero-count statuses.
        status_parts = [f"{k}={v}" for k, v in counts.items() if v]
        summary_parts = status_parts + ([f"rotated={rotated}"] if rotated else [])
        summary = ", ".join(summary_parts) if summary_parts else "no changes"

        total = endpoints.count()
        if dry_run:
            self.log_info(f"[dry-run] {total} endpoint(s) would have been polled.")
        else:
            self.log_success(f"Polled {total} endpoint(s): {summary}")

        return summary
