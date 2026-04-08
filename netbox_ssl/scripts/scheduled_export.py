"""
Scheduled Certificate Export.

Generates a certificate export on a schedule and logs the result.
Can be scheduled via NetBox's job scheduler or triggered manually.

Supported formats: CSV, JSON, YAML.
"""

from django.conf import settings
from extras.scripts import ChoiceVar, ObjectVar, Script

from netbox_ssl.models import Certificate, CertificateStatusChoices
from netbox_ssl.utils.export import CertificateExporter


class ScheduledCertificateExport(Script):
    """
    Generate a certificate export report.

    Creates an export of all (or filtered) certificates in the chosen format
    and logs the output. Designed to be run as a scheduled job for periodic
    compliance or inventory reporting.
    """

    class Meta:
        name = "Scheduled Certificate Export"
        description = "Generate a periodic certificate export report"
        commit_default = False
        job_timeout = 300

    export_format = ChoiceVar(
        choices=[
            ("csv", "CSV"),
            ("json", "JSON"),
        ],
        default="json",
        description="Export format",
    )
    tenant = ObjectVar(
        model="tenancy.Tenant",
        description="Filter by tenant (empty = all)",
        required=False,
    )
    status_filter = ChoiceVar(
        choices=[("", "All")] + CertificateStatusChoices.CHOICES,
        default="",
        description="Filter by status",
        required=False,
    )

    def run(self, data, commit):
        export_format = data.get("export_format", "json")
        tenant = data.get("tenant")
        status_filter = data.get("status_filter", "")

        # Build queryset
        qs = Certificate.objects.all()
        if tenant:
            qs = qs.filter(tenant=tenant)
        if status_filter:
            qs = qs.filter(status=status_filter)

        # Respect max export size
        max_size = settings.PLUGINS_CONFIG.get("netbox_ssl", {}).get("max_export_size", 1000)
        total = qs.count()
        if total > max_size:
            self.log_warning(
                f"Export limited to {max_size} of {total} certificates. "
                "Adjust max_export_size in plugin settings to increase."
            )
            qs = qs[:max_size]

        # Generate export
        fields = CertificateExporter.EXTENDED_FIELDS
        output = CertificateExporter.export(qs, format=export_format, fields=fields)

        self.log_info(f"Generated {export_format.upper()} export with {min(total, max_size)} certificates")
        self.log_info(f"Export size: {len(output)} bytes")

        # Output the export content
        self.log_success(output[:5000])  # Log first 5KB as preview
        if len(output) > 5000:
            self.log_info(f"... (truncated, full export is {len(output)} bytes)")

        return output
