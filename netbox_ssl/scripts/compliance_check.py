"""
Scheduled compliance evaluation across the certificate inventory.

The documentation has described a ``CertificateComplianceCheck`` script since
v0.7, but no such script was ever written (issue #164): compliance could only be
evaluated one certificate at a time through the REST API. This provides the
scheduled, fleet-wide evaluation the docs promised.

Results are upserted per (certificate, policy) pair by
``ComplianceChecker.save_check_results``, so re-running the script refreshes the
existing rows rather than accumulating duplicates.
"""

from extras.scripts import BooleanVar, ObjectVar, Script
from tenancy.models import Tenant

from netbox_ssl.models import Certificate, CertificateStatusChoices, CompliancePolicy
from netbox_ssl.utils.compliance_checker import ComplianceChecker


class CertificateComplianceCheck(Script):
    """
    Evaluate every enabled compliance policy against the certificate inventory.

    Features:
    - Optional tenant filtering
    - Optional restriction to a single policy
    - Skips archived/replaced certificates by default
    - Dry-run mode that reports counts without writing results
    """

    class Meta:
        name = "Certificate Compliance Check"
        description = "Evaluate compliance policies against all certificates"
        commit_default = True
        job_timeout = 1800

    tenant = ObjectVar(
        model=Tenant,
        description="Limit the run to one tenant (optional).",
        required=False,
    )
    policy = ObjectVar(
        model=CompliancePolicy,
        description="Evaluate only this policy (optional; default is every enabled policy).",
        required=False,
    )
    include_inactive = BooleanVar(
        description="Also check archived and replaced certificates.",
        default=False,
    )
    dry_run = BooleanVar(
        description="Report what would be evaluated without saving results.",
        default=False,
    )

    def run(self, data: dict, commit: bool) -> str:
        """Evaluate policies across the selected certificates and return a summary."""
        tenant = data.get("tenant")
        policy = data.get("policy")
        include_inactive = bool(data.get("include_inactive", False))
        dry_run = bool(data.get("dry_run", False))

        certificates = Certificate.objects.all()
        if tenant:
            certificates = certificates.filter(tenant=tenant)
        if not include_inactive:
            certificates = certificates.exclude(
                status__in=[
                    CertificateStatusChoices.STATUS_ARCHIVED,
                    CertificateStatusChoices.STATUS_REPLACED,
                ]
            )

        if policy:
            policies = CompliancePolicy.objects.filter(pk=policy.pk, enabled=True)
            if not policies.exists():
                self.log_warning(f"Policy '{policy}' is disabled — nothing to evaluate.")
                return "No enabled policy selected."
        else:
            policies = None  # ComplianceChecker resolves the enabled, in-scope set

        total = certificates.count()
        if dry_run:
            scope = f"policy '{policy}'" if policy else "all enabled policies"
            self.log_info(f"Dry-run: would evaluate {scope} against {total} certificate(s).")
            return f"Dry-run: {total} certificate(s) would be evaluated."

        checked = 0
        passed = 0
        failed = 0

        for certificate in certificates.select_related("tenant").iterator():
            results = ComplianceChecker.run_all_checks(certificate, policies)
            if not results:
                continue
            saved = ComplianceChecker.save_check_results(certificate, results)
            checked += 1
            for check in saved:
                if check.is_passing:
                    passed += 1
                else:
                    failed += 1
                    self.log_warning(f"{certificate.common_name} failed '{check.policy.name}': {check.message}")

        if failed:
            self.log_warning(f"{failed} failing check(s) across {checked} certificate(s).")
        else:
            self.log_success(f"All {passed} check(s) passed across {checked} certificate(s).")

        return f"Evaluated {checked} certificate(s): {passed} passed, {failed} failed."
