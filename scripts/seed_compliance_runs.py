"""
Run compliance checks over every seeded certificate and back-fill 90 days of
ComplianceTrendSnapshot rows so the compliance report chart has data.

Pipe into Django shell:

    docker exec -i netbox-ssl-netbox-1 /opt/netbox/venv/bin/python \\
        /opt/netbox/netbox/manage.py shell < scripts/seed_compliance_runs.py
"""

from datetime import date, timedelta

from netbox_ssl.models import (
    Certificate,
    ComplianceCheck,
    CompliancePolicy,
    ComplianceTrendSnapshot,
)
from netbox_ssl.utils.compliance_checker import ComplianceChecker
from netbox_ssl.utils.compliance_reporter import ComplianceReporter

print("Running compliance checks for every certificate...")
checks_created = 0
for cert in Certificate.objects.all():
    results = ComplianceChecker.run_all_checks(cert)
    saved = ComplianceChecker.save_check_results(cert, results)
    checks_created += len(saved)
print(f"  Total checks recorded: {checks_created}")

# Current report (creates today's snapshot)
reporter = ComplianceReporter()
today_snap = reporter.create_snapshot()
print(f"Today's snapshot score: {today_snap.compliance_score:.1f}%")

# Back-fill 90-day trend — simulate gradual improvement from 62% to today's score.
print("Back-filling 90-day trend...")
today = date.today()
current_score = float(today_snap.compliance_score)
total_certs = today_snap.total_certificates
total_checks = today_snap.total_checks

# Create snapshots every 7 days going back 91 days.
backfilled = 0
for weeks_ago in range(1, 14):
    snap_date = today - timedelta(days=weeks_ago * 7)
    # Score ramp: older = lower (start ~60%, end at current)
    ramp = (14 - weeks_ago) / 14
    simulated_score = max(58.0, min(current_score, 60.0 + (current_score - 60.0) * ramp))
    passed = round(total_checks * simulated_score / 100)
    failed = total_checks - passed

    snap, created = ComplianceTrendSnapshot.objects.update_or_create(
        tenant=None,
        snapshot_date=snap_date,
        defaults={
            "total_certificates": total_certs,
            "total_checks": total_checks,
            "passed_checks": passed,
            "failed_checks": failed,
            "compliance_score": round(simulated_score, 2),
            "details": {},
        },
    )
    if created:
        backfilled += 1

print(f"  Back-filled snapshots: {backfilled}")
print("Done.")
print(f"Summary: {ComplianceCheck.objects.count()} checks, "
      f"{ComplianceTrendSnapshot.objects.count()} trend snapshots, "
      f"{CompliancePolicy.objects.count()} policies.")
