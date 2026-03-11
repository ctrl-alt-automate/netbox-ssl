"""
Unit tests for ComplianceReporter utility.

Tests report generation, snapshot creation, trend retrieval, and export.
"""

import importlib.util
import json
import sys
from datetime import date
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Mock Django/NetBox before importing plugin code
# ---------------------------------------------------------------------------
try:
    _spec = importlib.util.find_spec("netbox")
    _NETBOX_AVAILABLE = _spec is not None and _spec.origin is not None
except (ValueError, ModuleNotFoundError):
    _NETBOX_AVAILABLE = False

if not _NETBOX_AVAILABLE:
    if "netbox" not in sys.modules:
        for mod in [
            "django",
            "django.conf",
            "django.db",
            "django.db.models",
            "django.db.models.functions",
            "django.utils",
            "django.utils.timezone",
            "django.utils.translation",
            "django.contrib",
            "django.contrib.contenttypes",
            "django.contrib.contenttypes.fields",
            "django.contrib.contenttypes.models",
            "django.contrib.postgres",
            "django.contrib.postgres.fields",
            "django.contrib.postgres.indexes",
            "django.core",
            "django.core.exceptions",
            "django.urls",
            "django.views",
            "django.views.generic",
            "django.http",
            "netbox",
            "netbox.models",
            "netbox.plugins",
            "utilities",
            "utilities.choices",
        ]:
            sys.modules.setdefault(mod, MagicMock())

    sys.modules.setdefault("netbox_ssl.models", MagicMock())


from netbox_ssl.utils.compliance_reporter import ComplianceReporter


class TestComplianceReporter:
    """Tests for ComplianceReporter."""

    def _make_reporter(self):
        """Create reporter with mocked models."""
        reporter = ComplianceReporter()
        reporter.Certificate = MagicMock()
        reporter.ComplianceCheck = MagicMock()
        reporter.CompliancePolicy = MagicMock()
        reporter.ComplianceTrendSnapshot = MagicMock()
        return reporter

    def _setup_checks_qs(self, reporter, total=20, passed=15, failed=4, errors=1):
        """Configure the check queryset mocks."""
        checks_qs = reporter.ComplianceCheck.objects.all.return_value
        checks_qs.count.return_value = total
        checks_qs.filter.return_value.count.side_effect = [passed, failed, errors]
        checks_qs.filter.return_value.values.return_value.annotate.return_value.order_by.return_value = []
        return checks_qs

    @patch("netbox_ssl.utils.compliance_reporter.date")
    def test_generate_report_keys(self, mock_date):
        """Report contains all expected keys."""
        mock_date.today.return_value = date(2026, 3, 11)
        reporter = self._make_reporter()
        reporter.Certificate.objects.filter.return_value.count.return_value = 50
        self._setup_checks_qs(reporter)

        report = reporter.generate_report()
        expected_keys = {
            "snapshot_date",
            "total_certificates",
            "total_checks",
            "passed_checks",
            "failed_checks",
            "error_checks",
            "compliance_score",
            "severity_breakdown",
            "policy_breakdown",
        }
        assert set(report.keys()) == expected_keys

    @patch("netbox_ssl.utils.compliance_reporter.date")
    def test_compliance_score_calculation(self, mock_date):
        """Score is calculated as passed/total * 100."""
        mock_date.today.return_value = date(2026, 3, 11)
        reporter = self._make_reporter()
        reporter.Certificate.objects.filter.return_value.count.return_value = 10
        self._setup_checks_qs(reporter, total=20, passed=15, failed=4, errors=1)

        report = reporter.generate_report()
        assert report["compliance_score"] == 75.0

    @patch("netbox_ssl.utils.compliance_reporter.date")
    def test_compliance_score_no_checks(self, mock_date):
        """Score is 100 when no checks exist."""
        mock_date.today.return_value = date(2026, 3, 11)
        reporter = self._make_reporter()
        reporter.Certificate.objects.filter.return_value.count.return_value = 0
        self._setup_checks_qs(reporter, total=0, passed=0, failed=0, errors=0)

        report = reporter.generate_report()
        assert report["compliance_score"] == 100.0

    @patch("netbox_ssl.utils.compliance_reporter.date")
    def test_create_snapshot(self, mock_date):
        """Snapshot is created via update_or_create."""
        mock_date.today.return_value = date(2026, 3, 11)
        reporter = self._make_reporter()
        reporter.Certificate.objects.filter.return_value.count.return_value = 10
        self._setup_checks_qs(reporter)
        reporter.ComplianceTrendSnapshot.objects.update_or_create.return_value = (
            MagicMock(),
            True,
        )

        reporter.create_snapshot()
        reporter.ComplianceTrendSnapshot.objects.update_or_create.assert_called_once()

    @patch("netbox_ssl.utils.compliance_reporter.date")
    def test_get_trend(self, mock_date):
        """Trend returns ordered snapshots."""
        mock_date.today.return_value = date(2026, 3, 11)
        reporter = self._make_reporter()
        expected = [
            {"snapshot_date": date(2026, 3, 1), "compliance_score": 85.0},
        ]
        (
            reporter.ComplianceTrendSnapshot.objects.filter.return_value.filter.return_value.order_by.return_value.values.return_value
        ) = expected

        result = reporter.get_trend()
        assert result == expected

    @patch("netbox_ssl.utils.compliance_reporter.date")
    def test_export_json(self, mock_date):
        """JSON export produces valid JSON."""
        mock_date.today.return_value = date(2026, 3, 11)
        reporter = self._make_reporter()
        reporter.Certificate.objects.filter.return_value.count.return_value = 5
        self._setup_checks_qs(reporter, total=10, passed=8, failed=2, errors=0)

        result = reporter.export_report(format="json")
        parsed = json.loads(result)
        assert parsed["compliance_score"] == 80.0
        assert parsed["snapshot_date"] == "2026-03-11"

    @patch("netbox_ssl.utils.compliance_reporter.date")
    def test_export_csv(self, mock_date):
        """CSV export contains header and data row."""
        mock_date.today.return_value = date(2026, 3, 11)
        reporter = self._make_reporter()
        reporter.Certificate.objects.filter.return_value.count.return_value = 5
        self._setup_checks_qs(reporter, total=10, passed=8, failed=2, errors=0)

        result = reporter.export_report(format="csv")
        lines = result.strip().split("\n")
        assert len(lines) == 2  # header + data
        assert "date" in lines[0]
        assert "2026-03-11" in lines[1]

    @patch("netbox_ssl.utils.compliance_reporter.date")
    def test_generate_report_with_tenant(self, mock_date):
        """Report filters by tenant when provided."""
        mock_date.today.return_value = date(2026, 3, 11)
        reporter = self._make_reporter()
        tenant = MagicMock()

        checks_qs = reporter.ComplianceCheck.objects.all.return_value
        filtered_checks = checks_qs.filter.return_value
        filtered_checks.count.return_value = 5
        filtered_checks.filter.return_value.count.side_effect = [4, 1, 0]
        filtered_checks.filter.return_value.values.return_value.annotate.return_value.order_by.return_value = []

        certs_qs = reporter.Certificate.objects.filter.return_value
        certs_qs.filter.return_value.count.return_value = 3

        report = reporter.generate_report(tenant=tenant)
        assert report["total_checks"] == 5
