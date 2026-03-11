"""
Unit tests for CertificateAnalytics aggregation utilities.

Tests the analytics methods without requiring a running NetBox instance.
"""

import importlib.util
import sys
from datetime import datetime, timedelta
from datetime import timezone as tz
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Mock Django/NetBox before importing plugin code
# ---------------------------------------------------------------------------
try:
    _spec = importlib.util.find_spec("netbox")
    _NETBOX_AVAILABLE = _spec is not None and _spec.origin is not None
except (ValueError, ModuleNotFoundError):
    _NETBOX_AVAILABLE = False

if not _NETBOX_AVAILABLE and "netbox" not in sys.modules:
    _django_utils_timezone = MagicMock()
    _now = datetime(2026, 6, 15, 12, 0, 0, tzinfo=tz.utc)
    _django_utils_timezone.now.return_value = _now

    _django_db_models = MagicMock()
    # Expose real-looking Avg, Count, F, Q, etc.
    _django_db_models.Avg = MagicMock(name="Avg")
    _django_db_models.Count = MagicMock(name="Count")
    _django_db_models.F = MagicMock(name="F")
    _django_db_models.Q = MagicMock(name="Q")

    _django_db_models_functions = MagicMock()
    _django_db_models_functions.TruncMonth = MagicMock(name="TruncMonth")

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
        "netbox",
        "netbox.models",
        "netbox.plugins",
        "netbox.views",
        "netbox.views.generic",
        "utilities",
        "utilities.choices",
        "utilities.permissions",
    ]:
        sys.modules.setdefault(mod, MagicMock())
    sys.modules["django.utils.timezone"] = _django_utils_timezone
    sys.modules["django.db.models"] = _django_db_models
    sys.modules["django.db.models.functions"] = _django_db_models_functions

    # Mock plugin models module
    sys.modules.setdefault("netbox_ssl.models", MagicMock())


from netbox_ssl.utils.analytics import CertificateAnalytics


class TestCertificateAnalytics:
    """Tests for CertificateAnalytics aggregation methods."""

    def _make_analytics(self):
        """Create analytics instance with mocked models."""
        analytics = CertificateAnalytics()
        analytics.Certificate = MagicMock()
        analytics.CertificateAssignment = MagicMock()
        return analytics

    def test_get_status_distribution(self):
        """Returns annotated status counts."""
        analytics = self._make_analytics()
        expected = [{"status": "active", "count": 10}, {"status": "expired", "count": 3}]
        qs = analytics.Certificate.objects.all.return_value
        qs.values.return_value.annotate.return_value.order_by.return_value = expected

        result = analytics.get_status_distribution()
        assert result == expected
        qs.values.assert_called_once_with("status")

    def test_get_status_distribution_with_tenant(self):
        """Filters by tenant when provided."""
        analytics = self._make_analytics()
        tenant = MagicMock()
        qs = analytics.Certificate.objects.all.return_value
        filtered = qs.filter.return_value
        filtered.values.return_value.annotate.return_value.order_by.return_value = []

        analytics.get_status_distribution(tenant=tenant)
        qs.filter.assert_called_once_with(tenant=tenant)

    def test_get_algorithm_distribution(self):
        """Returns annotated algorithm counts."""
        analytics = self._make_analytics()
        expected = [{"algorithm": "rsa", "count": 15}]
        qs = analytics.Certificate.objects.all.return_value
        qs.values.return_value.annotate.return_value.order_by.return_value = expected

        result = analytics.get_algorithm_distribution()
        assert result == expected

    @patch("netbox_ssl.utils.analytics.timezone")
    def test_get_avg_remaining_days_with_certs(self, mock_tz):
        """Returns average days remaining as float."""
        mock_tz.now.return_value = datetime(2026, 6, 15, tzinfo=tz.utc)
        analytics = self._make_analytics()
        qs = analytics.Certificate.objects.all.return_value
        filtered = qs.filter.return_value
        filtered.aggregate.return_value = {"avg_remaining": timedelta(days=45)}

        result = analytics.get_avg_remaining_days()
        assert result == 45.0

    @patch("netbox_ssl.utils.analytics.timezone")
    def test_get_avg_remaining_days_no_certs(self, mock_tz):
        """Returns None when no active certificates."""
        mock_tz.now.return_value = datetime(2026, 6, 15, tzinfo=tz.utc)
        analytics = self._make_analytics()
        qs = analytics.Certificate.objects.all.return_value
        filtered = qs.filter.return_value
        filtered.aggregate.return_value = {"avg_remaining": None}

        result = analytics.get_avg_remaining_days()
        assert result is None

    def test_get_orphan_count(self):
        """Returns count of active certs with no assignments."""
        analytics = self._make_analytics()
        qs = analytics.Certificate.objects.all.return_value
        qs.filter.return_value.annotate.return_value.filter.return_value.count.return_value = 5

        result = analytics.get_orphan_count()
        assert result == 5

    def test_get_acme_distribution(self):
        """Returns ACME vs non-ACME counts."""
        analytics = self._make_analytics()
        qs = analytics.Certificate.objects.all.return_value
        active_qs = qs.filter.return_value
        active_qs.filter.return_value.count.side_effect = [8, 12]

        result = analytics.get_acme_distribution()
        assert result["acme"] == 8
        assert result["non_acme"] == 12

    def test_get_total_active(self):
        """Returns active certificate count."""
        analytics = self._make_analytics()
        qs = analytics.Certificate.objects.all.return_value
        qs.filter.return_value.count.return_value = 42

        result = analytics.get_total_active()
        assert result == 42

    @patch("netbox_ssl.utils.analytics.timezone")
    def test_get_expiry_forecast(self, mock_tz):
        """Returns monthly expiry counts."""
        mock_tz.now.return_value = datetime(2026, 6, 15, tzinfo=tz.utc)
        analytics = self._make_analytics()
        expected = [
            {"month": datetime(2026, 7, 1, tzinfo=tz.utc), "count": 3},
            {"month": datetime(2026, 8, 1, tzinfo=tz.utc), "count": 7},
        ]
        qs = analytics.Certificate.objects.all.return_value
        (
            qs.filter.return_value.annotate.return_value.values.return_value.annotate.return_value.order_by.return_value
        ) = expected

        result = analytics.get_expiry_forecast()
        assert result == expected

    @patch("netbox_ssl.utils.analytics.timezone")
    def test_get_dashboard_context_keys(self, mock_tz):
        """Dashboard context contains all expected keys."""
        mock_tz.now.return_value = datetime(2026, 6, 15, tzinfo=tz.utc)
        analytics = self._make_analytics()
        # Set up minimal mocks for all methods
        qs = analytics.Certificate.objects.all.return_value
        qs.values.return_value.annotate.return_value.order_by.return_value = []
        qs.filter.return_value.values.return_value.annotate.return_value.order_by.return_value = []
        qs.filter.return_value.aggregate.return_value = {"avg_remaining": None}
        qs.filter.return_value.annotate.return_value.filter.return_value.count.return_value = 0
        qs.filter.return_value.count.return_value = 0
        qs.filter.return_value.filter.return_value.count.return_value = 0
        (
            qs.filter.return_value.annotate.return_value.values.return_value.annotate.return_value.order_by.return_value
        ) = []

        ctx = analytics.get_dashboard_context()
        expected_keys = {
            "status_distribution",
            "ca_distribution",
            "algorithm_distribution",
            "avg_remaining_days",
            "orphan_count",
            "acme_distribution",
            "expiry_forecast",
            "total_active",
        }
        assert set(ctx.keys()) == expected_keys
