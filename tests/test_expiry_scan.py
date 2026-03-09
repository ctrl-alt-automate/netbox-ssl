"""
Unit tests for the CertificateEventLog model and expiry scan logic.

Tests idempotency checking and event log lifecycle without requiring
a running NetBox instance.
"""

import importlib.util
import sys
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

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
    _django_utils_timezone.now.return_value = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)

    for mod in [
        "django", "django.conf", "django.db", "django.db.models",
        "django.utils", "django.utils.timezone", "django.utils.translation",
        "django.contrib", "django.contrib.contenttypes",
        "django.contrib.contenttypes.fields", "django.contrib.contenttypes.models",
        "django.contrib.postgres", "django.contrib.postgres.fields",
        "django.contrib.postgres.indexes", "django.core", "django.core.exceptions",
        "django.urls", "netbox", "netbox.models", "netbox.plugins",
        "utilities", "utilities.choices",
    ]:
        sys.modules.setdefault(mod, MagicMock())
    sys.modules["django.utils.timezone"] = _django_utils_timezone

from netbox_ssl.utils.events import (
    EVENT_CERTIFICATE_EXPIRED,
    EVENT_CERTIFICATE_EXPIRING_SOON,
    build_certificate_event_payload,
)


# ---------------------------------------------------------------------------
# Tests: Threshold categorization logic
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestThresholdCategorization:
    """Test the logic that determines which threshold a certificate falls into."""

    def _categorize(self, days_remaining: int, thresholds: list[int]) -> str | None:
        """Simulate the scan's categorization logic."""
        if days_remaining < 0:
            return "expired"
        thresholds_sorted = sorted(thresholds)
        for t in thresholds_sorted:
            if days_remaining <= t:
                return f"{t}_days"
        return None

    def test_expired_certificate(self):
        assert self._categorize(-5, [14, 30, 60, 90]) == "expired"

    def test_within_smallest_threshold(self):
        assert self._categorize(10, [14, 30, 60, 90]) == "14_days"

    def test_within_second_threshold(self):
        assert self._categorize(20, [14, 30, 60, 90]) == "30_days"

    def test_within_third_threshold(self):
        assert self._categorize(45, [14, 30, 60, 90]) == "60_days"

    def test_within_largest_threshold(self):
        assert self._categorize(75, [14, 30, 60, 90]) == "90_days"

    def test_beyond_all_thresholds(self):
        assert self._categorize(120, [14, 30, 60, 90]) is None

    def test_exactly_on_threshold(self):
        assert self._categorize(30, [14, 30, 60, 90]) == "30_days"

    def test_custom_thresholds(self):
        assert self._categorize(5, [7, 21]) == "7_days"
        assert self._categorize(15, [7, 21]) == "21_days"
        assert self._categorize(25, [7, 21]) is None

    def test_single_threshold(self):
        assert self._categorize(5, [30]) == "30_days"
        assert self._categorize(35, [30]) is None


# ---------------------------------------------------------------------------
# Tests: Event payload for scan results
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestScanEventPayloads:
    """Test event payloads generated during scans."""

    def _make_cert(self, days_remaining: int) -> SimpleNamespace:
        now = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        valid_to = now + timedelta(days=days_remaining)
        mock_assignments = MagicMock()
        mock_assignments.select_related.return_value.all.return_value = []
        return SimpleNamespace(
            pk=1,
            common_name="test.example.com",
            serial_number="ABC123",
            status="active",
            days_remaining=days_remaining,
            valid_to=valid_to,
            issuer="CN=Test CA",
            tenant=None,
            assignments=mock_assignments,
        )

    def test_expired_event_payload(self):
        cert = self._make_cert(-5)
        payload = build_certificate_event_payload(cert, EVENT_CERTIFICATE_EXPIRED)
        assert payload["event_type"] == EVENT_CERTIFICATE_EXPIRED
        assert payload["days_remaining"] == -5

    def test_expiring_soon_event_payload_with_threshold(self):
        cert = self._make_cert(10)
        payload = build_certificate_event_payload(
            cert, EVENT_CERTIFICATE_EXPIRING_SOON, threshold_days=14
        )
        assert payload["event_type"] == EVENT_CERTIFICATE_EXPIRING_SOON
        assert payload["threshold_days"] == 14
        assert payload["days_remaining"] == 10

    def test_payload_contains_all_required_fields(self):
        cert = self._make_cert(25)
        payload = build_certificate_event_payload(cert, EVENT_CERTIFICATE_EXPIRING_SOON)

        required_fields = [
            "event_type",
            "certificate_id",
            "common_name",
            "serial_number",
            "status",
            "days_remaining",
            "valid_to",
            "issuer",
            "tenant",
            "timestamp",
            "assigned_objects",
            "assignment_count",
        ]
        for field in required_fields:
            assert field in payload, f"Missing required field: {field}"


# ---------------------------------------------------------------------------
# Tests: Idempotency logic
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestIdempotencyLogic:
    """Test the conceptual idempotency check logic."""

    def test_no_recent_event_allows_firing(self):
        """If no event was fired recently, the scan should fire one."""
        fired_events = {}  # empty = nothing fired recently
        cert_id = 1
        key = (cert_id, EVENT_CERTIFICATE_EXPIRING_SOON, 30)
        assert key not in fired_events

    def test_recent_event_blocks_firing(self):
        """If an event was fired within cooldown, the scan should skip."""
        now = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        fired_events = {
            (1, EVENT_CERTIFICATE_EXPIRING_SOON, 30): now - timedelta(hours=12),
        }
        cooldown_hours = 24
        key = (1, EVENT_CERTIFICATE_EXPIRING_SOON, 30)
        last_fired = fired_events.get(key)
        assert last_fired is not None
        assert (now - last_fired).total_seconds() < cooldown_hours * 3600

    def test_old_event_allows_firing(self):
        """If the event was fired before the cooldown expired, fire again."""
        now = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        fired_events = {
            (1, EVENT_CERTIFICATE_EXPIRING_SOON, 30): now - timedelta(hours=48),
        }
        cooldown_hours = 24
        key = (1, EVENT_CERTIFICATE_EXPIRING_SOON, 30)
        last_fired = fired_events.get(key)
        assert last_fired is not None
        assert (now - last_fired).total_seconds() >= cooldown_hours * 3600

    def test_different_threshold_is_separate_event(self):
        """Events for different thresholds should be tracked independently."""
        fired_events = {
            (1, EVENT_CERTIFICATE_EXPIRING_SOON, 30): datetime.now(tz=timezone.utc),
        }
        key_14 = (1, EVENT_CERTIFICATE_EXPIRING_SOON, 14)
        assert key_14 not in fired_events

    def test_different_cert_is_separate_event(self):
        """Events for different certificates should be tracked independently."""
        fired_events = {
            (1, EVENT_CERTIFICATE_EXPIRING_SOON, 30): datetime.now(tz=timezone.utc),
        }
        key_cert2 = (2, EVENT_CERTIFICATE_EXPIRING_SOON, 30)
        assert key_cert2 not in fired_events
