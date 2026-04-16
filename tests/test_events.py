"""
Unit tests for certificate event utilities.

Tests the event payload builder and event firing helper functions
without requiring a running NetBox instance.
"""

import importlib.util
import sys
from datetime import datetime, timezone
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
        "django",
        "django.conf",
        "django.db",
        "django.db.models",
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
        "netbox",
        "netbox.models",
        "netbox.plugins",
        "utilities",
        "utilities.choices",
    ]:
        sys.modules.setdefault(mod, MagicMock())
    sys.modules["django.utils.timezone"] = _django_utils_timezone

from netbox_ssl.utils.events import (
    EVENT_CERTIFICATE_EXPIRED,
    EVENT_CERTIFICATE_EXPIRING_SOON,
    EVENT_CERTIFICATE_RENEWED,
    EVENT_CERTIFICATE_REVOKED,
    build_certificate_event_payload,
    fire_certificate_event,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_certificate(
    pk: int = 1,
    common_name: str = "example.com",
    serial_number: str = "ABCDEF123456",
    status: str = "active",
    days_remaining: int = 25,
    valid_to: datetime | None = None,
    issuer: str = "CN=Test CA",
    tenant_name: str | None = None,
    assignments: list | None = None,
):
    """Create a mock certificate object for testing."""
    if valid_to is None:
        valid_to = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)

    tenant = None
    if tenant_name:
        tenant = SimpleNamespace(name=tenant_name)

    # Build assignments mock
    mock_assignments = MagicMock()
    if assignments:
        mock_assignments.select_related.return_value.all.return_value = assignments
    else:
        mock_assignments.select_related.return_value.all.return_value = []

    return SimpleNamespace(
        pk=pk,
        common_name=common_name,
        serial_number=serial_number,
        status=status,
        days_remaining=days_remaining,
        valid_to=valid_to,
        issuer=issuer,
        tenant=tenant,
        assignments=mock_assignments,
    )


# ---------------------------------------------------------------------------
# Tests: Event Constants
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestEventConstants:
    def test_event_type_constants_are_strings(self):
        assert isinstance(EVENT_CERTIFICATE_EXPIRED, str)
        assert isinstance(EVENT_CERTIFICATE_EXPIRING_SOON, str)
        assert isinstance(EVENT_CERTIFICATE_RENEWED, str)
        assert isinstance(EVENT_CERTIFICATE_REVOKED, str)

    def test_event_types_are_unique(self):
        events = {
            EVENT_CERTIFICATE_EXPIRED,
            EVENT_CERTIFICATE_EXPIRING_SOON,
            EVENT_CERTIFICATE_RENEWED,
            EVENT_CERTIFICATE_REVOKED,
        }
        assert len(events) == 4


# ---------------------------------------------------------------------------
# Tests: build_certificate_event_payload
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestBuildEventPayload:
    def test_basic_payload_fields(self):
        cert = _make_certificate()
        payload = build_certificate_event_payload(cert, EVENT_CERTIFICATE_EXPIRING_SOON)

        assert payload["event_type"] == EVENT_CERTIFICATE_EXPIRING_SOON
        assert payload["certificate_id"] == 1
        assert payload["common_name"] == "example.com"
        assert payload["serial_number"] == "ABCDEF123456"
        assert payload["status"] == "active"
        assert payload["days_remaining"] == 25
        assert payload["issuer"] == "CN=Test CA"
        assert "timestamp" in payload

    def test_payload_includes_valid_to(self):
        cert = _make_certificate()
        payload = build_certificate_event_payload(cert, EVENT_CERTIFICATE_EXPIRED)
        assert "2026-07-10" in payload["valid_to"]

    def test_payload_with_tenant(self):
        cert = _make_certificate(tenant_name="ACME Corp")
        payload = build_certificate_event_payload(cert, EVENT_CERTIFICATE_EXPIRED)
        assert payload["tenant"] == "ACME Corp"

    def test_payload_without_tenant(self):
        cert = _make_certificate()
        payload = build_certificate_event_payload(cert, EVENT_CERTIFICATE_EXPIRED)
        assert payload["tenant"] is None

    def test_payload_with_threshold_days(self):
        cert = _make_certificate()
        payload = build_certificate_event_payload(cert, EVENT_CERTIFICATE_EXPIRING_SOON, threshold_days=30)
        assert payload["threshold_days"] == 30

    def test_payload_without_threshold_days(self):
        cert = _make_certificate()
        payload = build_certificate_event_payload(cert, EVENT_CERTIFICATE_EXPIRED)
        assert "threshold_days" not in payload

    def test_payload_with_extra_data(self):
        cert = _make_certificate()
        payload = build_certificate_event_payload(
            cert,
            EVENT_CERTIFICATE_RENEWED,
            extra={"old_certificate_id": 42, "assignments_transferred": 5},
        )
        assert payload["old_certificate_id"] == 42
        assert payload["assignments_transferred"] == 5

    def test_payload_includes_assigned_objects(self):
        assignment = SimpleNamespace(
            assigned_object_type=SimpleNamespace(model="service"),
            assigned_object_id=10,
            assigned_object="HTTPS on port 443",
        )
        cert = _make_certificate(assignments=[assignment])
        payload = build_certificate_event_payload(cert, EVENT_CERTIFICATE_EXPIRED)

        assert payload["assignment_count"] == 1
        assert len(payload["assigned_objects"]) == 1
        assert payload["assigned_objects"][0]["type"] == "service"
        assert payload["assigned_objects"][0]["id"] == 10

    def test_payload_empty_assignments(self):
        cert = _make_certificate()
        payload = build_certificate_event_payload(cert, EVENT_CERTIFICATE_EXPIRED)
        assert payload["assignment_count"] == 0
        assert payload["assigned_objects"] == []


# ---------------------------------------------------------------------------
# Tests: fire_certificate_event
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestFireCertificateEvent:
    def test_returns_payload(self):
        cert = _make_certificate()
        payload = fire_certificate_event(cert, EVENT_CERTIFICATE_EXPIRED)
        assert payload["event_type"] == EVENT_CERTIFICATE_EXPIRED
        assert payload["certificate_id"] == 1

    def test_passes_threshold_days(self):
        cert = _make_certificate()
        payload = fire_certificate_event(cert, EVENT_CERTIFICATE_EXPIRING_SOON, threshold_days=14)
        assert payload["threshold_days"] == 14

    def test_passes_extra_data(self):
        cert = _make_certificate()
        payload = fire_certificate_event(
            cert,
            EVENT_CERTIFICATE_RENEWED,
            extra={"old_certificate_id": 99},
        )
        assert payload["old_certificate_id"] == 99

    def test_logs_event(self):
        cert = _make_certificate()
        with patch("netbox_ssl.utils.events.logger") as mock_logger:
            fire_certificate_event(cert, EVENT_CERTIFICATE_EXPIRED)
            mock_logger.info.assert_called_once()
            log_msg = mock_logger.info.call_args[0][0]
            assert "Certificate event fired" in log_msg
