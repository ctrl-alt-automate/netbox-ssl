"""Unit tests for endpoint events + the poll service."""

import datetime
import importlib.util
import uuid

import pytest

# ---------------------------------------------------------------------------
# Guard: only run these tests inside the Docker container where NetBox lives.
# ---------------------------------------------------------------------------
try:
    _netbox_available = importlib.util.find_spec("netbox") is not None
except (ValueError, ModuleNotFoundError):
    # The host-only unit lane mocks ``netbox`` in sys.modules, so find_spec hits
    # a Mock ``__spec__`` and raises ValueError — treat that as "not available".
    _netbox_available = False
if not _netbox_available:
    pytest.skip("NetBox not available – skipping endpoint monitor tests", allow_module_level=True)

from unittest.mock import patch

from django.utils import timezone


def _make_cert(serial=None):
    from netbox_ssl.models import Certificate

    uid = uuid.uuid4().hex[:8]
    # Fingerprint must be unique per cert — derive 32 bytes from the uid so two
    # certs created in the same test don't collide on the unique constraint.
    fp_bytes = (uid * 4)[:32]  # 32 ASCII chars, all unique per uid
    fingerprint = ":".join([f"{ord(c):02X}" for c in fp_bytes])
    return Certificate.objects.create(
        common_name=f"{uid}.example.com",
        serial_number=serial or f"SER:{uid}",
        issuer="Test CA",
        valid_from=timezone.now(),
        valid_to=timezone.now() + datetime.timedelta(days=365),
        fingerprint_sha256=fingerprint,
        algorithm="RSA",
    )


# ---------------------------------------------------------------------------
# TestEndpointEventPayload
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestEndpointEventPayload:
    def test_payload_has_endpoint_fields(self):
        from netbox_ssl.models import MonitoredEndpoint
        from netbox_ssl.utils.events import EVENT_ENDPOINT_UNREACHABLE, build_endpoint_event_payload

        ep = MonitoredEndpoint.objects.create(name="hr", url="https://hr.example.com")
        payload = build_endpoint_event_payload(ep, EVENT_ENDPOINT_UNREACHABLE)
        assert payload["event_type"] == EVENT_ENDPOINT_UNREACHABLE
        assert payload["endpoint_id"] == ep.pk
        assert payload["url"] == "https://hr.example.com"

    def test_payload_includes_cert_fields_when_cert_linked(self):
        from netbox_ssl.models import MonitoredEndpoint
        from netbox_ssl.utils.events import EVENT_ENDPOINT_CERT_ROTATED, build_endpoint_event_payload

        cert = _make_cert()
        ep = MonitoredEndpoint.objects.create(name="pay", url="https://pay.example.com", certificate=cert)
        payload = build_endpoint_event_payload(ep, EVENT_ENDPOINT_CERT_ROTATED)
        assert payload["certificate_id"] == cert.pk
        assert payload["common_name"] == cert.common_name

    def test_payload_cert_fields_are_none_when_no_cert(self):
        from netbox_ssl.models import MonitoredEndpoint
        from netbox_ssl.utils.events import EVENT_ENDPOINT_UNREACHABLE, build_endpoint_event_payload

        ep = MonitoredEndpoint.objects.create(name="nocert", url="https://nocert.example.com")
        payload = build_endpoint_event_payload(ep, EVENT_ENDPOINT_UNREACHABLE)
        assert payload["certificate_id"] is None
        assert payload["common_name"] is None
        assert payload["days_remaining"] is None

    def test_payload_includes_extra(self):
        from netbox_ssl.models import MonitoredEndpoint
        from netbox_ssl.utils.events import EVENT_ENDPOINT_UNREACHABLE, build_endpoint_event_payload

        ep = MonitoredEndpoint.objects.create(name="extra", url="https://extra.example.com")
        payload = build_endpoint_event_payload(ep, EVENT_ENDPOINT_UNREACHABLE, extra={"prev_id": 42})
        assert payload["prev_id"] == 42

    def test_payload_has_timestamp(self):
        from netbox_ssl.models import MonitoredEndpoint
        from netbox_ssl.utils.events import EVENT_ENDPOINT_UNREACHABLE, build_endpoint_event_payload

        ep = MonitoredEndpoint.objects.create(name="ts", url="https://ts.example.com")
        payload = build_endpoint_event_payload(ep, EVENT_ENDPOINT_UNREACHABLE)
        assert "timestamp" in payload
        assert payload["timestamp"]  # non-empty


# ---------------------------------------------------------------------------
# TestPollEndpoint
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestPollEndpoint:
    def _ep(self, **kw):
        from netbox_ssl.models import MonitoredEndpoint

        return MonitoredEndpoint.objects.create(name="hr", url="https://hr.example.com:443", **kw)

    @patch("netbox_ssl.utils.endpoint_monitor.scrape_and_import")
    def test_ok_links_cert_and_history(self, mock_import):
        from netbox_ssl.models import MonitoredEndpointCertificate, MonitoredEndpointStatusChoices
        from netbox_ssl.utils.endpoint_monitor import poll_endpoint
        from netbox_ssl.utils.url_cert_import import ImportOutcome

        cert = _make_cert()
        mock_import.return_value = ImportOutcome(certificate=cert, created=True)
        ep = self._ep()
        result = poll_endpoint(ep, allowlist=[])
        ep.refresh_from_db()
        assert result.status == MonitoredEndpointStatusChoices.STATUS_OK
        assert ep.certificate == cert
        assert ep.last_seen is not None
        assert MonitoredEndpointCertificate.objects.filter(endpoint=ep, certificate=cert).count() == 1

    @patch("netbox_ssl.utils.endpoint_monitor.scrape_and_import")
    def test_ok_clears_last_error(self, mock_import):
        from netbox_ssl.models import MonitoredEndpointStatusChoices
        from netbox_ssl.utils.endpoint_monitor import poll_endpoint
        from netbox_ssl.utils.url_cert_import import ImportOutcome

        cert = _make_cert()
        mock_import.return_value = ImportOutcome(certificate=cert, created=False)
        ep = self._ep(last_error="previous error")
        poll_endpoint(ep, allowlist=[])
        ep.refresh_from_db()
        assert ep.last_error == ""
        assert ep.status == MonitoredEndpointStatusChoices.STATUS_OK

    @patch("netbox_ssl.utils.endpoint_monitor.scrape_and_import")
    def test_ok_result_has_no_events_when_no_rotation(self, mock_import):
        from netbox_ssl.utils.endpoint_monitor import poll_endpoint
        from netbox_ssl.utils.url_cert_import import ImportOutcome

        cert = _make_cert()
        mock_import.return_value = ImportOutcome(certificate=cert, created=True)
        ep = self._ep()  # no previous cert
        result = poll_endpoint(ep, allowlist=[])
        assert result.rotated is False
        assert len(result.events_fired) == 0

    @patch("netbox_ssl.utils.endpoint_monitor.scrape_and_import")
    def test_unreachable_fires_event(self, mock_import):
        from netbox_ssl.models import MonitoredEndpointStatusChoices
        from netbox_ssl.utils.endpoint_monitor import poll_endpoint
        from netbox_ssl.utils.events import EVENT_ENDPOINT_UNREACHABLE
        from netbox_ssl.utils.tls_scraper import TLSScrapeError

        mock_import.side_effect = TLSScrapeError("connection refused")
        ep = self._ep()
        result = poll_endpoint(ep, allowlist=[])
        ep.refresh_from_db()
        assert result.status == MonitoredEndpointStatusChoices.STATUS_UNREACHABLE
        assert EVENT_ENDPOINT_UNREACHABLE in result.events_fired
        assert ep.last_error

    @patch("netbox_ssl.utils.endpoint_monitor.scrape_and_import")
    def test_unreachable_when_both_attempts_fail(self, mock_import):
        from netbox_ssl.models import MonitoredEndpointStatusChoices
        from netbox_ssl.utils.endpoint_monitor import poll_endpoint
        from netbox_ssl.utils.events import EVENT_ENDPOINT_UNREACHABLE
        from netbox_ssl.utils.tls_scraper import TLSScrapeError

        # Both verify=True and verify=False fail
        mock_import.side_effect = [TLSScrapeError("timeout"), TLSScrapeError("timeout")]
        ep = self._ep()
        result = poll_endpoint(ep, allowlist=[])
        ep.refresh_from_db()
        assert result.status == MonitoredEndpointStatusChoices.STATUS_UNREACHABLE
        assert EVENT_ENDPOINT_UNREACHABLE in result.events_fired
        assert ep.last_error

    @patch("netbox_ssl.utils.endpoint_monitor.scrape_and_import")
    def test_rotation_fires_event_and_keeps_status_ok(self, mock_import):
        from netbox_ssl.models import MonitoredEndpointStatusChoices
        from netbox_ssl.utils.endpoint_monitor import poll_endpoint
        from netbox_ssl.utils.events import EVENT_ENDPOINT_CERT_ROTATED
        from netbox_ssl.utils.url_cert_import import ImportOutcome

        cert_a, cert_b = _make_cert(), _make_cert()
        ep = self._ep(certificate=cert_a)
        mock_import.return_value = ImportOutcome(certificate=cert_b, created=False)
        result = poll_endpoint(ep, allowlist=[])
        ep.refresh_from_db()
        assert result.rotated is True
        assert ep.certificate == cert_b
        assert result.status == MonitoredEndpointStatusChoices.STATUS_OK
        assert EVENT_ENDPOINT_CERT_ROTATED in result.events_fired

    @patch("netbox_ssl.utils.endpoint_monitor.scrape_and_import")
    def test_no_rotation_when_same_cert(self, mock_import):
        from netbox_ssl.utils.endpoint_monitor import poll_endpoint
        from netbox_ssl.utils.url_cert_import import ImportOutcome

        cert = _make_cert()
        ep = self._ep(certificate=cert)
        mock_import.return_value = ImportOutcome(certificate=cert, created=False)
        result = poll_endpoint(ep, allowlist=[])
        assert result.rotated is False

    @patch("netbox_ssl.utils.endpoint_monitor.scrape_and_import")
    def test_untrusted_when_verify_fails_then_succeeds(self, mock_import):
        from netbox_ssl.models import MonitoredEndpointStatusChoices
        from netbox_ssl.utils.endpoint_monitor import poll_endpoint
        from netbox_ssl.utils.events import EVENT_ENDPOINT_UNTRUSTED_CERT
        from netbox_ssl.utils.tls_scraper import TLSScrapeError
        from netbox_ssl.utils.url_cert_import import ImportOutcome

        cert = _make_cert()
        # First (verify_chain=True) raises; second (verify_chain=False) succeeds.
        mock_import.side_effect = [TLSScrapeError("self-signed"), ImportOutcome(certificate=cert, created=True)]
        ep = self._ep()
        result = poll_endpoint(ep, allowlist=[])
        ep.refresh_from_db()
        assert result.status == MonitoredEndpointStatusChoices.STATUS_UNTRUSTED
        assert ep.certificate == cert
        assert EVENT_ENDPOINT_UNTRUSTED_CERT in result.events_fired

    @patch("netbox_ssl.utils.endpoint_monitor.scrape_and_import")
    def test_untrusted_with_rotation_fires_both_events(self, mock_import):
        from netbox_ssl.models import MonitoredEndpointStatusChoices
        from netbox_ssl.utils.endpoint_monitor import poll_endpoint
        from netbox_ssl.utils.events import EVENT_ENDPOINT_CERT_ROTATED, EVENT_ENDPOINT_UNTRUSTED_CERT
        from netbox_ssl.utils.tls_scraper import TLSScrapeError
        from netbox_ssl.utils.url_cert_import import ImportOutcome

        cert_old, cert_new = _make_cert(), _make_cert()
        ep = self._ep(certificate=cert_old)
        mock_import.side_effect = [TLSScrapeError("self-signed"), ImportOutcome(certificate=cert_new, created=True)]
        result = poll_endpoint(ep, allowlist=[])
        ep.refresh_from_db()
        assert result.status == MonitoredEndpointStatusChoices.STATUS_UNTRUSTED
        assert result.rotated is True
        assert EVENT_ENDPOINT_UNTRUSTED_CERT in result.events_fired
        assert EVENT_ENDPOINT_CERT_ROTATED in result.events_fired

    @patch("netbox_ssl.utils.endpoint_monitor.scrape_and_import")
    def test_history_row_upserted_on_second_ok_poll(self, mock_import):
        from netbox_ssl.models import MonitoredEndpointCertificate
        from netbox_ssl.utils.endpoint_monitor import poll_endpoint
        from netbox_ssl.utils.url_cert_import import ImportOutcome

        cert = _make_cert()
        mock_import.return_value = ImportOutcome(certificate=cert, created=False)
        ep = self._ep()
        poll_endpoint(ep, allowlist=[])
        poll_endpoint(ep, allowlist=[])  # second poll: same cert
        # Still only ONE history row (upserted, not doubled)
        assert MonitoredEndpointCertificate.objects.filter(endpoint=ep, certificate=cert).count() == 1

    @patch("netbox_ssl.utils.endpoint_monitor.scrape_and_import")
    def test_poll_result_is_frozen_dataclass(self, mock_import):
        from netbox_ssl.utils.endpoint_monitor import PollResult, poll_endpoint
        from netbox_ssl.utils.url_cert_import import ImportOutcome

        cert = _make_cert()
        mock_import.return_value = ImportOutcome(certificate=cert, created=True)
        ep = self._ep()
        result = poll_endpoint(ep, allowlist=[])
        import dataclasses

        assert isinstance(result, PollResult)
        # Frozen: attribute assignment should raise FrozenInstanceError
        with pytest.raises(dataclasses.FrozenInstanceError):
            result.status = "bad"  # type: ignore[misc]

    @patch("netbox_ssl.utils.endpoint_monitor.scrape_and_import")
    def test_url_validation_error_treated_as_unreachable(self, mock_import):
        from netbox_ssl.models import MonitoredEndpointStatusChoices
        from netbox_ssl.utils.endpoint_monitor import poll_endpoint
        from netbox_ssl.utils.url_validation import URLValidationError

        mock_import.side_effect = URLValidationError("private IP")
        ep = self._ep()
        result = poll_endpoint(ep, allowlist=[])
        ep.refresh_from_db()
        assert result.status == MonitoredEndpointStatusChoices.STATUS_UNREACHABLE
        assert ep.last_error
        assert "private IP" in ep.last_error
