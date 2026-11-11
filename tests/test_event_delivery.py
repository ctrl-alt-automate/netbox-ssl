"""Certificate events must actually reach NetBox's Event Rules.

NetBox dispatches Event Rules (webhooks, scripts, notifications) from the events
it queues while a request or a script job runs. These tests run plugin code
inside that same tracking context and look at what NetBox hands to its Event
Rules pipeline when the context closes — one step short of the webhook itself.

``tests/test_events.py`` and ``tests/test_expiry_scan.py`` check the payload a
"fired" event returns and the scan's bookkeeping, against mocks. Neither ever
asked whether NetBox noticed, which is how the expiry scan could report events
as fired for years while no Event Rule ever saw one.
"""

from __future__ import annotations

import datetime
import importlib.util
import uuid
from contextlib import contextmanager
from unittest.mock import patch

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
    pytest.skip("NetBox not available – skipping event delivery tests", allow_module_level=True)

from django.utils import timezone


def _certificate(*, expires_in_days: int, **kwargs):
    """A certificate whose ``valid_to`` lies ``expires_in_days`` from now."""
    from netbox_ssl.models import Certificate

    uid = uuid.uuid4().hex
    now = timezone.now()
    return Certificate.objects.create(
        common_name=f"{uid[:8]}.example.com",
        serial_number=f"SER:{uid[:16]}",
        fingerprint_sha256=":".join(f"{ord(c):02X}" for c in uid),
        issuer="Test CA",
        valid_from=now - datetime.timedelta(days=30),
        valid_to=now + datetime.timedelta(days=expires_in_days),
        algorithm="rsa",
        **kwargs,
    )


@contextmanager
def _netbox_tracking():
    """Run a block the way NetBox runs a request or a script job.

    Yields the list that receives every event NetBox hands to its Event Rules
    pipeline. The hand-over happens when the tracking context closes, so read
    the list after the ``with`` block.
    """
    from django.contrib.auth import get_user_model
    from django.test import RequestFactory
    from netbox.context_managers import event_tracking

    user_model = get_user_model()
    user = user_model.objects.create_user(username=f"events-{uuid.uuid4().hex[:8]}")
    request = RequestFactory().post("/")
    request.user = user
    request.id = uuid.uuid4()

    dispatched: list = []
    with (
        patch("netbox.context_managers.flush_events", side_effect=dispatched.extend),
        event_tracking(request),
    ):
        yield dispatched


def _certificate_events(dispatched: list) -> list[tuple[int, str]]:
    """``(certificate pk, event type)`` for every dispatched certificate event."""
    return [
        (event["object_id"], event["event_type"]) for event in dispatched if event["object_type"].model == "certificate"
    ]


def _run_scan(**options) -> None:
    from netbox_ssl.scripts.expiry_scan import CertificateExpiryScan

    data = {"tenant": None, "dry_run": False, "ignore_cooldown": False, "cleanup_old_events": False}
    data.update(options)
    CertificateExpiryScan().run(data, commit=True)


@pytest.mark.django_db
class TestFiredCertificateEventReachesNetBox:
    def test_fired_event_is_handed_to_the_event_rules_pipeline(self):
        from netbox_ssl.utils.events import EVENT_CERTIFICATE_EXPIRING_SOON, fire_certificate_event

        certificate = _certificate(expires_in_days=13)

        with _netbox_tracking() as dispatched:
            fire_certificate_event(certificate, EVENT_CERTIFICATE_EXPIRING_SOON, threshold_days=14)

        assert _certificate_events(dispatched) == [(certificate.pk, "object_updated")]

    def test_firing_an_event_does_not_write_back_stale_field_values(self):
        """The scan holds certificates in memory; an edit made meanwhile must survive."""
        from netbox_ssl.models import Certificate
        from netbox_ssl.utils.events import EVENT_CERTIFICATE_EXPIRING_SOON, fire_certificate_event

        stale = _certificate(expires_in_days=13)
        Certificate.objects.filter(pk=stale.pk).update(renewal_note="edited while the scan was running")

        with _netbox_tracking():
            fire_certificate_event(stale, EVENT_CERTIFICATE_EXPIRING_SOON, threshold_days=14)

        assert Certificate.objects.get(pk=stale.pk).renewal_note == "edited while the scan was running"

    def test_firing_an_event_adds_no_changelog_entry(self):
        """Nothing about the certificate changed, so its change log must not say it did."""
        from core.models import ObjectChange
        from django.contrib.contenttypes.models import ContentType

        from netbox_ssl.models import Certificate
        from netbox_ssl.utils.events import EVENT_CERTIFICATE_EXPIRING_SOON, fire_certificate_event

        certificate = _certificate(expires_in_days=13)

        with _netbox_tracking():
            fire_certificate_event(certificate, EVENT_CERTIFICATE_EXPIRING_SOON, threshold_days=14)

        changes = ObjectChange.objects.filter(
            changed_object_type=ContentType.objects.get_for_model(Certificate),
            changed_object_id=certificate.pk,
        )
        assert changes.count() == 0


@pytest.mark.django_db
class TestExpiryScanReachesEventRules:
    def test_certificate_inside_a_threshold_dispatches_an_event(self):
        certificate = _certificate(expires_in_days=13)

        with _netbox_tracking() as dispatched:
            _run_scan()

        assert _certificate_events(dispatched) == [(certificate.pk, "object_updated")]

    def test_expired_certificate_dispatches_an_event(self):
        certificate = _certificate(expires_in_days=-2)

        with _netbox_tracking() as dispatched:
            _run_scan()

        assert _certificate_events(dispatched) == [(certificate.pk, "object_updated")]

    def test_certificate_outside_every_threshold_dispatches_nothing(self):
        _certificate(expires_in_days=400)

        with _netbox_tracking() as dispatched:
            _run_scan()

        assert _certificate_events(dispatched) == []

    def test_dry_run_dispatches_nothing(self):
        _certificate(expires_in_days=13)

        with _netbox_tracking() as dispatched:
            _run_scan(dry_run=True)

        assert _certificate_events(dispatched) == []

    def test_second_scan_inside_the_cooldown_dispatches_nothing(self):
        _certificate(expires_in_days=13)
        with _netbox_tracking():
            _run_scan()

        with _netbox_tracking() as dispatched:
            _run_scan()

        assert _certificate_events(dispatched) == []
