"""Unit tests for the MonitoredEndpoint models."""

import datetime
import uuid

import pytest
from django.utils import timezone


def _make_cert(serial=None):
    from netbox_ssl.models import Certificate

    uid = uuid.uuid4()
    # Build a unique 95-char colon-hex fingerprint from the UUID's 16 bytes +
    # 16 bytes of a second UUID → 32 bytes total.
    raw = uid.bytes + uuid.uuid4().bytes  # 32 bytes
    fingerprint = ":".join(f"{b:02X}" for b in raw)
    return Certificate.objects.create(
        common_name=f"{uid.hex[:8]}.example.com",
        serial_number=serial or f"SER:{uid.hex[:8]}",
        issuer="Test CA",
        valid_from=timezone.now(),
        valid_to=timezone.now() + datetime.timedelta(days=365),
        fingerprint_sha256=fingerprint,
        algorithm="RSA",
    )


@pytest.mark.django_db
class TestMonitoredEndpoint:
    def test_create_and_link_certificate(self):
        from netbox_ssl.models import MonitoredEndpoint, MonitoredEndpointStatusChoices

        cert = _make_cert()
        ep = MonitoredEndpoint.objects.create(
            name="HR portal", url="https://hr.example.com:443", certificate=cert
        )
        assert ep.status == MonitoredEndpointStatusChoices.STATUS_PENDING
        assert ep.certificate == cert
        assert ep.days_remaining == cert.days_remaining

    def test_certificate_set_null_on_delete(self):
        from netbox_ssl.models import MonitoredEndpoint

        cert = _make_cert()
        ep = MonitoredEndpoint.objects.create(name="x", url="https://x.example.com", certificate=cert)
        cert.delete()
        ep.refresh_from_db()
        assert ep.certificate is None

    def test_rotation_history_unique_constraint(self):
        from django.db import IntegrityError

        from netbox_ssl.models import MonitoredEndpoint, MonitoredEndpointCertificate

        cert = _make_cert()
        ep = MonitoredEndpoint.objects.create(name="x", url="https://x.example.com")
        now = timezone.now()
        MonitoredEndpointCertificate.objects.create(endpoint=ep, certificate=cert, first_seen=now, last_seen=now)
        with pytest.raises(IntegrityError):
            MonitoredEndpointCertificate.objects.create(endpoint=ep, certificate=cert, first_seen=now, last_seen=now)

    def test_which_sites_share_a_certificate(self):
        from netbox_ssl.models import MonitoredEndpoint

        cert = _make_cert()
        MonitoredEndpoint.objects.create(name="a", url="https://a.example.com", certificate=cert)
        MonitoredEndpoint.objects.create(name="b", url="https://b.example.com", certificate=cert)
        MonitoredEndpoint.objects.create(name="c", url="https://c.example.com", certificate=_make_cert())
        assert MonitoredEndpoint.objects.filter(certificate=cert).count() == 2
