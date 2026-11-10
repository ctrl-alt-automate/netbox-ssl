"""Endpoint rotation must run the Janus renewal, not just re-point the endpoint (#184).

These tests drive the real ``poll_endpoint`` -> ``scrape_and_import`` -> parser ->
ORM path. Only the network is replaced (URL validation, DNS and the TLS
handshake), so every assertion is about what an operator sees once the poll
script has run: which certificates are Active, which are Replaced, and what
moved across to the successor.

The older ``test_endpoint_monitor.py`` mocks ``scrape_and_import`` and asserts
the endpoint's pointer and the fired event. That is how #184 shipped green: no
test ever looked at the *previous* certificate after a rotation.
"""

from __future__ import annotations

import importlib.util
import logging
import sys
import uuid
from contextlib import contextmanager
from pathlib import Path
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
    pytest.skip("NetBox not available – skipping endpoint rotation renewal tests", allow_module_level=True)

# Add tests/ dir so cert_factory can be imported as a top-level module
# (mirrors the pattern in test_url_cert_import.py).
_tests_dir = Path(__file__).parent
if str(_tests_dir) not in sys.path:
    sys.path.insert(0, str(_tests_dir))

from cert_factory import CertFactory  # noqa: E402


def _cn() -> str:
    return f"{uuid.uuid4().hex[:8]}.example.com"


def _old_pem(cn: str, **kwargs) -> str:
    """A certificate issued 60 days ago with 30 days left: due for renewal."""
    return CertFactory.create(cn=cn, issued_days_ago=60, valid_days=30, **kwargs)


def _new_pem(cn: str, **kwargs) -> str:
    """The freshly issued successor."""
    return CertFactory.create(cn=cn, valid_days=90, **kwargs)


def _endpoint(cn: str, **kwargs):
    from netbox_ssl.models import MonitoredEndpoint

    kwargs.setdefault("name", f"ep-{uuid.uuid4().hex[:6]}")
    return MonitoredEndpoint.objects.create(url=f"https://{cn}", **kwargs)


@contextmanager
def _serving(pem: str):
    """Fake the network so that any HTTPS endpoint presents ``pem``."""
    with (
        patch("netbox_ssl.utils.url_cert_import.validate_https_url"),
        patch(
            "netbox_ssl.utils.url_cert_import.socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("203.0.113.10", 443))],
        ),
        patch("netbox_ssl.utils.url_cert_import.scrape_tls_certificate", return_value=pem),
    ):
        yield


def _poll(endpoint, pem: str):
    """Poll ``endpoint`` as if it presented ``pem``. Only the network is faked."""
    from netbox_ssl.utils.endpoint_monitor import poll_endpoint

    with _serving(pem):
        return poll_endpoint(endpoint, allowlist=[])


def _import(cn: str, pem: str):
    """Import ``pem`` the way URL import does, without any monitored endpoint."""
    from netbox_ssl.utils.url_cert_import import scrape_and_import

    with _serving(pem):
        return scrape_and_import(f"https://{cn}", cn, 443, allowlist=[]).certificate


def _cert(pem: str):
    """The Certificate row that ``pem`` was imported as."""
    from netbox_ssl.models import Certificate
    from netbox_ssl.utils.parser import CertificateParser

    parsed = CertificateParser.parse(pem)
    return Certificate.objects.get(serial_number=parsed.serial_number, issuer=parsed.issuer)


def _device(name: str):
    from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site

    uid = uuid.uuid4().hex[:8]
    site = Site.objects.create(name=f"site-{uid}", slug=f"site-{uid}")
    mfr = Manufacturer.objects.create(name=f"mfr-{uid}", slug=f"mfr-{uid}")
    dtype = DeviceType.objects.create(manufacturer=mfr, model=f"model-{uid}", slug=f"model-{uid}")
    role = DeviceRole.objects.create(name=f"role-{uid}", slug=f"role-{uid}")
    return Device.objects.create(name=f"{name}-{uid}", site=site, device_type=dtype, role=role)


def _assign(cert, obj, **kwargs):
    from django.contrib.contenttypes.models import ContentType

    from netbox_ssl.models import CertificateAssignment

    return CertificateAssignment.objects.create(
        certificate=cert,
        assigned_object_type=ContentType.objects.get_for_model(obj),
        assigned_object_id=obj.pk,
        **kwargs,
    )


def _rotate(cn: str | None = None):
    """Poll an endpoint twice: first the old certificate, then its renewal.

    Returns ``(endpoint, old_pem, new_pem, second_poll_result)``.
    """
    cn = cn or _cn()
    old_pem, new_pem = _old_pem(cn), _new_pem(cn)
    endpoint = _endpoint(cn)
    _poll(endpoint, old_pem)
    result = _poll(endpoint, new_pem)
    return endpoint, old_pem, new_pem, result


@pytest.mark.django_db
class TestRotationRunsRenewal:
    """The report in #184: after a rotation both certificates stayed Active."""

    def test_previous_certificate_is_replaced_by_its_successor(self):
        from netbox_ssl.models import CertificateStatusChoices

        _, old_pem, new_pem, _ = _rotate()

        old, new = _cert(old_pem), _cert(new_pem)
        assert old.status == CertificateStatusChoices.STATUS_REPLACED
        assert old.replaced_by == new

    def test_certificate_linked_to_the_endpoint_by_hand_is_replaced_too(self):
        """#184 as reported: import the certificate, then configure the endpoint for it."""
        from netbox_ssl.models import CertificateStatusChoices

        cn = _cn()
        old_pem, new_pem = _old_pem(cn), _new_pem(cn)
        old = _import(cn, old_pem)
        endpoint = _endpoint(cn, certificate=old)  # never polled: no history row yet

        _poll(endpoint, new_pem)

        old.refresh_from_db()
        assert old.status == CertificateStatusChoices.STATUS_REPLACED
        assert old.replaced_by == _cert(new_pem)

    def test_only_the_successor_stays_active(self):
        from netbox_ssl.models import Certificate, CertificateStatusChoices

        cn = _cn()
        _, _, new_pem, _ = _rotate(cn)

        active = Certificate.objects.filter(common_name=cn, status=CertificateStatusChoices.STATUS_ACTIVE)
        assert list(active) == [_cert(new_pem)]

    def test_assignments_are_copied_to_the_successor(self):
        cn = _cn()
        old_pem, new_pem = _old_pem(cn), _new_pem(cn)
        endpoint = _endpoint(cn)
        _poll(endpoint, old_pem)
        device = _device("web")
        _assign(_cert(old_pem), device, is_primary=True, notes="frontend listener")

        _poll(endpoint, new_pem)

        copied = _cert(new_pem).assignments.get()
        assert copied.assigned_object == device
        assert copied.is_primary is True
        assert copied.notes == "frontend listener"

    def test_previous_certificate_keeps_its_own_assignments(self):
        """Janus copies; the replaced certificate stays a faithful record."""
        cn = _cn()
        old_pem, new_pem = _old_pem(cn), _new_pem(cn)
        endpoint = _endpoint(cn)
        _poll(endpoint, old_pem)
        _assign(_cert(old_pem), _device("web"))

        _poll(endpoint, new_pem)

        assert _cert(old_pem).assignments.count() == 1

    def test_an_assignment_the_successor_already_has_is_not_duplicated(self, caplog):
        cn = _cn()
        old_pem, new_pem = _old_pem(cn), _new_pem(cn)
        endpoint, other = _endpoint(cn), _endpoint(cn)
        _poll(endpoint, old_pem)
        _poll(other, new_pem)  # the successor is already in the inventory...
        device = _device("web")
        _assign(_cert(old_pem), device)
        _assign(_cert(new_pem), device)  # ...and already assigned to the device

        with caplog.at_level(logging.WARNING, logger="netbox_ssl.renewal"):
            _poll(endpoint, new_pem)

        assert _cert(new_pem).assignments.count() == 1
        assert _cert(old_pem).status == "replaced"
        assert caplog.records == []  # an everyday situation, not something to warn about

    def test_private_key_location_and_renewal_note_carry_over(self):
        cn = _cn()
        old_pem, new_pem = _old_pem(cn), _new_pem(cn)
        endpoint = _endpoint(cn)
        _poll(endpoint, old_pem)
        old = _cert(old_pem)
        old.private_key_location = "vault://pki/shop"
        old.renewal_note = "certbot renew --cert-name shop"
        old.save()

        _poll(endpoint, new_pem)

        new = _cert(new_pem)
        assert new.private_key_location == "vault://pki/shop"
        assert new.renewal_note == "certbot renew --cert-name shop"

    def test_acme_settings_carry_over(self):
        cn = _cn()
        old_pem, new_pem = _old_pem(cn), _new_pem(cn)
        endpoint = _endpoint(cn)
        _poll(endpoint, old_pem)
        old = _cert(old_pem)
        old.is_acme = True
        old.acme_provider = "letsencrypt"
        old.acme_account_email = "pki@example.com"
        old.acme_challenge_type = "dns-01"
        old.acme_server_url = "https://acme-v02.api.letsencrypt.org/directory"
        old.acme_auto_renewal = True
        old.acme_renewal_days = 20
        old.save()

        _poll(endpoint, new_pem)

        new = _cert(new_pem)
        assert new.is_acme is True
        assert new.acme_provider == "letsencrypt"
        assert new.acme_account_email == "pki@example.com"
        assert new.acme_challenge_type == "dns-01"
        assert new.acme_server_url == "https://acme-v02.api.letsencrypt.org/directory"
        assert new.acme_auto_renewal is True
        assert new.acme_renewal_days == 20

    def test_tenant_carries_over_when_the_endpoint_has_none(self):
        from tenancy.models import Tenant

        cn = _cn()
        old_pem, new_pem = _old_pem(cn), _new_pem(cn)
        endpoint = _endpoint(cn)
        _poll(endpoint, old_pem)
        uid = uuid.uuid4().hex[:8]
        tenant = Tenant.objects.create(name=f"tenant-{uid}", slug=f"tenant-{uid}")
        old = _cert(old_pem)
        old.tenant = tenant
        old.save()

        _poll(endpoint, new_pem)

        assert _cert(new_pem).tenant == tenant

    def test_metadata_already_on_the_successor_is_not_overwritten(self):
        cn = _cn()
        old_pem, new_pem = _old_pem(cn), _new_pem(cn)
        endpoint, other = _endpoint(cn), _endpoint(cn)
        _poll(endpoint, old_pem)
        _poll(other, new_pem)  # successor already known and already documented
        old, new = _cert(old_pem), _cert(new_pem)
        old.private_key_location = "vault://pki/old"
        old.save()
        new.private_key_location = "vault://pki/new"
        new.save()

        _poll(endpoint, new_pem)

        assert _cert(new_pem).private_key_location == "vault://pki/new"

    def test_successor_gets_a_renewed_lifecycle_event_linking_the_predecessor(self):
        from netbox_ssl.models import CertificateLifecycleEvent, LifecycleEventTypeChoices

        _, old_pem, new_pem, _ = _rotate()

        event = CertificateLifecycleEvent.objects.get(
            certificate=_cert(new_pem), event_type=LifecycleEventTypeChoices.EVENT_RENEWED
        )
        assert event.related_certificate == _cert(old_pem)

    def test_poll_result_names_the_replaced_certificate(self):
        _, old_pem, _, result = _rotate()

        assert result.replaced_certificate_ids == (_cert(old_pem).pk,)

    def test_poll_result_reports_the_certificate_renewed_event(self):
        from netbox_ssl.utils.events import EVENT_CERTIFICATE_RENEWED

        _, _, _, result = _rotate()

        assert EVENT_CERTIFICATE_RENEWED in result.events_fired


@pytest.mark.django_db
class TestRotationGuards:
    """Replaced certificates drop out of expiry alerting, so never guess."""

    def test_certificate_another_endpoint_still_serves_stays_active(self):
        """One node of two has rotated: the old certificate is still in service."""
        from netbox_ssl.models import CertificateStatusChoices

        cn = _cn()
        old_pem, new_pem = _old_pem(cn), _new_pem(cn)
        first, second = _endpoint(cn), _endpoint(cn)
        _poll(first, old_pem)
        _poll(second, old_pem)

        _poll(first, new_pem)

        assert _cert(old_pem).status == CertificateStatusChoices.STATUS_ACTIVE

    def test_shared_certificate_is_replaced_once_the_last_endpoint_rotates(self):
        from netbox_ssl.models import CertificateStatusChoices

        cn = _cn()
        old_pem, new_pem = _old_pem(cn), _new_pem(cn)
        first, second = _endpoint(cn), _endpoint(cn)
        _poll(first, old_pem)
        _poll(second, old_pem)
        _poll(first, new_pem)

        _poll(second, new_pem)

        old = _cert(old_pem)
        assert old.status == CertificateStatusChoices.STATUS_REPLACED
        assert old.replaced_by == _cert(new_pem)

    def test_falling_back_to_an_older_certificate_does_not_replace_the_newer_one(self):
        """A rollback, or two nodes behind one name, is not a renewal."""
        from netbox_ssl.models import CertificateStatusChoices

        cn = _cn()
        old_pem, new_pem = _old_pem(cn), _new_pem(cn)
        endpoint = _endpoint(cn)
        _poll(endpoint, new_pem)

        _poll(endpoint, old_pem)

        assert _cert(new_pem).status == CertificateStatusChoices.STATUS_ACTIVE
        assert _cert(new_pem).replaced_by is None

    def test_certificate_for_different_names_does_not_replace_the_previous_one(self):
        """The host now answers with someone else's certificate: drift, not renewal."""
        from netbox_ssl.models import CertificateStatusChoices

        cn = _cn()
        old_pem, stranger_pem = _old_pem(cn), _new_pem(_cn())
        endpoint = _endpoint(cn)
        _poll(endpoint, old_pem)

        _poll(endpoint, stranger_pem)

        assert _cert(old_pem).status == CertificateStatusChoices.STATUS_ACTIVE
        assert _cert(old_pem).replaced_by is None

    def test_successor_matching_on_a_san_only_still_replaces(self):
        """Renewals may change the CN; a shared SAN is the same logical certificate."""
        from netbox_ssl.models import CertificateStatusChoices

        cn, other_cn = _cn(), _cn()
        old_pem = _old_pem(cn, sans=[cn, f"www.{cn}"])
        new_pem = _new_pem(other_cn, sans=[other_cn, f"www.{cn}"])
        endpoint = _endpoint(cn)
        _poll(endpoint, old_pem)

        _poll(endpoint, new_pem)

        assert _cert(old_pem).status == CertificateStatusChoices.STATUS_REPLACED

    def test_revoked_previous_certificate_keeps_its_status(self):
        from netbox_ssl.models import CertificateStatusChoices

        cn = _cn()
        old_pem, new_pem = _old_pem(cn), _new_pem(cn)
        endpoint = _endpoint(cn)
        _poll(endpoint, old_pem)
        old = _cert(old_pem)
        old.status = CertificateStatusChoices.STATUS_REVOKED
        old.save()

        _poll(endpoint, new_pem)

        assert _cert(old_pem).status == CertificateStatusChoices.STATUS_REVOKED

    def test_revoked_successor_does_not_replace_its_predecessor(self):
        """A certificate somebody revoked is no successor, even while it is served."""
        from netbox_ssl.models import CertificateStatusChoices

        cn = _cn()
        old_pem, new_pem = _old_pem(cn), _new_pem(cn)
        endpoint, other = _endpoint(cn), _endpoint(cn)
        _poll(endpoint, old_pem)
        _poll(other, new_pem)
        new = _cert(new_pem)
        new.status = CertificateStatusChoices.STATUS_REVOKED
        new.save()

        _poll(endpoint, new_pem)

        assert _cert(old_pem).status == CertificateStatusChoices.STATUS_ACTIVE

    def test_assignment_crossing_a_tenant_boundary_is_skipped_and_the_renewal_completes(self):
        from tenancy.models import Tenant

        from netbox_ssl.models import CertificateStatusChoices

        uid = uuid.uuid4().hex[:8]
        cert_tenant = Tenant.objects.create(name=f"cert-{uid}", slug=f"cert-{uid}")
        device_tenant = Tenant.objects.create(name=f"device-{uid}", slug=f"device-{uid}")
        cn = _cn()
        old_pem, new_pem = _old_pem(cn), _new_pem(cn)
        endpoint = _endpoint(cn)
        _poll(endpoint, old_pem)
        device = _device("web")
        device.tenant = device_tenant
        device.save()
        _assign(_cert(old_pem), device)  # allowed: the old certificate has no tenant
        endpoint.tenant = cert_tenant  # ...but its successor is imported into one
        endpoint.save()

        _poll(endpoint, new_pem)

        assert _cert(new_pem).tenant == cert_tenant
        assert _cert(new_pem).assignments.count() == 0
        assert _cert(old_pem).status == CertificateStatusChoices.STATUS_REPLACED

    def test_poll_still_succeeds_when_the_renewal_itself_fails(self):
        """One broken renewal must not abort the endpoint, or the whole script run."""
        from netbox_ssl.models import MonitoredEndpointStatusChoices

        cn = _cn()
        old_pem, new_pem = _old_pem(cn), _new_pem(cn)
        endpoint = _endpoint(cn)
        _poll(endpoint, old_pem)

        with patch(
            "netbox_ssl.utils.endpoint_monitor.supersede_certificate",
            side_effect=RuntimeError("boom"),
        ):
            result = _poll(endpoint, new_pem)

        endpoint.refresh_from_db()
        assert result.status == MonitoredEndpointStatusChoices.STATUS_OK
        assert endpoint.certificate == _cert(new_pem)
        assert result.replaced_certificate_ids == ()


@pytest.mark.django_db
class TestMissedRotationsAreHealed:
    """Installations that rotated on v1.3.0–v1.4.0 already hold stale Active rows."""

    def test_next_poll_replaces_a_predecessor_left_active_by_an_older_version(self):
        from django.utils import timezone

        from netbox_ssl.models import CertificateStatusChoices, MonitoredEndpointCertificate

        cn = _cn()
        old_pem, new_pem = _old_pem(cn), _new_pem(cn)
        endpoint = _endpoint(cn)
        _poll(endpoint, old_pem)

        # Reproduce exactly what v1.4.0 left behind after a rotation: the
        # successor imported and linked, a history row for it, and the
        # predecessor untouched.
        new = _import(cn, new_pem)
        now = timezone.now()
        endpoint.certificate = new
        endpoint.save()
        MonitoredEndpointCertificate.objects.create(endpoint=endpoint, certificate=new, first_seen=now, last_seen=now)
        assert _cert(old_pem).status == CertificateStatusChoices.STATUS_ACTIVE  # the bug, as shipped

        result = _poll(endpoint, new_pem)  # same certificate again: no rotation this time

        assert result.rotated is False
        old = _cert(old_pem)
        assert old.status == CertificateStatusChoices.STATUS_REPLACED
        assert old.replaced_by == new


class TestCertificateNames:
    """``shares_a_name`` decides whether two certificates are the same logical one."""

    @staticmethod
    def _certificate(common_name: str, sans: list[str]):
        from types import SimpleNamespace

        return SimpleNamespace(common_name=common_name, sans=sans)

    def test_names_are_the_common_name_plus_the_untyped_san_values(self):
        from netbox_ssl.utils.renewal import certificate_names

        certificate = self._certificate("Shop.Example.com", ["DNS:www.example.com", "IP:2001:db8::1"])

        assert certificate_names(certificate) == {"shop.example.com", "www.example.com", "2001:db8::1"}

    def test_two_certificates_without_a_common_name_do_not_match_on_the_empty_name(self):
        from netbox_ssl.utils.renewal import shares_a_name

        first = self._certificate("", ["DNS:a.example.com"])
        second = self._certificate("", ["DNS:b.example.com"])

        assert shares_a_name(first, second) is False
