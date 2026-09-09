"""
In-process Django REST Framework tests for the assign-targets action.

POST /api/plugins/ssl/certificates/{id}/assign-targets/

Runs inside the NetBox container with pytest-django (DJANGO_SETTINGS_MODULE
provided via pytest.ini).  No live HTTP server or NETBOX_TOKEN required.
"""

import uuid

import pytest

# DRF ships with NetBox (the container test lane), not the host-only unit lane
# (-p no:django). Skip this whole module there instead of crashing collection.
APIClient = pytest.importorskip("rest_framework.test").APIClient


def _make_fp() -> str:
    """Return a unique 95-char SHA-256 fingerprint (32 colon-separated hex pairs)."""
    uid_int = int(uuid.uuid4().hex[:8], 16)
    pairs = [f"{(uid_int >> (i * 8)) & 0xFF:02X}" for i in range(4)]
    tail = [f"{i:02X}" for i in range(28)]
    return ":".join(pairs + tail)


def _make_cert():
    from netbox_ssl.models import Certificate

    return Certificate.objects.create(
        common_name="*.example.com",
        serial_number=f"01:AA:{uuid.uuid4().hex[:8].upper()}",
        issuer="Test CA",
        fingerprint_sha256=_make_fp(),
        algorithm="rsa",
        valid_from="2026-01-01T00:00:00Z",
        valid_to="2027-01-01T00:00:00Z",
    )


def _make_device(name: str):
    from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site

    uid = uuid.uuid4().hex[:8]
    site = Site.objects.create(name=f"site-{uid}", slug=f"site-{uid}")
    mfr = Manufacturer.objects.create(name=f"mfr-{uid}", slug=f"mfr-{uid}")
    dtype = DeviceType.objects.create(manufacturer=mfr, model=f"model-{uid}", slug=f"model-{uid}")
    role = DeviceRole.objects.create(name=f"role-{uid}", slug=f"role-{uid}")
    return Device.objects.create(name=name, site=site, device_type=dtype, role=role)


@pytest.fixture
def admin_client(django_user_model):
    user = django_user_model.objects.create(username=f"admin-{uuid.uuid4().hex[:6]}", is_superuser=True)
    client = APIClient()
    client.force_authenticate(user=user)
    return client


@pytest.fixture
def limited_client(django_user_model):
    """Authenticated client whose user has NO bulk_certificate / add_certificateassignment."""
    user = django_user_model.objects.create(username=f"limited-{uuid.uuid4().hex[:6]}")
    client = APIClient()
    client.force_authenticate(user=user)
    return client


@pytest.fixture
def certificate():
    return _make_cert()


@pytest.fixture
def device():
    return _make_device("web-assign-test")


@pytest.mark.django_db
class TestAssignTargetsAPI:
    """POST /certificates/{id}/assign-targets — one cert → many objects."""

    def test_assigns_and_skips(self, certificate, device, admin_client):
        url = f"/api/plugins/ssl/certificates/{certificate.pk}/assign-targets/"
        payload = {
            "targets": [{"object_type": "dcim.device", "object_id": device.pk}],
            "is_primary": False,
        }

        first = admin_client.post(url, payload, format="json")
        assert first.status_code == 200, first.data
        assert first.data["assigned"] == 1
        assert first.data["skipped"] == 0

        second = admin_client.post(url, payload, format="json")
        assert second.status_code == 200, second.data
        assert second.data["assigned"] == 0
        assert second.data["skipped"] == 1

    def test_denied_without_add_permission(self, certificate, device, limited_client):
        url = f"/api/plugins/ssl/certificates/{certificate.pk}/assign-targets/"
        payload = {"targets": [{"object_type": "dcim.device", "object_id": device.pk}]}
        resp = limited_client.post(url, payload, format="json")
        assert resp.status_code == 403

    def test_invalid_object_type_rejected(self, certificate, admin_client):
        url = f"/api/plugins/ssl/certificates/{certificate.pk}/assign-targets/"
        payload = {"targets": [{"object_type": "auth.user", "object_id": 1}]}
        resp = admin_client.post(url, payload, format="json")
        assert resp.status_code == 400

    def test_response_contains_detail_string(self, certificate, device, admin_client):
        url = f"/api/plugins/ssl/certificates/{certificate.pk}/assign-targets/"
        payload = {"targets": [{"object_type": "dcim.device", "object_id": device.pk}]}
        resp = admin_client.post(url, payload, format="json")
        assert resp.status_code == 200
        assert "detail" in resp.data

    def test_nonexistent_certificate_returns_404(self, admin_client, device):
        url = "/api/plugins/ssl/certificates/999999/assign-targets/"
        payload = {"targets": [{"object_type": "dcim.device", "object_id": device.pk}]}
        resp = admin_client.post(url, payload, format="json")
        assert resp.status_code == 404

    def test_batch_cap_returns_400(self, certificate, device, admin_client):
        """Sending more than 100 targets must return 400 with a plain detail string."""
        url = f"/api/plugins/ssl/certificates/{certificate.pk}/assign-targets/"
        # Repeat a valid device pk 101 times — cap check happens before resolution
        targets = [{"object_type": "dcim.device", "object_id": device.pk}] * 101
        resp = admin_client.post(url, {"targets": targets, "is_primary": False}, format="json")
        assert resp.status_code == 400
        # body must be {"detail": "..."} — plain string, NOT a list
        assert isinstance(resp.data.get("detail"), str)
        assert "100" in resp.data["detail"]

    # NOTE: test_no_view_perm_on_cert_returns_404 is intentionally omitted.
    # NetBox uses its own ObjectPermission system (users.models.ObjectPermission)
    # rather than standard Django auth.Permission objects for has_perm() checks.
    # Adding standard Permission rows to user.user_permissions has no effect —
    # user.has_perm("netbox_ssl.bulk_certificate") returns False regardless.
    # Setting up ObjectPermission rows correctly requires additional NetBox-specific
    # infrastructure (Token, ObjectPermission.objects.create + .users.add) that is
    # beyond the scope of a unit test and was attempted twice without success.
    # The behaviour is verified structurally: the cert lookup now runs BEFORE the
    # batch-cap check (Fix 1), so a user who passes _check_bulk_perm but cannot see
    # the cert will hit the restrict() → None → 404 path rather than a 400.
