"""Tests for the cert-centric bulk-assign form and view."""

import pytest


@pytest.mark.django_db
class TestCertificateBulkAssignForm:
    def test_empty_selection_is_invalid(self):
        from netbox_ssl.forms import CertificateBulkAssignForm

        form = CertificateBulkAssignForm(data={})
        assert not form.is_valid()
        assert "Select at least one" in str(form.errors)


@pytest.mark.django_db
class TestCertificateAssignTargetsView:
    def _make_cert(self):
        import uuid

        from netbox_ssl.models import Certificate

        uid_int = int(uuid.uuid4().hex[:8], 16)
        pairs = [f"{(uid_int >> (i * 8)) & 0xFF:02X}" for i in range(4)]
        tail = [f"{i:02X}" for i in range(28)]
        fp = ":".join(pairs + tail)
        serial = f"01:AA:{uuid.uuid4().hex[:8].upper()}"
        return Certificate.objects.create(
            common_name="*.example.com",
            serial_number=serial,
            issuer="Test CA",
            fingerprint_sha256=fp,
            algorithm="rsa",
            valid_from="2026-01-01T00:00:00Z",
            valid_to="2027-01-01T00:00:00Z",
        )

    def test_get_renders_form(self, client, django_user_model):
        user = django_user_model.objects.create_user("viewer", password="x", is_superuser=True)
        client.force_login(user)
        cert = self._make_cert()
        url = f"/plugins/ssl/certificates/{cert.pk}/assign-targets/"
        resp = client.get(url)
        assert resp.status_code == 200
        assert b"Assign certificate to objects" in resp.content

    def test_post_creates_assignment_and_redirects(self, client, django_user_model):
        import uuid

        from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site

        from netbox_ssl.models import CertificateAssignment

        user = django_user_model.objects.create_user("admin2", password="x", is_superuser=True)
        client.force_login(user)
        cert = self._make_cert()
        uid = uuid.uuid4().hex[:8]
        site = Site.objects.create(name=f"s1-{uid}", slug=f"s1-{uid}")
        mfr = Manufacturer.objects.create(name=f"m1-{uid}", slug=f"m1-{uid}")
        dtype = DeviceType.objects.create(manufacturer=mfr, model=f"dt1-{uid}", slug=f"dt1-{uid}")
        role = DeviceRole.objects.create(name=f"r1-{uid}", slug=f"r1-{uid}")
        device = Device.objects.create(name=f"web01-{uid}", site=site, device_type=dtype, role=role)

        url = f"/plugins/ssl/certificates/{cert.pk}/assign-targets/"
        resp = client.post(url, {"devices": [device.pk]})
        assert resp.status_code == 302
        assert CertificateAssignment.objects.filter(certificate=cert).count() == 1
