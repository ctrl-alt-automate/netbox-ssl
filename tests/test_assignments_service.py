"""Unit tests for the bulk certificate-assignment service."""

import uuid

import pytest
from django.contrib.contenttypes.models import ContentType


@pytest.mark.django_db
class TestAssignCertificateToTargets:
    def _make_cert(self, suffix: str = ""):
        from netbox_ssl.models import Certificate

        # Unique serial and fingerprint per invocation to avoid UniqueConstraint violations.
        # Fingerprint format: 32 uppercase hex pairs colon-separated = exactly 95 chars.
        uid_int = int(uuid.uuid4().hex[:8], 16)  # first 32 bits as int
        pairs = [f"{(uid_int >> (i * 8)) & 0xFF:02X}" for i in range(4)]
        # Pad to 32 pairs using fixed values for the remaining 28 bytes
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

    def _device(self, name: str):
        from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site

        # Unique slugs per invocation
        uid = uuid.uuid4().hex[:8]
        site = Site.objects.create(name=f"site-{name}-{uid}", slug=f"site-{name}-{uid}")
        mfr = Manufacturer.objects.create(name=f"mfr-{name}-{uid}", slug=f"mfr-{name}-{uid}")
        dtype = DeviceType.objects.create(
            manufacturer=mfr,
            model=f"model-{name}-{uid}",
            slug=f"model-{name}-{uid}",
        )
        role = DeviceRole.objects.create(name=f"role-{name}-{uid}", slug=f"role-{name}-{uid}")
        return Device.objects.create(name=name, site=site, device_type=dtype, role=role)

    def test_creates_assignments_for_each_target(self):
        from netbox_ssl.models import CertificateAssignment
        from netbox_ssl.utils.assignments import assign_certificate_to_targets

        cert = self._make_cert()
        d1, d2 = self._device("web01"), self._device("web02")
        ct = ContentType.objects.get_for_model(d1)

        result = assign_certificate_to_targets(cert, [(ct, d1.pk), (ct, d2.pk)])

        assert result.created == 2
        assert result.skipped == 0
        assert CertificateAssignment.objects.filter(certificate=cert).count() == 2

    def test_skips_already_assigned_targets(self):
        from netbox_ssl.utils.assignments import assign_certificate_to_targets

        cert = self._make_cert()
        d1 = self._device("web01")
        ct = ContentType.objects.get_for_model(d1)

        assign_certificate_to_targets(cert, [(ct, d1.pk)])
        result = assign_certificate_to_targets(cert, [(ct, d1.pk)])

        assert result.created == 0
        assert result.skipped == 1
        assert result.skipped_targets == (f"device:{d1.pk}",)

    def test_is_primary_propagates(self):
        from netbox_ssl.models import CertificateAssignment
        from netbox_ssl.utils.assignments import assign_certificate_to_targets

        cert = self._make_cert()
        d1 = self._device("web01")
        ct = ContentType.objects.get_for_model(d1)

        assign_certificate_to_targets(cert, [(ct, d1.pk)], is_primary=True)

        assert CertificateAssignment.objects.get(certificate=cert).is_primary is True

    def test_is_primary_defaults_to_false(self):
        from netbox_ssl.models import CertificateAssignment
        from netbox_ssl.utils.assignments import assign_certificate_to_targets

        cert = self._make_cert()
        d1 = self._device("web01")
        ct = ContentType.objects.get_for_model(d1)

        assign_certificate_to_targets(cert, [(ct, d1.pk)])

        assert CertificateAssignment.objects.get(certificate=cert).is_primary is False

    def test_empty_targets_raises(self):
        from netbox_ssl.utils.assignments import AssignmentError, assign_certificate_to_targets

        cert = self._make_cert()
        with pytest.raises(AssignmentError):
            assign_certificate_to_targets(cert, [])

    def test_missing_object_raises(self):
        from netbox_ssl.utils.assignments import AssignmentError, assign_certificate_to_targets

        cert = self._make_cert()
        d1 = self._device("web01")
        ct = ContentType.objects.get_for_model(d1)
        with pytest.raises(AssignmentError):
            assign_certificate_to_targets(cert, [(ct, d1.pk + 9999)])

    def test_disallowed_content_type_raises(self):
        from netbox_ssl.models import Certificate
        from netbox_ssl.utils.assignments import AssignmentError, assign_certificate_to_targets

        cert = self._make_cert()
        bad_ct = ContentType.objects.get_for_model(Certificate)
        with pytest.raises(AssignmentError):
            assign_certificate_to_targets(cert, [(bad_ct, cert.pk)])
