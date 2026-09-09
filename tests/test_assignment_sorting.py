"""Tests for sorting and searching assignments by their assigned object (#167).

``CertificateAssignment.assigned_object`` is a GenericForeignKey. It spans the
device, virtual machine and service tables, so it cannot appear in
``order_by()`` or in a filter -- the table column was therefore declared
``orderable=False`` and the search box ignored it. For a wildcard certificate
assigned to dozens of hosts, the list was effectively unnavigable.

``CertificateAssignmentQuerySet.with_assigned_object_name()`` annotates the
target's ``name`` with a correlated subquery chosen by content type, which makes
the column sortable and searchable without denormalising anything (and so
without any risk of the value going stale when an object is renamed).
"""

from __future__ import annotations

import uuid

import pytest

from .conftest import get_plugin_source_dir


def _read(relative: str) -> str:
    return (get_plugin_source_dir() / relative).read_text()


@pytest.mark.unit
class TestSortingIsWiredUp:
    """Source-level checks that run in the host lane, where NetBox is absent."""

    def test_column_is_no_longer_marked_unorderable(self):
        table = _read("tables/assignments.py")
        assert "orderable=False" not in table, "the Assigned To column is still unsortable"
        assert 'order_by="assigned_object_name"' in table

    def test_annotation_is_applied_where_the_column_is_rendered(self):
        """A sortable column is useless if the annotation is missing from the queryset."""
        assert "with_assigned_object_name()" in _read("views/assignments.py")
        assert "with_assigned_object_name()" in _read("api/views.py")

    def test_annotation_issues_no_query_while_being_built(self):
        """Keying off __model keeps the queryset lazy, so it is migrate-safe."""
        model_source = _read("models/assignments.py")
        assert 'assigned_object_type__model="device"' in model_source
        assert "ContentType.objects.filter(model__in=" not in model_source

    def test_custom_manager_preserves_restrict(self):
        """Overriding `objects` must not drop NetBox's object-permission filtering.

        NetBox's BaseModel sets ``objects = RestrictedQuerySet.as_manager()``.
        A custom manager built on a plain ``models.QuerySet`` silently removes
        ``.restrict(user, action)``, which every view and API endpoint uses to
        enforce object permissions -- a security regression with no error.
        """
        model_source = _read("models/assignments.py")
        assert "class CertificateAssignmentQuerySet(RestrictedQuerySet):" in model_source, (
            "the assignment queryset must subclass RestrictedQuerySet, or .restrict() is lost"
        )
        assert "class CertificateAssignmentQuerySet(models.QuerySet):" not in model_source

    def test_filterset_searches_the_assigned_object(self):
        filterset = _read("filtersets/assignments.py")
        assert "assigned_object_name__icontains" in filterset
        assert "filter_assigned_object_name" in filterset


@pytest.mark.django_db
class TestAssignedObjectNameAnnotation:
    """Behavioural tests -- these need the ORM, so they run in the container lane."""

    def _certificate(self):
        from datetime import timedelta

        from django.utils import timezone

        from netbox_ssl.models import Certificate

        return Certificate.objects.create(
            common_name=f"cert-{uuid.uuid4().hex[:6]}.example.com",
            serial_number=uuid.uuid4().hex,
            issuer="Test CA",
            valid_from=timezone.now(),
            valid_to=timezone.now() + timedelta(days=90),
        )

    def _device(self, name):
        from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site

        site, _ = Site.objects.get_or_create(name="Test Site", slug="test-site")
        manufacturer, _ = Manufacturer.objects.get_or_create(name="Test Mfr", slug="test-mfr")
        device_type, _ = DeviceType.objects.get_or_create(
            manufacturer=manufacturer, model="Test Model", slug="test-model"
        )
        role, _ = DeviceRole.objects.get_or_create(name="Test Role", slug="test-role")
        return Device.objects.create(name=name, site=site, device_type=device_type, role=role)

    def _assign(self, certificate, device):
        from django.contrib.contenttypes.models import ContentType

        from netbox_ssl.models import CertificateAssignment

        return CertificateAssignment.objects.create(
            certificate=certificate,
            assigned_object_type=ContentType.objects.get_for_model(device),
            assigned_object_id=device.pk,
        )

    def test_annotation_exposes_the_device_name(self):
        from netbox_ssl.models import CertificateAssignment

        certificate = self._certificate()
        device = self._device(f"web-{uuid.uuid4().hex[:6]}")
        assignment = self._assign(certificate, device)

        annotated = CertificateAssignment.objects.with_assigned_object_name().get(pk=assignment.pk)
        assert annotated.assigned_object_name == device.name

    def test_assignments_can_be_ordered_by_the_assigned_object(self):
        from netbox_ssl.models import CertificateAssignment

        certificate = self._certificate()
        suffix = uuid.uuid4().hex[:6]
        for name in (f"zulu-{suffix}", f"alpha-{suffix}", f"mike-{suffix}"):
            self._assign(certificate, self._device(name))

        ordered = (
            CertificateAssignment.objects.with_assigned_object_name()
            .filter(certificate=certificate)
            .order_by("assigned_object_name")
            .values_list("assigned_object_name", flat=True)
        )
        assert list(ordered) == sorted(ordered)

    def test_annotation_tracks_a_rename(self):
        """The value is resolved per query, so it cannot go stale."""
        from netbox_ssl.models import CertificateAssignment

        certificate = self._certificate()
        device = self._device(f"before-{uuid.uuid4().hex[:6]}")
        assignment = self._assign(certificate, device)

        device.name = f"after-{uuid.uuid4().hex[:6]}"
        device.save()

        annotated = CertificateAssignment.objects.with_assigned_object_name().get(pk=assignment.pk)
        assert annotated.assigned_object_name == device.name

    def test_search_matches_the_assigned_object_name(self):
        from netbox_ssl.filtersets import CertificateAssignmentFilterSet
        from netbox_ssl.models import CertificateAssignment

        certificate = self._certificate()
        needle = uuid.uuid4().hex[:8]
        self._assign(certificate, self._device(f"host-{needle}"))
        self._assign(certificate, self._device(f"other-{uuid.uuid4().hex[:6]}"))

        result = CertificateAssignmentFilterSet({"q": needle}, queryset=CertificateAssignment.objects.all()).qs
        assert result.count() == 1
        assert needle in result.first().assigned_object.name
