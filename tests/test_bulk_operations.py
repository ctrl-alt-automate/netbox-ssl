"""
Tests for the bulk-operations serializers (BulkStatusUpdateSerializer,
BulkAssignSerializer).

NOTE (test-hardening, v1.1.1): this file previously exec'd the serializer
source with hand-built *fake* DRF field classes and asserted on those fakes via
class-attribute access (``Serializer.field.kwargs``). That only ever exercised
the fakes — never the shipped serializers — and only "passed" in CI because an
unrelated ``sys.modules`` mock contamination forced the fake code path. It
therefore caught zero real bugs (false confidence).

It now tests the **real** DRF serializers via the real field API
(``serializer().fields``), so it actually validates the code that ships. This
requires a real NetBox/DRF environment and runs in the Docker integration job;
it skips elsewhere.
"""

import contextlib
import os
import sys
from pathlib import Path

import pytest

_root = Path(__file__).parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

import importlib.util

try:
    _spec = importlib.util.find_spec("netbox")
    NETBOX_AVAILABLE = _spec is not None and _spec.origin is not None
except (ValueError, ModuleNotFoundError):
    NETBOX_AVAILABLE = False

if NETBOX_AVAILABLE:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "netbox.settings")
    import django

    with contextlib.suppress(Exception):
        django.setup()

requires_netbox = pytest.mark.skipif(
    not NETBOX_AVAILABLE,
    reason="NetBox/DRF not available - run these tests inside the Docker container",
)


def _fields(serializer_cls):
    """Return the bound DRF fields (name -> Field) for a serializer class."""
    return serializer_cls().fields


@requires_netbox
class TestBulkStatusUpdateSerializer:
    """Field-level checks against the real BulkStatusUpdateSerializer."""

    def _fields(self):
        from netbox_ssl.api.serializers import BulkStatusUpdateSerializer

        return _fields(BulkStatusUpdateSerializer)

    def test_has_ids_and_status_fields(self):
        from rest_framework import serializers

        fields = self._fields()
        assert "ids" in fields
        assert "status" in fields
        assert isinstance(fields["ids"], serializers.ListField)
        assert isinstance(fields["status"], serializers.ChoiceField)

    def test_ids_is_integer_list_disallowing_empty(self):
        from rest_framework import serializers

        ids = self._fields()["ids"]
        assert isinstance(ids.child, serializers.IntegerField)
        assert ids.allow_empty is False
        assert ids.help_text

    def test_status_choices_match_certificate_status_choices(self):
        from netbox_ssl.models import CertificateStatusChoices

        status = self._fields()["status"]
        expected = {c[0] for c in CertificateStatusChoices.CHOICES}
        assert set(status.choices.keys()) == expected
        assert status.help_text


@requires_netbox
class TestBulkAssignSerializer:
    """Field-level checks against the real BulkAssignSerializer."""

    def _fields(self):
        from netbox_ssl.api.serializers import BulkAssignSerializer

        return _fields(BulkAssignSerializer)

    def test_has_all_four_expected_fields(self):
        fields = self._fields()
        assert set(fields) >= {"certificate_ids", "assigned_object_type", "assigned_object_id", "is_primary"}

    def test_certificate_ids_is_integer_list_disallowing_empty(self):
        from rest_framework import serializers

        cert_ids = self._fields()["certificate_ids"]
        assert isinstance(cert_ids, serializers.ListField)
        assert isinstance(cert_ids.child, serializers.IntegerField)
        assert cert_ids.allow_empty is False
        assert cert_ids.help_text

    def test_assigned_object_type_is_char_field(self):
        from rest_framework import serializers

        field = self._fields()["assigned_object_type"]
        assert isinstance(field, serializers.CharField)
        assert "content type" in (field.help_text or "").lower()

    def test_assigned_object_id_is_integer_field(self):
        from rest_framework import serializers

        field = self._fields()["assigned_object_id"]
        assert isinstance(field, serializers.IntegerField)
        assert field.help_text

    def test_is_primary_is_boolean_defaulting_true(self):
        from rest_framework import serializers

        field = self._fields()["is_primary"]
        assert isinstance(field, serializers.BooleanField)
        assert field.default is True
        assert field.help_text
