"""
Unit tests for bulk operations serializers.

Tests the BulkStatusUpdateSerializer and BulkAssignSerializer field
definitions and class structure without requiring a running NetBox instance
or djangorestframework installed.
"""

import importlib.util
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Mock Django/NetBox/DRF before importing plugin code
# ---------------------------------------------------------------------------
try:
    _spec = importlib.util.find_spec("netbox")
    _NETBOX_AVAILABLE = _spec is not None and _spec.origin is not None
    if _NETBOX_AVAILABLE:
        # Verify Django settings are actually configured (not just importable)
        from django.conf import settings
        _ = settings.USE_I18N  # noqa: F841
except (ValueError, ModuleNotFoundError, Exception):
    _NETBOX_AVAILABLE = False


def _load_serializer_classes() -> tuple:
    """Load the bulk serializer classes from certificates.py.

    In a non-NetBox environment (no DRF, no Django), we exec the module
    source with injected fake base classes so the serializer class
    definitions can be inspected without the full import chain.
    """
    if _NETBOX_AVAILABLE:
        from netbox_ssl.api.serializers.certificates import (
            BulkAssignSerializer,
            BulkStatusUpdateSerializer,
        )

        return BulkStatusUpdateSerializer, BulkAssignSerializer

    # --- Fake DRF field classes ---

    class _FakeSerializer:
        """Minimal Serializer stand-in for class definition."""

        def __init_subclass__(cls, **kwargs):
            super().__init_subclass__(**kwargs)

    class _FakeField:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    class _FakeListField(_FakeField):
        pass

    class _FakeChoiceField(_FakeField):
        pass

    class _FakeCharField(_FakeField):
        pass

    class _FakeIntegerField(_FakeField):
        pass

    class _FakeBooleanField(_FakeField):
        pass

    class _FakeHyperlinkedIdentityField(_FakeField):
        pass

    class _FakeSerializerMethodField(_FakeField):
        pass

    class _FakePrimaryKeyRelatedField(_FakeField):
        pass

    class _FakeValidationError(Exception):
        pass

    class _FakeNetBoxModelSerializer(_FakeSerializer):
        class Meta:
            pass

        def __init__(self, *args, **kwargs):
            pass

    class _FakeStatusChoices:
        STATUS_ACTIVE = "active"
        STATUS_EXPIRED = "expired"
        STATUS_REPLACED = "replaced"
        STATUS_REVOKED = "revoked"
        STATUS_PENDING = "pending"

    # Build a fake serializers module for the `from rest_framework import serializers` line
    rf_serializers_mod = ModuleType("rest_framework.serializers")
    rf_serializers_mod.Serializer = _FakeSerializer
    rf_serializers_mod.ListField = _FakeListField
    rf_serializers_mod.ChoiceField = _FakeChoiceField
    rf_serializers_mod.CharField = _FakeCharField
    rf_serializers_mod.IntegerField = _FakeIntegerField
    rf_serializers_mod.BooleanField = _FakeBooleanField
    rf_serializers_mod.HyperlinkedIdentityField = _FakeHyperlinkedIdentityField
    rf_serializers_mod.SerializerMethodField = _FakeSerializerMethodField
    rf_serializers_mod.PrimaryKeyRelatedField = _FakePrimaryKeyRelatedField
    rf_serializers_mod.ValidationError = _FakeValidationError

    # Prepare namespace with all imports pre-resolved
    namespace: dict = {
        "__name__": "netbox_ssl.api.serializers.certificates",
        "__package__": "netbox_ssl.api.serializers",
        "NetBoxModelSerializer": _FakeNetBoxModelSerializer,
        "serializers": rf_serializers_mod,
        "TenantSerializer": type("TenantSerializer", (_FakeNetBoxModelSerializer,), {}),
        "Tenant": MagicMock(),
        "Certificate": MagicMock(),
        "CertificateStatusChoices": _FakeStatusChoices,
        "CertificateParseError": Exception,
        "CertificateParser": MagicMock(),
        "detect_issuing_ca": MagicMock(),
        "CertificateAuthoritySerializer": type("CertificateAuthoritySerializer", (_FakeNetBoxModelSerializer,), {}),
        "ExternalSourceSerializer": type("ExternalSourceSerializer", (_FakeNetBoxModelSerializer,), {}),
    }

    # Read the source and strip import lines so our injected names are used
    source_path = Path(__file__).parent.parent / "netbox_ssl" / "api" / "serializers" / "certificates.py"
    if not source_path.exists():
        # Docker CI: tests at /tmp/plugin_tests/, plugin at /opt/netbox/netbox/netbox_ssl/
        source_path = Path("/opt/netbox/netbox/netbox_ssl/api/serializers/certificates.py")
    source = source_path.read_text()

    lines = source.split("\n")
    filtered: list[str] = []
    in_import = False
    for line in lines:
        stripped = line.strip()
        # Detect start of import block
        if stripped.startswith("from ") or stripped.startswith("import "):
            in_import = True
            # Single-line import
            if "(" not in stripped or ")" in stripped:
                in_import = False
            continue
        # Inside multi-line import
        if in_import:
            if ")" in stripped:
                in_import = False
            continue
        filtered.append(line)

    clean_source = "\n".join(filtered)
    exec(compile(clean_source, str(source_path), "exec"), namespace)  # noqa: S102

    return namespace["BulkStatusUpdateSerializer"], namespace["BulkAssignSerializer"]


BulkStatusUpdateSerializer, BulkAssignSerializer = _load_serializer_classes()


# ---------------------------------------------------------------------------
# Tests: BulkStatusUpdateSerializer
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestBulkStatusUpdateSerializer:
    """Tests for BulkStatusUpdateSerializer field definitions."""

    def test_has_ids_field(self) -> None:
        """Serializer defines an 'ids' field."""
        assert hasattr(BulkStatusUpdateSerializer, "ids")

    def test_ids_field_is_list_field(self) -> None:
        """The 'ids' field is a ListField."""
        field = BulkStatusUpdateSerializer.ids
        assert "ListField" in type(field).__name__

    def test_ids_field_has_child_integer(self) -> None:
        """The 'ids' ListField child is an IntegerField."""
        field = BulkStatusUpdateSerializer.ids
        child = field.kwargs.get("child")
        assert child is not None
        assert "IntegerField" in type(child).__name__

    def test_ids_field_disallows_empty(self) -> None:
        """The 'ids' field does not allow empty lists."""
        field = BulkStatusUpdateSerializer.ids
        assert field.kwargs.get("allow_empty") is False

    def test_has_status_field(self) -> None:
        """Serializer defines a 'status' field."""
        assert hasattr(BulkStatusUpdateSerializer, "status")

    def test_status_field_is_choice_field(self) -> None:
        """The 'status' field is a ChoiceField."""
        field = BulkStatusUpdateSerializer.status
        assert "ChoiceField" in type(field).__name__

    def test_status_field_has_choices(self) -> None:
        """The 'status' ChoiceField has choices configured."""
        field = BulkStatusUpdateSerializer.status
        assert "choices" in field.kwargs

    def test_status_field_choices_reference_status_choices(self) -> None:
        """The 'status' ChoiceField references CertificateStatusChoices."""
        field = BulkStatusUpdateSerializer.status
        choices = field.kwargs["choices"]
        # Should reference our fake status choices class
        assert hasattr(choices, "STATUS_ACTIVE")

    def test_ids_field_has_help_text(self) -> None:
        """The 'ids' field has help_text."""
        field = BulkStatusUpdateSerializer.ids
        assert field.kwargs.get("help_text")

    def test_status_field_has_help_text(self) -> None:
        """The 'status' field has help_text."""
        field = BulkStatusUpdateSerializer.status
        assert field.kwargs.get("help_text")

    def test_class_has_both_required_fields(self) -> None:
        """BulkStatusUpdateSerializer has both 'ids' and 'status' fields."""
        assert hasattr(BulkStatusUpdateSerializer, "ids")
        assert hasattr(BulkStatusUpdateSerializer, "status")


# ---------------------------------------------------------------------------
# Tests: BulkAssignSerializer
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestBulkAssignSerializer:
    """Tests for BulkAssignSerializer field definitions."""

    def test_has_certificate_ids_field(self) -> None:
        """Serializer defines a 'certificate_ids' field."""
        assert hasattr(BulkAssignSerializer, "certificate_ids")

    def test_certificate_ids_is_list_field(self) -> None:
        """The 'certificate_ids' field is a ListField."""
        field = BulkAssignSerializer.certificate_ids
        assert "ListField" in type(field).__name__

    def test_certificate_ids_has_child_integer(self) -> None:
        """The 'certificate_ids' ListField child is an IntegerField."""
        field = BulkAssignSerializer.certificate_ids
        child = field.kwargs.get("child")
        assert child is not None
        assert "IntegerField" in type(child).__name__

    def test_certificate_ids_disallows_empty(self) -> None:
        """The 'certificate_ids' field does not allow empty lists."""
        field = BulkAssignSerializer.certificate_ids
        assert field.kwargs.get("allow_empty") is False

    def test_has_assigned_object_type_field(self) -> None:
        """Serializer defines an 'assigned_object_type' field."""
        assert hasattr(BulkAssignSerializer, "assigned_object_type")

    def test_assigned_object_type_is_char_field(self) -> None:
        """The 'assigned_object_type' field is a CharField."""
        field = BulkAssignSerializer.assigned_object_type
        assert "CharField" in type(field).__name__

    def test_has_assigned_object_id_field(self) -> None:
        """Serializer defines an 'assigned_object_id' field."""
        assert hasattr(BulkAssignSerializer, "assigned_object_id")

    def test_assigned_object_id_is_integer_field(self) -> None:
        """The 'assigned_object_id' field is an IntegerField."""
        field = BulkAssignSerializer.assigned_object_id
        assert "IntegerField" in type(field).__name__

    def test_has_is_primary_field(self) -> None:
        """Serializer defines an 'is_primary' field."""
        assert hasattr(BulkAssignSerializer, "is_primary")

    def test_is_primary_is_boolean_field(self) -> None:
        """The 'is_primary' field is a BooleanField."""
        field = BulkAssignSerializer.is_primary
        assert "BooleanField" in type(field).__name__

    def test_is_primary_defaults_to_true(self) -> None:
        """The 'is_primary' field defaults to True."""
        field = BulkAssignSerializer.is_primary
        assert field.kwargs.get("default") is True

    def test_certificate_ids_has_help_text(self) -> None:
        """The 'certificate_ids' field has help_text."""
        field = BulkAssignSerializer.certificate_ids
        assert field.kwargs.get("help_text")

    def test_assigned_object_type_has_help_text(self) -> None:
        """The 'assigned_object_type' field has help_text."""
        field = BulkAssignSerializer.assigned_object_type
        assert field.kwargs.get("help_text")

    def test_assigned_object_id_has_help_text(self) -> None:
        """The 'assigned_object_id' field has help_text."""
        field = BulkAssignSerializer.assigned_object_id
        assert field.kwargs.get("help_text")

    def test_is_primary_has_help_text(self) -> None:
        """The 'is_primary' field has help_text."""
        field = BulkAssignSerializer.is_primary
        assert field.kwargs.get("help_text")

    def test_has_all_four_expected_fields(self) -> None:
        """BulkAssignSerializer has all four expected fields."""
        expected_fields = [
            "certificate_ids",
            "assigned_object_type",
            "assigned_object_id",
            "is_primary",
        ]
        for field_name in expected_fields:
            assert hasattr(BulkAssignSerializer, field_name), f"Missing field: {field_name}"

    def test_assigned_object_type_help_text_mentions_content_types(self) -> None:
        """The help_text for assigned_object_type mentions supported types."""
        field = BulkAssignSerializer.assigned_object_type
        help_text = field.kwargs.get("help_text", "")
        assert "dcim.device" in help_text or "content type" in help_text.lower()
