"""
Unit tests for Certificate Lifecycle Tracking (Feature #49).

Tests the CertificateLifecycleEvent model, LifecycleEventTypeChoices,
and lifecycle event creation hooks in Certificate and CertificateAssignment
models without requiring a running NetBox instance.

All tests use source file inspection to verify code structure rather than
importing Django models (which require a full NetBox environment).
"""

from pathlib import Path

try:
    from conftest import get_plugin_source_dir
except ImportError:
    from tests.conftest import get_plugin_source_dir

import pytest

# ---------------------------------------------------------------------------
# Paths to source files
# ---------------------------------------------------------------------------
_MODELS_DIR = get_plugin_source_dir() /  "models"
_MIGRATIONS_DIR = get_plugin_source_dir() /  "migrations"
_LIFECYCLE_PATH = _MODELS_DIR / "lifecycle.py"
_CERTIFICATES_PATH = _MODELS_DIR / "certificates.py"
_ASSIGNMENTS_PATH = _MODELS_DIR / "assignments.py"
_INIT_PATH = _MODELS_DIR / "__init__.py"


def _read_source(path: Path) -> str:
    """Read source file content."""
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Tests: LifecycleEventTypeChoices
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestLifecycleEventTypeChoices:
    """Tests for LifecycleEventTypeChoices choice set via source inspection."""

    def test_has_all_expected_event_type_constants(self):
        """Test that all expected event type constants are defined."""
        source = _read_source(_LIFECYCLE_PATH)
        expected_constants = [
            "EVENT_IMPORTED",
            "EVENT_ISSUED",
            "EVENT_ACTIVATED",
            "EVENT_STATUS_CHANGED",
            "EVENT_RENEWED",
            "EVENT_REVOKED",
            "EVENT_ARCHIVED",
            "EVENT_ASSIGNMENT_ADDED",
            "EVENT_ASSIGNMENT_REMOVED",
        ]
        for const in expected_constants:
            assert const in source, f"Missing constant: {const}"

    def test_event_type_string_values(self):
        """Test that event type constants have correct string values."""
        source = _read_source(_LIFECYCLE_PATH)
        expected_values = {
            'EVENT_IMPORTED = "imported"',
            'EVENT_ISSUED = "issued"',
            'EVENT_ACTIVATED = "activated"',
            'EVENT_STATUS_CHANGED = "status_changed"',
            'EVENT_RENEWED = "renewed"',
            'EVENT_REVOKED = "revoked"',
            'EVENT_ARCHIVED = "archived"',
            'EVENT_ASSIGNMENT_ADDED = "assignment_added"',
            'EVENT_ASSIGNMENT_REMOVED = "assignment_removed"',
        }
        for val in expected_values:
            assert val in source, f"Missing value assignment: {val}"

    def test_choices_list_has_nine_entries(self):
        """Test that CHOICES list has 9 entries (one per event type)."""
        source = _read_source(_LIFECYCLE_PATH)
        # Count tuples in CHOICES list by looking for label strings
        labels = [
            '"Imported"',
            '"Issued"',
            '"Activated"',
            '"Status Changed"',
            '"Renewed"',
            '"Revoked"',
            '"Archived"',
            '"Assignment Added"',
            '"Assignment Removed"',
        ]
        for label in labels:
            assert label in source, f"Missing CHOICES label: {label}"

    def test_choices_have_colors(self):
        """Test that each CHOICES tuple has a color (third element)."""
        source = _read_source(_LIFECYCLE_PATH)
        colors = ['"blue"', '"green"', '"yellow"', '"cyan"', '"orange"', '"dark"', '"purple"', '"gray"']
        for color in colors:
            assert color in source, f"Missing color: {color}"

    def test_extends_choiceset(self):
        """Test that LifecycleEventTypeChoices extends ChoiceSet."""
        source = _read_source(_LIFECYCLE_PATH)
        assert "class LifecycleEventTypeChoices(ChoiceSet)" in source


# ---------------------------------------------------------------------------
# Tests: CertificateLifecycleEvent model source inspection
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCertificateLifecycleEventModel:
    """Tests for CertificateLifecycleEvent model definition via source inspection."""

    def test_model_extends_django_model(self):
        """Test that the model extends models.Model."""
        source = _read_source(_LIFECYCLE_PATH)
        assert "class CertificateLifecycleEvent(models.Model)" in source

    def test_model_has_certificate_foreignkey(self):
        """Test that the model has a certificate ForeignKey field."""
        source = _read_source(_LIFECYCLE_PATH)
        assert "certificate = models.ForeignKey" in source
        assert 'related_name="lifecycle_events"' in source
        assert "on_delete=models.CASCADE" in source

    def test_model_has_event_type_field(self):
        """Test that the model has an event_type CharField."""
        source = _read_source(_LIFECYCLE_PATH)
        assert "event_type = models.CharField" in source
        assert "max_length=30" in source

    def test_model_has_timestamp_field(self):
        """Test that the model has a timestamp DateTimeField with default."""
        source = _read_source(_LIFECYCLE_PATH)
        assert "timestamp = models.DateTimeField" in source
        assert "default=timezone.now" in source

    def test_model_has_description_field(self):
        """Test that the model has a description TextField."""
        source = _read_source(_LIFECYCLE_PATH)
        assert "description = models.TextField" in source

    def test_model_has_old_status_field(self):
        """Test that the model has an old_status CharField for status tracking."""
        source = _read_source(_LIFECYCLE_PATH)
        assert "old_status = models.CharField" in source

    def test_model_has_new_status_field(self):
        """Test that the model has a new_status CharField for status tracking."""
        source = _read_source(_LIFECYCLE_PATH)
        assert "new_status = models.CharField" in source

    def test_model_has_related_certificate_foreignkey(self):
        """Test that the model has a related_certificate ForeignKey."""
        source = _read_source(_LIFECYCLE_PATH)
        assert "related_certificate = models.ForeignKey" in source
        assert "on_delete=models.SET_NULL" in source
        assert 'related_name="related_lifecycle_events"' in source

    def test_model_has_actor_field(self):
        """Test that the model has an actor CharField."""
        source = _read_source(_LIFECYCLE_PATH)
        assert "actor = models.CharField" in source
        assert "max_length=150" in source

    def test_model_ordering_is_newest_first(self):
        """Test that model Meta ordering is by -timestamp (newest first)."""
        source = _read_source(_LIFECYCLE_PATH)
        assert '"-timestamp"' in source

    def test_model_has_composite_index(self):
        """Test that the model has a composite index on certificate + timestamp."""
        source = _read_source(_LIFECYCLE_PATH)
        assert "netbox_ssl_lifecycle_cert_ts" in source
        assert "models.Index" in source

    def test_model_has_str_method(self):
        """Test that the model has a __str__ method with event display."""
        source = _read_source(_LIFECYCLE_PATH)
        assert "def __str__(self)" in source
        assert "get_event_type_display" in source

    def test_all_fields_have_help_text(self):
        """Test that all model fields have help_text defined."""
        source = _read_source(_LIFECYCLE_PATH)
        # Each field definition should have help_text
        field_names = [
            "certificate",
            "event_type",
            "timestamp",
            "description",
            "old_status",
            "new_status",
            "related_certificate",
            "actor",
        ]
        # Count help_text occurrences - should be at least as many as fields
        help_text_count = source.count("help_text=")
        assert help_text_count >= len(field_names), (
            f"Expected at least {len(field_names)} help_text definitions, found {help_text_count}"
        )

    def test_model_has_type_annotation_on_str(self):
        """Test that __str__ has a return type annotation."""
        source = _read_source(_LIFECYCLE_PATH)
        assert "def __str__(self) -> str:" in source


# ---------------------------------------------------------------------------
# Tests: Certificate model lifecycle event hooks (source inspection)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCertificateSaveLifecycleHooks:
    """Tests for lifecycle event creation in Certificate.save() via source inspection."""

    def test_save_creates_lifecycle_event_on_status_change(self):
        """Test that Certificate.save() creates a lifecycle event for status transitions."""
        source = _read_source(_CERTIFICATES_PATH)
        assert "CertificateLifecycleEvent.objects.create" in source
        assert "EVENT_STATUS_CHANGED" in source

    def test_save_maps_revoked_status_to_revoked_event(self):
        """Test that revoked status maps to EVENT_REVOKED event type."""
        source = _read_source(_CERTIFICATES_PATH)
        assert "EVENT_REVOKED" in source
        assert '"revoked"' in source

    def test_save_maps_archived_status_to_archived_event(self):
        """Test that archived status maps to EVENT_ARCHIVED event type."""
        source = _read_source(_CERTIFICATES_PATH)
        assert "EVENT_ARCHIVED" in source
        assert '"archived"' in source

    def test_save_creates_imported_event_for_new_certificates(self):
        """Test that Certificate.save() creates an imported event for new certs."""
        source = _read_source(_CERTIFICATES_PATH)
        assert "EVENT_IMPORTED" in source
        assert "_original_status is None" in source

    def test_save_wraps_lifecycle_in_try_except(self):
        """Test that lifecycle event creation is wrapped in try/except."""
        source = _read_source(_CERTIFICATES_PATH)
        assert "Failed to create lifecycle event" in source

    def test_save_uses_lazy_import(self):
        """Test that lifecycle models are imported lazily inside save()."""
        source = _read_source(_CERTIFICATES_PATH)
        assert "from .lifecycle import CertificateLifecycleEvent" in source

    def test_save_records_old_and_new_status(self):
        """Test that lifecycle event records both old and new status."""
        source = _read_source(_CERTIFICATES_PATH)
        assert "old_status=self._original_status" in source
        assert "new_status=self.status" in source

    def test_save_includes_description_for_status_change(self):
        """Test that status change event includes a human-readable description."""
        source = _read_source(_CERTIFICATES_PATH)
        assert "Status changed from" in source

    def test_save_includes_description_for_import(self):
        """Test that import event includes a human-readable description."""
        source = _read_source(_CERTIFICATES_PATH)
        assert "Certificate imported with status" in source


# ---------------------------------------------------------------------------
# Tests: CertificateAssignment lifecycle event hooks (source inspection)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAssignmentLifecycleHooks:
    """Tests for lifecycle event creation in CertificateAssignment save/delete."""

    def test_save_creates_assignment_added_event(self):
        """Test that CertificateAssignment.save() creates an assignment_added event."""
        source = _read_source(_ASSIGNMENTS_PATH)
        assert "EVENT_ASSIGNMENT_ADDED" in source

    def test_delete_creates_assignment_removed_event(self):
        """Test that CertificateAssignment.delete() creates an assignment_removed event."""
        source = _read_source(_ASSIGNMENTS_PATH)
        assert "EVENT_ASSIGNMENT_REMOVED" in source

    def test_save_wraps_lifecycle_in_try_except(self):
        """Test that assignment lifecycle event creation is wrapped in try/except."""
        source = _read_source(_ASSIGNMENTS_PATH)
        assert "Failed to create lifecycle event" in source

    def test_delete_creates_event_before_super_delete(self):
        """Test that delete creates lifecycle event before calling super().delete()."""
        source = _read_source(_ASSIGNMENTS_PATH)
        # Find positions of lifecycle creation and super().delete() in delete method
        lifecycle_pos = source.find("EVENT_ASSIGNMENT_REMOVED")
        super_delete_pos = source.find("result = super().delete(")
        assert lifecycle_pos > 0, "EVENT_ASSIGNMENT_REMOVED should be in source"
        assert super_delete_pos > 0, "result = super().delete() should be in source"
        assert lifecycle_pos < super_delete_pos, "Lifecycle event for removal must be created before super().delete()"

    def test_assignment_model_has_logger(self):
        """Test that assignments.py has a logger configured."""
        source = _read_source(_ASSIGNMENTS_PATH)
        assert 'logger = logging.getLogger("netbox_ssl.models")' in source

    def test_save_description_includes_object_type(self):
        """Test that assignment added event description includes the object type."""
        source = _read_source(_ASSIGNMENTS_PATH)
        assert "self.assigned_object_type.model" in source

    def test_delete_description_includes_object_type(self):
        """Test that assignment removed event description includes the object type."""
        source = _read_source(_ASSIGNMENTS_PATH)
        # Both save and delete reference the object type in descriptions
        assert 'f"Removed from {self.assigned_object_type.model}' in source


# ---------------------------------------------------------------------------
# Tests: Migration file
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestLifecycleMigration:
    """Tests for the lifecycle migration file."""

    def test_migration_file_exists(self):
        """Test that migration 0011 exists."""
        migration_path = _MIGRATIONS_DIR / "0011_certificatelifecycleevent.py"
        assert migration_path.exists(), "Migration 0011_certificatelifecycleevent.py must exist"

    def test_migration_depends_on_0009(self):
        """Test that migration depends on 0009_compliancetrendsnapshot."""
        migration_path = _MIGRATIONS_DIR / "0011_certificatelifecycleevent.py"
        source = migration_path.read_text()
        assert "0009_compliancetrendsnapshot" in source

    def test_migration_creates_model(self):
        """Test that migration creates the CertificateLifecycleEvent model."""
        migration_path = _MIGRATIONS_DIR / "0011_certificatelifecycleevent.py"
        source = migration_path.read_text()
        assert "CertificateLifecycleEvent" in source
        assert "CreateModel" in source

    def test_migration_includes_index(self):
        """Test that migration includes the composite index."""
        migration_path = _MIGRATIONS_DIR / "0011_certificatelifecycleevent.py"
        source = migration_path.read_text()
        assert "netbox_ssl_lifecycle_cert_ts" in source


# ---------------------------------------------------------------------------
# Tests: Model exports
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestModelExports:
    """Tests for lifecycle model exports in __init__.py."""

    def test_init_imports_lifecycle_model(self):
        """Test that __init__.py imports CertificateLifecycleEvent."""
        source = _read_source(_INIT_PATH)
        assert "from .lifecycle import CertificateLifecycleEvent" in source

    def test_init_imports_lifecycle_choices(self):
        """Test that __init__.py imports LifecycleEventTypeChoices."""
        source = _read_source(_INIT_PATH)
        assert "LifecycleEventTypeChoices" in source

    def test_init_all_includes_lifecycle_event(self):
        """Test that __all__ includes CertificateLifecycleEvent."""
        source = _read_source(_INIT_PATH)
        assert '"CertificateLifecycleEvent"' in source

    def test_init_all_includes_lifecycle_choices(self):
        """Test that __all__ includes LifecycleEventTypeChoices."""
        source = _read_source(_INIT_PATH)
        assert '"LifecycleEventTypeChoices"' in source


# ---------------------------------------------------------------------------
# Tests: Template and view integration (source inspection)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestViewAndTemplateIntegration:
    """Tests for lifecycle integration in views and templates."""

    def test_certificate_view_includes_lifecycle_events(self):
        """Test that CertificateView passes lifecycle_events to context."""
        views_path = get_plugin_source_dir() /  "views" / "certificates.py"
        source = views_path.read_text()
        assert "lifecycle_events" in source
        assert "instance.lifecycle_events.all()" in source

    def test_certificate_template_has_lifecycle_tab(self):
        """Test that certificate detail template has a Lifecycle tab."""
        template_path = get_plugin_source_dir() /  "templates" / "netbox_ssl" / "certificate.html"
        source = template_path.read_text()
        assert "tab-lifecycle" in source
        assert "Lifecycle" in source

    def test_certificate_template_shows_lifecycle_badge_colors(self):
        """Test that template uses appropriate badge colors per event type."""
        template_path = get_plugin_source_dir() /  "templates" / "netbox_ssl" / "certificate.html"
        source = template_path.read_text()
        assert "event.event_type == 'imported'" in source
        assert "event.event_type == 'status_changed'" in source
        assert "event.event_type == 'revoked'" in source

    def test_certificate_template_tabbed_section_includes_lifecycle(self):
        """Test that the tabbed section condition includes lifecycle_events."""
        template_path = get_plugin_source_dir() /  "templates" / "netbox_ssl" / "certificate.html"
        source = template_path.read_text()
        assert "or lifecycle_events" in source


# ---------------------------------------------------------------------------
# Tests: API endpoint (source inspection)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestApiLifecycleEndpoint:
    """Tests for lifecycle API endpoint via source inspection."""

    def test_api_viewset_has_lifecycle_action(self):
        """Test that CertificateViewSet has a lifecycle action."""
        api_views_path = get_plugin_source_dir() /  "api" / "views.py"
        source = api_views_path.read_text()
        assert "def lifecycle(self, request, pk=None)" in source

    def test_api_lifecycle_is_get_method(self):
        """Test that lifecycle endpoint accepts GET requests."""
        api_views_path = get_plugin_source_dir() /  "api" / "views.py"
        source = api_views_path.read_text()
        assert 'methods=["get"]' in source
        assert 'url_path="lifecycle"' in source

    def test_api_lifecycle_limits_to_50_events(self):
        """Test that lifecycle endpoint limits results to 50 events."""
        api_views_path = get_plugin_source_dir() /  "api" / "views.py"
        source = api_views_path.read_text()
        assert "lifecycle_events.all()[:50]" in source


# ---------------------------------------------------------------------------
# Tests: GraphQL type (source inspection)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestGraphQLLifecycleType:
    """Tests for lifecycle GraphQL type via source inspection."""

    def test_graphql_types_imports_lifecycle_model(self):
        """Test that GraphQL types.py imports CertificateLifecycleEvent."""
        types_path = get_plugin_source_dir() /  "graphql" / "types.py"
        source = types_path.read_text()
        assert "CertificateLifecycleEvent" in source

    def test_graphql_has_lifecycle_event_type(self):
        """Test that GraphQL defines CertificateLifecycleEventType."""
        types_path = get_plugin_source_dir() /  "graphql" / "types.py"
        source = types_path.read_text()
        assert "class CertificateLifecycleEventType" in source

    def test_graphql_lifecycle_type_has_explicit_fields(self):
        """Test that GraphQL type uses explicit field list (not __all__)."""
        types_path = get_plugin_source_dir() /  "graphql" / "types.py"
        source = types_path.read_text()
        # Verify explicit fields are listed for the lifecycle type
        assert '"event_type"' in source
        assert '"timestamp"' in source
        assert '"description"' in source
        assert '"old_status"' in source
        assert '"new_status"' in source
        assert '"actor"' in source
        # Must NOT use __all__
        assert "__all__" not in source
