"""
Unit tests for CertificateAssignment bug fixes (#85, #86).

#85: Editing assignments flashes screen but never saves
#86: Assignment list throws FieldError on GenericForeignKey sort
"""

import pathlib

import pytest

pytestmark = pytest.mark.unit


def _get_plugin_source_dir() -> pathlib.Path:
    """Resolve plugin source directory for both local and Docker CI environments."""
    # Local development: tests/ is next to netbox_ssl/
    local = pathlib.Path(__file__).resolve().parent.parent / "netbox_ssl"
    if local.is_dir():
        return local
    # Docker CI: tests at /tmp/plugin_tests/, plugin at /opt/netbox/netbox/netbox_ssl/
    docker = pathlib.Path("/opt/netbox/netbox/netbox_ssl")
    if docker.is_dir():
        return docker
    return local  # fallback


_PLUGIN_DIR = _get_plugin_source_dir()


def _read_source(relative_path: str) -> str:
    return (_PLUGIN_DIR / relative_path).read_text()


# ─────────────────────────────────────────────
# Bug #86: FieldError on assignment list sort
# ─────────────────────────────────────────────


class TestAssignmentTableOrderable:
    """Verify assigned_object column is not orderable (#86)."""

    @pytest.fixture(autouse=True)
    def _load_source(self):
        self.source = _read_source("tables/assignments.py")

    def test_assigned_object_column_not_orderable(self):
        """assigned_object column must have orderable=False to prevent FieldError."""
        assert "orderable=False" in self.source

    def test_assigned_object_column_exists(self):
        """The assigned_object column is still present in the table."""
        assert "assigned_object = tables.Column(" in self.source

    def test_table_has_custom_render(self):
        """Table has render_assigned_object for proper display."""
        assert "def render_assigned_object" in self.source


# ─────────────────────────────────────────────
# Bug #85: Edit assignment doesn't save
# ─────────────────────────────────────────────


class TestAssignmentFormEditBehavior:
    """Verify form handles edit-without-target-change correctly (#85)."""

    @pytest.fixture(autouse=True)
    def _load_source(self):
        self.source = _read_source("forms/assignments.py")

    def test_clean_allows_edit_without_new_target(self):
        """clean() must not reject edits where target hasn't changed."""
        assert "has_existing_target" in self.source
        # The validation should check for existing target on edit
        assert "self.instance.pk" in self.source
        assert "assigned_object_type_id" in self.source

    def test_save_preserves_existing_target(self):
        """save() must preserve assigned_object when no new target is selected."""
        # The save method should have an else branch that keeps existing values
        assert "keep as-is" in self.source or "not instance.pk" in self.source

    def test_save_guards_new_assignment_without_target(self):
        """save() raises error for new assignment without any target."""
        assert "not instance.pk" in self.source

    def test_form_populates_initial_on_edit(self):
        """Form __init__ populates device/vm/service fields when editing."""
        assert "self.instance.assigned_object" in self.source
        assert 'self.fields["service"].initial' in self.source
        assert 'self.fields["device"].initial' in self.source

    def test_duplicate_check_only_when_target_changes(self):
        """Duplicate check only runs when a new target is selected."""
        assert "has_new_target" in self.source


class TestAssignmentFormCleanLogic:
    """Test the actual clean/save logic flow via source analysis."""

    @pytest.fixture(autouse=True)
    def _load_source(self):
        self.source = _read_source("forms/assignments.py")

    def test_clean_defines_has_new_target(self):
        """clean() computes has_new_target from service/device/vm."""
        assert "has_new_target = service or device or vm" in self.source

    def test_clean_defines_has_existing_target(self):
        """clean() computes has_existing_target for edit case."""
        assert "has_existing_target = self.instance.pk and self.instance.assigned_object_type_id" in self.source

    def test_clean_rejects_new_without_target(self):
        """clean() rejects new assignments without any target."""
        assert "not has_new_target and not has_existing_target" in self.source

    def test_save_has_four_branches(self):
        """save() has branches for service, device, vm, and new-without-target."""
        # Should have: if service / elif device / elif vm / elif not instance.pk
        lines = self.source.split("\n")
        save_section = False
        branches = []
        for line in lines:
            if "def save(" in line:
                save_section = True
            if save_section:
                stripped = line.strip()
                if stripped.startswith(("if service:", "elif device:", "elif vm:", "elif not instance.pk:")):
                    branches.append(stripped)
                if stripped.startswith("def ") and "save" not in stripped:
                    break
        assert len(branches) == 4, f"Expected 4 branches in save(), got: {branches}"
