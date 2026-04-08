"""
Unit tests for granular permissions.

Tests that custom permissions are defined on models and that
API endpoint source code contains the correct has_perm checks.

These tests read source files directly to avoid needing Django/NetBox imports.
"""

import pathlib

import pytest

# Mark all tests in this module as unit tests
pytestmark = pytest.mark.unit

# Resolve the plugin source directory
_PLUGIN_DIR = pathlib.Path(__file__).resolve().parent.parent / "netbox_ssl"


def _read_source(relative_path: str) -> str:
    """Read a source file relative to the plugin directory."""
    return (_PLUGIN_DIR / relative_path).read_text()


class TestCustomPermissionsOnModels:
    """Test that custom permissions are defined in model Meta."""

    def test_certificate_model_has_import_permission(self):
        """Certificate Meta.permissions includes import_certificate."""
        source = _read_source("models/certificates.py")
        assert "import_certificate" in source
        assert "Can import certificates" in source

    def test_certificate_model_has_renew_permission(self):
        """Certificate Meta.permissions includes renew_certificate."""
        source = _read_source("models/certificates.py")
        assert "renew_certificate" in source
        assert "Can perform certificate renewal" in source

    def test_certificate_model_has_bulk_permission(self):
        """Certificate Meta.permissions includes bulk_operations."""
        source = _read_source("models/certificates.py")
        assert "bulk_operations" in source
        assert "Can perform bulk certificate operations" in source

    def test_compliance_policy_has_manage_permission(self):
        """CompliancePolicy Meta.permissions includes manage_compliance."""
        source = _read_source("models/compliance.py")
        assert "manage_compliance" in source
        assert "Can run compliance checks" in source


class TestAPIPermissionChecks:
    """Test that API endpoints have correct has_perm checks via source inspection."""

    @pytest.fixture(autouse=True)
    def _load_api_source(self):
        self.api_source = _read_source("api/views.py")

    def test_import_endpoint_uses_import_permission(self):
        """Import endpoint checks import_certificate permission."""
        assert 'has_perm("netbox_ssl.import_certificate")' in self.api_source

    def test_validate_chain_has_permission_check(self):
        """validate_chain endpoint has a permission check."""
        assert 'has_perm("netbox_ssl.change_certificate")' in self.api_source

    def test_compliance_check_uses_manage_permission(self):
        """compliance_check endpoint uses manage_compliance permission."""
        assert 'has_perm("netbox_ssl.manage_compliance")' in self.api_source

    def test_detect_acme_has_permission_check(self):
        """detect_acme endpoint has a change_certificate check."""
        # At least 3 occurrences: validate_chain, detect_acme, bulk_validate_chain
        assert self.api_source.count('has_perm("netbox_ssl.change_certificate")') >= 3

    def test_bulk_compliance_has_manage_permission(self):
        """bulk_compliance_check uses manage_compliance permission."""
        # manage_compliance should appear at least twice (single + bulk)
        assert self.api_source.count('has_perm("netbox_ssl.manage_compliance")') >= 2

    def test_no_add_certificate_in_import_endpoints(self):
        """Import endpoints no longer use generic add_certificate."""
        assert 'has_perm("netbox_ssl.add_certificate")' not in self.api_source

    def test_all_post_actions_have_permission_checks(self):
        """Every POST @action should have a has_perm check nearby."""
        lines = self.api_source.split("\n")
        action_lines = []
        for i, line in enumerate(lines):
            if "@action" in line and 'methods=["post"]' in line:
                action_lines.append(i)

        for action_line in action_lines:
            # Check the next 30 lines for a has_perm call (docstrings can be long)
            context = "\n".join(lines[action_line : action_line + 30])
            assert "has_perm" in context or "get_object" in context, (
                f"POST @action at line {action_line + 1} may be missing permission check:\n"
                f"{lines[action_line].strip()}"
            )


class TestViewPermissionChecks:
    """Test that web views have correct permission checks via source inspection."""

    @pytest.fixture(autouse=True)
    def _load_views_source(self):
        self.views_source = _read_source("views/certificates.py")

    def test_import_view_checks_import_permission(self):
        """CertificateImportView checks import_certificate."""
        assert "import_certificate" in self.views_source

    def test_renew_view_checks_renew_permission(self):
        """CertificateRenewView checks renew_certificate."""
        assert "renew_certificate" in self.views_source

    def test_bulk_import_view_checks_import_permission(self):
        """CertificateBulkDataImportView checks add_certificate or import_certificate."""
        assert "import_certificate" in self.views_source or "add_certificate" in self.views_source


class TestMigrationExists:
    """Test that the permissions migration is properly defined."""

    def test_migration_0016_exists(self):
        """Migration 0016 for custom permissions exists."""
        migration_path = _PLUGIN_DIR / "migrations" / "0016_custom_permissions.py"
        assert migration_path.exists()

    def test_migration_contains_permissions(self):
        """Migration 0016 includes the permission definitions."""
        source = _read_source("migrations/0016_custom_permissions.py")
        assert "import_certificate" in source
        assert "renew_certificate" in source
        assert "bulk_operations" in source
        assert "manage_compliance" in source
