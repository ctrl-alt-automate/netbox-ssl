"""
Unit tests for granular permissions.

Tests that custom permissions are defined on models and that
API endpoint source code contains the correct has_perm checks.

These tests read source files directly to avoid needing Django/NetBox imports.
"""

import pathlib
import re

import pytest

# Mark all tests in this module as unit tests
pytestmark = pytest.mark.unit

def _get_plugin_source_dir() -> pathlib.Path:
    """Resolve plugin source directory for both local and Docker CI environments."""
    local = pathlib.Path(__file__).resolve().parent.parent / "netbox_ssl"
    if local.is_dir():
        return local
    docker = pathlib.Path("/opt/netbox/netbox/netbox_ssl")
    if docker.is_dir():
        return docker
    return local


_PLUGIN_DIR = _get_plugin_source_dir()


def _read_source(relative_path: str) -> str:
    """Read a source file relative to the plugin directory."""
    return (_PLUGIN_DIR / relative_path).read_text()


class TestCustomPermissionsOnModels:
    """Test that custom permissions are defined in model Meta."""

    @pytest.fixture(autouse=True)
    def _load_sources(self):
        self.cert_source = _read_source("models/certificates.py")
        self.compliance_source = _read_source("models/compliance.py")

    def test_certificate_model_has_import_permission(self):
        assert "import_certificate" in self.cert_source
        assert "Can import certificates" in self.cert_source

    def test_certificate_model_has_renew_permission(self):
        assert "renew_certificate" in self.cert_source
        assert "Can perform certificate renewal" in self.cert_source

    def test_certificate_model_has_bulk_permission(self):
        assert "bulk_operations" in self.cert_source
        assert "Can perform bulk certificate operations" in self.cert_source

    def test_compliance_policy_has_manage_permission(self):
        assert "manage_compliance" in self.compliance_source
        assert "Can run compliance checks" in self.compliance_source


class TestBulkOperationsPermission:
    """Test that all bulk endpoints require bulk_operations permission."""

    @pytest.fixture(autouse=True)
    def _load_api_source(self):
        self.api_source = _read_source("api/views.py")

    def test_check_bulk_perm_helper_exists(self):
        """The _check_bulk_perm helper function is defined."""
        assert "def _check_bulk_perm(" in self.api_source
        assert "netbox_ssl.bulk_operations" in self.api_source

    def test_has_import_perm_fallback_helper(self):
        """_has_import_perm checks both import_certificate and add_certificate."""
        assert "def _has_import_perm(" in self.api_source
        assert "import_certificate" in self.api_source
        assert "add_certificate" in self.api_source

    def test_bulk_perm_uses_import_fallback(self):
        """_check_bulk_perm uses _has_import_perm for import permission checks."""
        assert "_has_import_perm" in self.api_source

    def test_all_bulk_endpoints_use_check_bulk_perm(self):
        """Every bulk endpoint uses _check_bulk_perm, not raw has_perm."""
        lines = self.api_source.split("\n")
        bulk_endpoints = []
        for i, line in enumerate(lines):
            if "@action" in line and 'url_path="bulk-' in line:
                bulk_endpoints.append(i)

        assert len(bulk_endpoints) >= 5, "Expected at least 5 bulk endpoints"

        for ep_line in bulk_endpoints:
            # Check next 30 lines for _check_bulk_perm
            context = "\n".join(lines[ep_line : ep_line + 30])
            assert "_check_bulk_perm" in context, (
                f"Bulk endpoint at line {ep_line + 1} does not use _check_bulk_perm:\n{lines[ep_line].strip()}"
            )

    def test_bulk_import_requires_import_and_bulk(self):
        """bulk-import checks both bulk_operations and import_certificate."""
        assert '_check_bulk_perm(request, "netbox_ssl.import_certificate")' in self.api_source

    def test_bulk_validate_requires_change_and_bulk(self):
        """bulk-validate-chain checks both bulk_operations and change_certificate."""
        assert '_check_bulk_perm(request, "netbox_ssl.change_certificate")' in self.api_source

    def test_bulk_compliance_requires_manage_and_bulk(self):
        """bulk-compliance-check checks both bulk_operations and manage_compliance."""
        assert '_check_bulk_perm(request, "netbox_ssl.manage_compliance")' in self.api_source

    def test_bulk_assign_requires_add_assignment_and_bulk(self):
        """bulk-assign checks both bulk_operations and add_certificateassignment."""
        assert '_check_bulk_perm(request, "netbox_ssl.add_certificateassignment")' in self.api_source


class TestSingleEndpointPermissions:
    """Test that non-bulk endpoints have correct direct has_perm checks."""

    @pytest.fixture(autouse=True)
    def _load_api_source(self):
        self.api_source = _read_source("api/views.py")

    def test_import_uses_import_permission(self):
        assert 'has_perm("netbox_ssl.import_certificate")' in self.api_source

    def test_compliance_check_uses_manage_permission(self):
        assert 'has_perm("netbox_ssl.manage_compliance")' in self.api_source

    def test_validate_chain_has_change_permission(self):
        assert 'has_perm("netbox_ssl.change_certificate")' in self.api_source

    def test_detect_acme_has_change_permission(self):
        # detect_acme is a POST that modifies the certificate
        # Check there are at least 2 direct has_perm calls for change_certificate
        # (validate_chain + detect_acme, separate from bulk endpoints)
        direct_checks = re.findall(r'has_perm\("netbox_ssl\.change_certificate"\)', self.api_source)
        assert len(direct_checks) >= 2

    def test_import_has_backward_compatible_fallback(self):
        """Import uses _has_import_perm which falls back to add_certificate."""
        assert "_has_import_perm" in self.api_source
        assert 'has_perm("netbox_ssl.add_certificate")' in self.api_source  # fallback

    def test_all_post_actions_have_permission_checks(self):
        """Every POST @action has a has_perm or _check_bulk_perm within 30 lines."""
        lines = self.api_source.split("\n")
        action_lines = []
        for i, line in enumerate(lines):
            if "@action" in line and 'methods=["post"]' in line:
                action_lines.append(i)

        for action_line in action_lines:
            context = "\n".join(lines[action_line : action_line + 30])
            has_check = (
                "has_perm" in context
                or "_check_bulk_perm" in context
                or "_has_import_perm" in context
                or "get_object" in context
            )
            assert has_check, (
                f"POST @action at line {action_line + 1} missing permission check:\n{lines[action_line].strip()}"
            )


class TestViewPermissionChecks:
    """Test that web views have correct permission checks."""

    @pytest.fixture(autouse=True)
    def _load_views_source(self):
        self.views_source = _read_source("views/certificates.py")

    def test_import_view_checks_import_permission(self):
        assert "import_certificate" in self.views_source

    def test_import_view_has_add_certificate_fallback(self):
        """Import views fall back to add_certificate for v0.8.x compatibility."""
        assert "add_certificate" in self.views_source

    def test_renew_view_checks_renew_permission(self):
        assert "renew_certificate" in self.views_source

    def test_bulk_import_view_checks_import_permission(self):
        assert "import_certificate" in self.views_source


class TestDocumentation:
    """Test that permission documentation exists and is complete."""

    @pytest.fixture(autouse=True)
    def _check_docs_available(self):
        doc_path = _PLUGIN_DIR.parent / "docs" / "permissions.md"
        if not doc_path.exists():
            pytest.skip("docs/ not available in this environment (e.g. Docker CI)")

    def test_permissions_doc_exists(self):
        doc_path = _PLUGIN_DIR.parent / "docs" / "permissions.md"
        assert doc_path.exists()

    def test_permissions_doc_covers_custom_permissions(self):
        source = (_PLUGIN_DIR.parent / "docs" / "permissions.md").read_text()
        assert "import_certificate" in source
        assert "renew_certificate" in source
        assert "bulk_operations" in source
        assert "manage_compliance" in source

    def test_permissions_doc_covers_bulk_endpoints(self):
        source = (_PLUGIN_DIR.parent / "docs" / "permissions.md").read_text()
        assert "bulk-import" in source
        assert "bulk-status-update" in source
        assert "bulk-assign" in source

    def test_permissions_doc_covers_tenant_scoping(self):
        source = (_PLUGIN_DIR.parent / "docs" / "permissions.md").read_text()
        assert "Tenant" in source or "tenant" in source
        assert "ObjectPermission" in source


class TestMigrationExists:
    """Test that the permissions migration is properly defined."""

    def test_migration_0016_exists(self):
        migration_path = _PLUGIN_DIR / "migrations" / "0016_custom_permissions.py"
        assert migration_path.exists()

    def test_migration_contains_all_permissions(self):
        source = _read_source("migrations/0016_custom_permissions.py")
        for perm in ["import_certificate", "renew_certificate", "bulk_operations", "manage_compliance"]:
            assert perm in source, f"Missing permission in migration: {perm}"
