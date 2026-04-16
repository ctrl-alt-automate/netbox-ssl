"""
Unit tests for performance optimizations.

Tests that indexes are defined, heavy fields are deferred in list views,
and plugin settings are configured.
"""

import pathlib

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


class TestDatabaseIndexes:
    """Test that performance indexes are defined on Certificate model."""

    @pytest.fixture(autouse=True)
    def _load_model_source(self):
        self.source = _read_source("models/certificates.py")

    def test_common_name_index_exists(self):
        assert "idx_cert_common_name" in self.source

    def test_status_index_exists(self):
        assert "idx_cert_status" in self.source

    def test_valid_to_index_exists(self):
        assert "idx_cert_valid_to" in self.source

    def test_issuer_index_exists(self):
        assert "idx_cert_issuer" in self.source

    def test_algorithm_index_exists(self):
        assert "idx_cert_algorithm" in self.source

    def test_tenant_index_exists(self):
        assert "idx_cert_tenant" in self.source

    def test_fingerprint_index_exists(self):
        assert "idx_cert_fingerprint" in self.source

    def test_composite_status_valid_to_index_exists(self):
        assert "idx_cert_status_valid_to" in self.source

    def test_acme_renewal_index_exists(self):
        assert "idx_cert_acme_renewal" in self.source

    def test_sans_gin_index_preserved(self):
        """Original GIN index on SANs is still present."""
        assert "netbox_ssl_cert_sans_gin" in self.source


class TestDeferredFields:
    """Test that heavy fields are deferred in list views based on setting."""

    def test_api_viewset_defers_on_list(self):
        """CertificateViewSet defers pem_content and issuer_chain on list action."""
        source = _read_source("api/views.py")
        assert "pem_content" in source
        assert "issuer_chain" in source
        assert "chain_validation_message" in source
        assert "_DEFERRED_FIELDS" in source
        assert 'self.action == "list"' in source

    def test_api_viewset_respects_lazy_load_setting(self):
        """Defer is conditional on lazy_load_pem_content setting."""
        source = _read_source("api/views.py")
        assert "lazy_load_pem_content" in source
        assert "PLUGINS_CONFIG" in source

    def test_web_list_view_has_get_queryset(self):
        """CertificateListView overrides get_queryset for conditional defer."""
        source = _read_source("views/certificates.py")
        assert "def get_queryset" in source
        assert "lazy_load_pem_content" in source
        assert ".defer(" in source


class TestPluginSettings:
    """Test performance-related plugin settings."""

    def test_performance_settings_defined(self):
        """Plugin config defines performance settings."""
        source = _read_source("__init__.py")
        assert "performance_prefetch_limit" in source
        assert "lazy_load_pem_content" in source


class TestMigrationExists:
    """Test that the performance indexes migration exists."""

    def test_migration_0017_exists(self):
        migration_path = _PLUGIN_DIR / "migrations" / "0017_performance_indexes.py"
        assert migration_path.exists()

    def test_migration_contains_all_indexes(self):
        source = _read_source("migrations/0017_performance_indexes.py")
        expected_indexes = [
            "idx_cert_common_name",
            "idx_cert_status",
            "idx_cert_valid_to",
            "idx_cert_issuer",
            "idx_cert_algorithm",
            "idx_cert_tenant",
            "idx_cert_fingerprint",
            "idx_cert_status_valid_to",
            "idx_cert_acme_renewal",
        ]
        for idx_name in expected_indexes:
            assert idx_name in source, f"Missing index: {idx_name}"
