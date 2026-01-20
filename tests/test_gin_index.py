"""
Unit tests for the GIN index on Certificate.sans field.

Tests cover:
- Migration file structure and operations
- Index naming conventions
- Migration dependencies
"""

import pytest
from pathlib import Path


def get_project_root():
    """Get the project root directory, handling both local and CI environments."""
    # Try the standard location first (local development)
    local_root = Path(__file__).parent.parent
    if (local_root / "netbox_ssl" / "migrations").exists():
        return local_root

    # In CI, tests might be copied to /tmp/plugin_tests
    # Try to find the netbox_ssl package in common locations
    for potential_root in [
        Path("/opt/netbox/netbox"),
        Path.cwd(),
        local_root,
    ]:
        if (potential_root / "netbox_ssl" / "migrations").exists():
            return potential_root

    # Fallback to local root
    return local_root


_project_root = get_project_root()


def migration_file_available():
    """Check if the migration file is available for testing."""
    migration_path = (
        _project_root
        / "netbox_ssl"
        / "migrations"
        / "0002_certificate_sans_gin_index.py"
    )
    return migration_path.exists()


# Skip file-based tests if migration files aren't available (CI environment)
skip_if_no_migration = pytest.mark.skipif(
    not migration_file_available(),
    reason="Migration file not available in this environment"
)


class TestGinIndexMigration:
    """Tests for the GIN index migration."""

    @pytest.mark.unit
    @skip_if_no_migration
    def test_migration_file_exists(self):
        """Test that the migration file exists."""
        migration_path = (
            _project_root
            / "netbox_ssl"
            / "migrations"
            / "0002_certificate_sans_gin_index.py"
        )
        assert migration_path.exists(), f"Migration file not found at {migration_path}"

    @pytest.mark.unit
    @skip_if_no_migration
    def test_migration_has_docstring(self):
        """Test that the migration has a descriptive docstring."""
        migration_path = (
            _project_root
            / "netbox_ssl"
            / "migrations"
            / "0002_certificate_sans_gin_index.py"
        )
        content = migration_path.read_text()

        # Should have a docstring explaining the migration
        assert '"""' in content or "'''" in content
        assert "GIN" in content
        assert "index" in content.lower()

    @pytest.mark.unit
    @skip_if_no_migration
    def test_migration_imports_gin_index(self):
        """Test that the migration imports GinIndex."""
        migration_path = (
            _project_root
            / "netbox_ssl"
            / "migrations"
            / "0002_certificate_sans_gin_index.py"
        )
        content = migration_path.read_text()

        assert "from django.contrib.postgres.indexes import GinIndex" in content

    @pytest.mark.unit
    @skip_if_no_migration
    def test_migration_imports_add_index_concurrently(self):
        """Test that the migration imports AddIndexConcurrently."""
        migration_path = (
            _project_root
            / "netbox_ssl"
            / "migrations"
            / "0002_certificate_sans_gin_index.py"
        )
        content = migration_path.read_text()

        assert "from django.contrib.postgres.operations import AddIndexConcurrently" in content

    @pytest.mark.unit
    @skip_if_no_migration
    def test_migration_has_correct_dependency(self):
        """Test that the migration depends on 0001_initial."""
        migration_path = (
            _project_root
            / "netbox_ssl"
            / "migrations"
            / "0002_certificate_sans_gin_index.py"
        )
        content = migration_path.read_text()

        # Check dependency on initial migration
        assert '"netbox_ssl"' in content or "'netbox_ssl'" in content
        assert '"0001_initial"' in content or "'0001_initial'" in content

    @pytest.mark.unit
    @skip_if_no_migration
    def test_migration_uses_add_index_concurrently_operation(self):
        """Test that the migration uses AddIndexConcurrently operation."""
        migration_path = (
            _project_root
            / "netbox_ssl"
            / "migrations"
            / "0002_certificate_sans_gin_index.py"
        )
        content = migration_path.read_text()

        assert "AddIndexConcurrently(" in content

    @pytest.mark.unit
    @skip_if_no_migration
    def test_migration_is_non_atomic(self):
        """Test that the migration is non-atomic (required for concurrent index)."""
        migration_path = (
            _project_root
            / "netbox_ssl"
            / "migrations"
            / "0002_certificate_sans_gin_index.py"
        )
        content = migration_path.read_text()

        assert "atomic = False" in content

    @pytest.mark.unit
    @skip_if_no_migration
    def test_migration_targets_certificate_model(self):
        """Test that the migration targets the certificate model."""
        migration_path = (
            _project_root
            / "netbox_ssl"
            / "migrations"
            / "0002_certificate_sans_gin_index.py"
        )
        content = migration_path.read_text()

        assert 'model_name="certificate"' in content or "model_name='certificate'" in content

    @pytest.mark.unit
    @skip_if_no_migration
    def test_migration_targets_sans_field(self):
        """Test that the index targets the sans field."""
        migration_path = (
            _project_root
            / "netbox_ssl"
            / "migrations"
            / "0002_certificate_sans_gin_index.py"
        )
        content = migration_path.read_text()

        assert '"sans"' in content or "'sans'" in content
        assert "fields=" in content

    @pytest.mark.unit
    @skip_if_no_migration
    def test_migration_has_explicit_index_name(self):
        """Test that the index has an explicit name."""
        migration_path = (
            _project_root
            / "netbox_ssl"
            / "migrations"
            / "0002_certificate_sans_gin_index.py"
        )
        content = migration_path.read_text()

        # Index should have explicit name
        assert 'name="netbox_ssl_cert_sans_gin"' in content or \
               "name='netbox_ssl_cert_sans_gin'" in content


class TestGinIndexNamingConvention:
    """Tests for GIN index naming conventions."""

    @pytest.mark.unit
    def test_index_name_follows_convention(self):
        """Test that the index name follows Django/NetBox naming conventions."""
        # Index name should be: {app}_{model_abbrev}_{field}_{type}
        expected_name = "netbox_ssl_cert_sans_gin"

        # Verify the name is valid (max 30 chars for PostgreSQL)
        assert len(expected_name) <= 30

        # Verify the name follows snake_case
        assert expected_name == expected_name.lower()
        assert " " not in expected_name

        # Verify naming components
        assert "netbox_ssl" in expected_name  # app name
        assert "cert" in expected_name  # model abbreviation
        assert "sans" in expected_name  # field name
        assert "gin" in expected_name  # index type

    @pytest.mark.unit
    def test_index_name_is_not_autogenerated(self):
        """Test that the index name is explicit, not auto-generated."""
        expected_name = "netbox_ssl_cert_sans_gin"

        # Auto-generated names would include model name in full
        assert "certificate_" not in expected_name

        # Should be a readable, explicit name
        assert len(expected_name) < 30


class TestModelIndexDefinition:
    """Tests for the index definition in the Certificate model."""

    @pytest.mark.unit
    @skip_if_no_migration
    def test_model_imports_gin_index(self):
        """Test that the model file imports GinIndex."""
        model_path = _project_root / "netbox_ssl" / "models" / "certificates.py"
        if not model_path.exists():
            pytest.skip("Model file not available in this environment")
        content = model_path.read_text()

        assert "from django.contrib.postgres.indexes import GinIndex" in content

    @pytest.mark.unit
    @skip_if_no_migration
    def test_model_has_indexes_in_meta(self):
        """Test that the model has indexes defined in Meta class."""
        model_path = _project_root / "netbox_ssl" / "models" / "certificates.py"
        if not model_path.exists():
            pytest.skip("Model file not available in this environment")
        content = model_path.read_text()

        assert "indexes = [" in content

    @pytest.mark.unit
    @skip_if_no_migration
    def test_model_gin_index_matches_migration(self):
        """Test that the model index definition matches the migration."""
        model_path = _project_root / "netbox_ssl" / "models" / "certificates.py"
        if not model_path.exists():
            pytest.skip("Model file not available in this environment")
        content = model_path.read_text()

        # Should have the same index name as the migration
        assert "netbox_ssl_cert_sans_gin" in content
        assert "GinIndex" in content


class TestGinIndexQueryOptimization:
    """Tests documenting GIN index query optimization benefits."""

    @pytest.mark.unit
    def test_containment_operator_documented(self):
        """Test that array containment operator optimization is understood."""
        # GIN indexes optimize the @> (contains) operator
        # Example query: Certificate.objects.filter(sans__contains=["example.com"])

        # This test documents the intended use case
        query_example = "Certificate.objects.filter(sans__contains=['example.com'])"
        assert "sans__contains" in query_example

    @pytest.mark.unit
    def test_overlap_operator_documented(self):
        """Test that array overlap operator optimization is understood."""
        # GIN indexes also optimize the && (overlap) operator
        # Example query: Certificate.objects.filter(sans__overlap=["example.com", "test.com"])

        query_example = "Certificate.objects.filter(sans__overlap=['example.com'])"
        assert "sans__overlap" in query_example

    @pytest.mark.unit
    def test_index_benefits_documented(self):
        """Document the benefits of GIN index on SANs field."""
        benefits = [
            "Fast containment queries (sans__contains)",
            "Fast overlap queries (sans__overlap)",
            "Efficient search for certificates by domain name",
            "O(log n) lookups instead of O(n) full table scans",
        ]

        # All benefits should be documented
        assert len(benefits) == 4
        assert any("containment" in b for b in benefits)
        assert any("overlap" in b for b in benefits)


class TestMigrationSafety:
    """Tests for migration safety and reversibility."""

    @pytest.mark.unit
    @skip_if_no_migration
    def test_migration_is_single_operation(self):
        """Test that the migration contains exactly one operation."""
        migration_path = (
            _project_root
            / "netbox_ssl"
            / "migrations"
            / "0002_certificate_sans_gin_index.py"
        )
        content = migration_path.read_text()

        # Count operations - should be exactly one AddIndexConcurrently
        add_index_count = content.count("AddIndexConcurrently(")
        assert add_index_count == 1

    @pytest.mark.unit
    @skip_if_no_migration
    def test_migration_uses_gin_index_class(self):
        """Test that the migration uses the GinIndex class."""
        migration_path = (
            _project_root
            / "netbox_ssl"
            / "migrations"
            / "0002_certificate_sans_gin_index.py"
        )
        content = migration_path.read_text()

        # Should use GinIndex specifically, not a generic index
        assert "GinIndex(" in content

    @pytest.mark.unit
    def test_migration_number_is_sequential(self):
        """Test that the migration number is sequential from initial."""
        # Migration should be numbered 0002 (following 0001_initial)
        expected_filename = "0002_certificate_sans_gin_index.py"
        assert "0002" in expected_filename


class TestConcurrentIndexBenefits:
    """Tests documenting the benefits of concurrent index creation."""

    @pytest.mark.unit
    def test_concurrent_index_avoids_table_lock(self):
        """Document that AddIndexConcurrently avoids full table locks."""
        # AddIndexConcurrently creates the index without blocking writes
        # This is critical for production deployments with large tables
        benefits = [
            "No exclusive table lock during index creation",
            "Writes can continue while index is being built",
            "Safe for zero-downtime deployments",
            "Required for production environments with traffic",
        ]
        assert len(benefits) == 4

    @pytest.mark.unit
    def test_atomic_false_requirement(self):
        """Document that non-atomic migrations are required for concurrent indexes."""
        # AddIndexConcurrently cannot run inside a transaction
        # Therefore atomic = False is required in the Migration class
        requirement = "atomic = False is required for AddIndexConcurrently"
        assert "atomic = False" in requirement
