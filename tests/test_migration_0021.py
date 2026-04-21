"""Smoke test that migration 0021 exists and declares the expected operations.

Full data-migration behavior is tested in the Docker integration suite
(tests that run inside the NetBox container with a real Django DB).
"""

import importlib
import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.unit


def _get_plugin_source_dir():
    """Find the netbox_ssl source directory (local or Docker CI)."""
    local = Path(__file__).resolve().parent.parent / "netbox_ssl"
    if local.is_dir():
        return local
    docker = Path("/opt/netbox/netbox/netbox_ssl")
    if docker.is_dir():
        return docker
    return local


MIGRATION_PATH = _get_plugin_source_dir() / "migrations" / "0021_external_source_auth_credentials_and_region.py"

try:
    _spec = importlib.util.find_spec("netbox")
    _NETBOX_AVAILABLE = _spec is not None and _spec.origin is not None
except (ValueError, ModuleNotFoundError):
    _NETBOX_AVAILABLE = False


def _stub_validate_external_source_url(value: str) -> None:
    """Stub validator — no-op in unit test environment."""


@pytest.fixture
def migration_module(monkeypatch):
    """Load the migration module with fresh stubs (isolated per test).

    This fixture ensures that sys.modules is clean for the migration exec
    by force-replacing all relevant entries using monkeypatch.setitem().
    Monkeypatch automatically restores values after the test, preventing
    cross-file sys.modules contamination from earlier test runs.

    Important: When other test modules (e.g. test_external_source) use
    sys.modules.setdefault() to install MagicMocks for parent packages
    like "django.db", those MagicMocks can interfere with attribute access
    on submodules like "django.db.migrations". We must recreate the entire
    parent hierarchy with real objects to avoid this pollution.
    """
    if not _NETBOX_AVAILABLE:
        # Create real operation classes so migration operations have proper names
        # Note: class names must be AlterField (not _AlterField) so type(op).__name__ works
        class AlterField:
            """Stub for migrations.AlterField."""

            def __init__(self, **kwargs):
                self.name = kwargs.get("name")

        class AddField:
            """Stub for migrations.AddField."""

            def __init__(self, **kwargs):
                self.name = kwargs.get("name")

        class RunPython:
            """Stub for migrations.RunPython."""

            def __init__(self, func, *args, **kwargs):
                self.code = func

            @staticmethod
            def noop(*args, **kwargs):
                """Stub noop method."""
                pass

        class Migration:
            """Stub Django Migration class."""

            operations = []
            dependencies = []

        # Rebuild the django.db hierarchy to avoid MagicMock attribute pollution
        _django_db = MagicMock()
        _django_db_migrations = MagicMock()
        _django_db_migrations.Migration = Migration
        _django_db_migrations.AlterField = AlterField
        _django_db_migrations.AddField = AddField
        _django_db_migrations.RunPython = RunPython
        _django_db.migrations = _django_db_migrations

        monkeypatch.setitem(sys.modules, "django.db.migrations", _django_db_migrations)
        monkeypatch.setitem(sys.modules, "django.db", _django_db)

        # Create a fresh netbox.plugins.PluginConfig stub (required by netbox_ssl/__init__.py)
        _netbox_plugins = MagicMock()

        class _StubPluginConfig:
            pass

        _netbox_plugins.PluginConfig = _StubPluginConfig

        # Force-install Django + NetBox stubs so netbox_ssl/__init__.py can import
        monkeypatch.setitem(sys.modules, "netbox.plugins", _netbox_plugins)

        # Create fresh external_source stub (required by the migration)
        es_stub = MagicMock()
        es_stub.validate_external_source_url = _stub_validate_external_source_url

        monkeypatch.setitem(sys.modules, "netbox_ssl.models.external_source", es_stub)

        # Ensure the package namespace resolves correctly for attribute access
        netbox_ssl_stub = MagicMock()
        models_stub = MagicMock()
        models_stub.external_source = es_stub
        netbox_ssl_stub.models = models_stub

        monkeypatch.setitem(sys.modules, "netbox_ssl", netbox_ssl_stub)
        monkeypatch.setitem(sys.modules, "netbox_ssl.models", models_stub)

    spec = importlib.util.spec_from_file_location("mig0021", MIGRATION_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_migration_file_exists():
    assert MIGRATION_PATH.is_file(), f"Migration not found at {MIGRATION_PATH}"


def test_migration_defines_expected_operations(migration_module):
    operation_types = [type(op).__name__ for op in migration_module.Migration.operations]
    # Two AddFields (auth_credentials, region), two AlterFields (auth_method, base_url), one RunPython (backfill).
    assert operation_types.count("AddField") == 2
    assert operation_types.count("AlterField") == 2
    assert operation_types.count("RunPython") == 1


def test_migration_adds_auth_credentials_and_region(migration_module):
    addfield_names = [op.name for op in migration_module.Migration.operations if type(op).__name__ == "AddField"]
    assert set(addfield_names) == {"auth_credentials", "region"}


def test_migration_depends_on_0020(migration_module):
    assert (
        "netbox_ssl",
        "0020_compliancetrendsnapshot_netboxmodel_fields",
    ) in migration_module.Migration.dependencies
