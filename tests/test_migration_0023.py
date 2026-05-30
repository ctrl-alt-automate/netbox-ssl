"""Smoke test that migration 0023 exists and declares the expected operations.

Migration 0023 reconciles drifted NetBoxModel fields / a stale constraint with
the model definitions (issue #118). Full apply/rollback/zero-drift behavior is
verified in the Docker integration suite (real NetBox DB) and by the
``makemigrations --check`` CI gate; this host-runnable test just locks the
operation structure so an accidental edit is caught in the fast unit lane.
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


MIGRATION_PATH = _get_plugin_source_dir() / "migrations" / "0023_compliance_tags_and_field_reconciliation.py"

try:
    _spec = importlib.util.find_spec("netbox")
    _NETBOX_AVAILABLE = _spec is not None and _spec.origin is not None
except (ValueError, ModuleNotFoundError):
    _NETBOX_AVAILABLE = False


@pytest.fixture
def migration_module(monkeypatch):
    """Load the migration module with fresh stubs (isolated per test).

    Mirrors test_migration_0021's approach: rebuild the django.db / taggit /
    utilities hierarchy with real stub classes so operation type names resolve
    and sys.modules pollution from other test files cannot interfere.
    """
    if not _NETBOX_AVAILABLE:

        class _Op:
            def __init__(self, **kwargs):
                self.model_name = kwargs.get("model_name")
                self.name = kwargs.get("name")

        class AddField(_Op):
            pass

        class AlterField(_Op):
            pass

        class RemoveConstraint(_Op):
            pass

        class SeparateDatabaseAndState:
            def __init__(self, state_operations=None, database_operations=None, **kwargs):
                self.state_operations = state_operations or []
                self.database_operations = database_operations or []

        class Migration:
            operations = []
            dependencies = []

        _migrations = MagicMock()
        _migrations.Migration = Migration
        _migrations.AddField = AddField
        _migrations.AlterField = AlterField
        _migrations.RemoveConstraint = RemoveConstraint
        _migrations.SeparateDatabaseAndState = SeparateDatabaseAndState

        _models = MagicMock()
        _django_db = MagicMock()
        _django_db.migrations = _migrations
        _django_db.models = _models

        monkeypatch.setitem(sys.modules, "django.db", _django_db)
        monkeypatch.setitem(sys.modules, "django.db.migrations", _migrations)
        monkeypatch.setitem(sys.modules, "django.db.models", _models)

        _taggit = MagicMock()
        _taggit_managers = MagicMock()
        _taggit.managers = _taggit_managers
        monkeypatch.setitem(sys.modules, "taggit", _taggit)
        monkeypatch.setitem(sys.modules, "taggit.managers", _taggit_managers)

        _utilities = MagicMock()
        _utilities_json = MagicMock()
        _utilities.json = _utilities_json
        monkeypatch.setitem(sys.modules, "utilities", _utilities)
        monkeypatch.setitem(sys.modules, "utilities.json", _utilities_json)

    spec = importlib.util.spec_from_file_location("mig0023", MIGRATION_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_migration_file_exists():
    assert MIGRATION_PATH.is_file(), f"Migration not found at {MIGRATION_PATH}"


def test_migration_depends_on_0022(migration_module):
    deps = migration_module.Migration.dependencies
    assert ("netbox_ssl", "0022_add_comments_fields") in deps
    # extras anchored at 0001_initial for cross-version (4.4-4.6) safety.
    assert ("extras", "0001_initial") in deps


def test_adds_tags_to_both_compliance_models(migration_module):
    add_targets = {
        (op.model_name, op.name) for op in migration_module.Migration.operations if type(op).__name__ == "AddField"
    }
    assert ("compliancecheck", "tags") in add_targets
    assert ("compliancepolicy", "tags") in add_targets


def test_removes_stale_unique_external_source_id_constraint(migration_module):
    removed = {
        (op.model_name, op.name)
        for op in migration_module.Migration.operations
        if type(op).__name__ == "RemoveConstraint"
    }
    assert ("certificate", "unique_external_source_id") in removed


def test_externalsource_tags_reconciliation_is_state_only(migration_module):
    """The M2M->TaggableManager alter must be state-only (no DB op).

    Django cannot ALTER to/from M2M; a DB op here would crash on migrate.
    """
    sds = [op for op in migration_module.Migration.operations if type(op).__name__ == "SeparateDatabaseAndState"]
    assert len(sds) == 1, "externalsource.tags reconciliation must use SeparateDatabaseAndState"
    assert sds[0].database_operations == [], "must carry NO database operation"
    state_targets = {(op.model_name, op.name) for op in sds[0].state_operations}
    assert ("externalsource", "tags") in state_targets
