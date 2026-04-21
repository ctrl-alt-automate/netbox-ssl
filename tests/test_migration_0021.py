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

MIGRATION_PATH = (
    Path(__file__).resolve().parent.parent
    / "netbox_ssl"
    / "migrations"
    / "0021_external_source_auth_credentials_and_region.py"
)

# ---------------------------------------------------------------------------
# Guard: when running outside a NetBox container, stub out
# netbox_ssl.models.external_source in sys.modules before the migration
# module is imported. The migration does:
#
#   import netbox_ssl.models.external_source  # for validate_external_source_url
#
# Without the stub, importing the package triggers netbox_ssl/__init__.py
# and the full Django model metaclass machinery, which requires a configured
# Django settings environment.
# ---------------------------------------------------------------------------
try:
    _spec = importlib.util.find_spec("netbox")
    _NETBOX_AVAILABLE = _spec is not None and _spec.origin is not None
except (ValueError, ModuleNotFoundError):
    _NETBOX_AVAILABLE = False

if not _NETBOX_AVAILABLE:
    # Stub the external_source module with only what the migration references:
    # the validate_external_source_url callable (used as a field validator).
    def _stub_validate_external_source_url(value: str) -> None:  # noqa: D401
        """Stub validator — no-op in unit test environment."""

    _es_stub = MagicMock()
    _es_stub.validate_external_source_url = _stub_validate_external_source_url

    sys.modules.setdefault("netbox_ssl.models.external_source", _es_stub)

    # Also ensure the package namespace resolves so attribute access
    # `netbox_ssl.models.external_source` on the module object works.
    _netbox_ssl_stub = sys.modules.get("netbox_ssl", MagicMock())
    if not hasattr(_netbox_ssl_stub, "models"):
        _netbox_ssl_stub.models = MagicMock()
    _netbox_ssl_stub.models.external_source = _es_stub
    sys.modules.setdefault("netbox_ssl", _netbox_ssl_stub)
    sys.modules.setdefault("netbox_ssl.models", _netbox_ssl_stub.models)


def _load_migration():
    """Load the migration module via importlib, bypassing Django's app registry."""
    spec = importlib.util.spec_from_file_location("mig0021", MIGRATION_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_migration_file_exists():
    assert MIGRATION_PATH.is_file(), f"Migration not found at {MIGRATION_PATH}"


def test_migration_defines_expected_operations():
    module = _load_migration()

    operation_types = [type(op).__name__ for op in module.Migration.operations]
    # Two AddFields (auth_credentials, region), one AlterField (base_url), one RunPython (backfill).
    assert operation_types.count("AddField") == 2
    assert operation_types.count("AlterField") == 1
    assert operation_types.count("RunPython") == 1


def test_migration_adds_auth_credentials_and_region():
    module = _load_migration()

    addfield_names = [op.name for op in module.Migration.operations if type(op).__name__ == "AddField"]
    assert set(addfield_names) == {"auth_credentials", "region"}


def test_migration_depends_on_0020():
    module = _load_migration()

    assert (
        "netbox_ssl",
        "0020_compliancetrendsnapshot_netboxmodel_fields",
    ) in module.Migration.dependencies
