from pathlib import Path


def _get_plugin_source_dir():
    """Find the netbox_ssl source directory (local or Docker CI)."""
    local = Path(__file__).resolve().parent.parent / "netbox_ssl"
    if local.is_dir():
        return local
    docker = Path("/opt/netbox/netbox/netbox_ssl")
    if docker.is_dir():
        return docker
    return local


"""
Unit tests for the ExternalSource model and related infrastructure.

Tests model choices, URL validation, field structure, and migration
existence without requiring a running NetBox instance.
"""

import importlib
import importlib.util
import os
import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Mock Django/NetBox before importing plugin code
# ---------------------------------------------------------------------------
try:
    _spec = importlib.util.find_spec("netbox")
    _NETBOX_AVAILABLE = _spec is not None and _spec.origin is not None
except (ValueError, ModuleNotFoundError):
    _NETBOX_AVAILABLE = False

if not _NETBOX_AVAILABLE:
    _django_utils_timezone = MagicMock()
    _django_utils_timezone.now.return_value = datetime(2026, 3, 22, 12, 0, 0, tzinfo=timezone.utc)

    # Mock ValidationError to be a real exception class
    class MockValidationError(Exception):
        pass

    _django_core_exceptions = MagicMock()
    _django_core_exceptions.ValidationError = MockValidationError

    # ChoiceSet must be a real class so subclasses can define class attributes
    class _MockChoiceSet:
        CHOICES = []

    _utilities_choices = MagicMock()
    _utilities_choices.ChoiceSet = _MockChoiceSet

    # NetBoxModel must be a real class so model subclasses can define class bodies
    class _MockNetBoxModel:
        pass

    _netbox_models = MagicMock()
    _netbox_models.NetBoxModel = _MockNetBoxModel

    for mod in [
        "django",
        "django.conf",
        "django.db",
        "django.db.models",
        "django.db.models.functions",
        "django.utils",
        "django.utils.timezone",
        "django.utils.translation",
        "django.contrib",
        "django.contrib.contenttypes",
        "django.contrib.contenttypes.fields",
        "django.contrib.contenttypes.models",
        "django.contrib.postgres",
        "django.contrib.postgres.fields",
        "django.contrib.postgres.indexes",
        "django.core",
        "django.core.exceptions",
        "django.urls",
        "django.http",
        "netbox",
        "netbox.models",
        "netbox.plugins",
        "utilities",
        "utilities.choices",
    ]:
        sys.modules.setdefault(mod, MagicMock())
    # These must always override, even if previously set by another test module
    sys.modules["django.utils.timezone"] = _django_utils_timezone
    sys.modules["django.core.exceptions"] = _django_core_exceptions
    sys.modules["utilities.choices"] = _utilities_choices
    sys.modules["netbox.models"] = _netbox_models

if _NETBOX_AVAILABLE:
    from netbox_ssl.models.external_source import (
        AuthMethodChoices,
        ExternalSourceTypeChoices,
        SyncStatusChoices,
        validate_external_source_url,
    )
else:
    # Load external_source module directly to avoid triggering models/__init__.py
    # which imports all other models requiring complex metaclass mocking.
    _es_spec = importlib.util.spec_from_file_location(
        "netbox_ssl.models.external_source",
        os.path.join(str(_get_plugin_source_dir()), "models", "external_source.py"),
        submodule_search_locations=[],
    )
    _es_mod = importlib.util.module_from_spec(_es_spec)
    sys.modules["netbox_ssl.models.external_source"] = _es_mod
    _es_spec.loader.exec_module(_es_mod)

    AuthMethodChoices = _es_mod.AuthMethodChoices
    ExternalSourceTypeChoices = _es_mod.ExternalSourceTypeChoices
    SyncStatusChoices = _es_mod.SyncStatusChoices
    validate_external_source_url = _es_mod.validate_external_source_url


@pytest.mark.unit
class TestExternalSourceTypeChoices:
    """Test ExternalSourceTypeChoices."""

    def test_choices_exist(self):
        """Test that source type choices are defined."""
        assert hasattr(ExternalSourceTypeChoices, "CHOICES")
        assert len(ExternalSourceTypeChoices.CHOICES) >= 2

    def test_lemur_type(self):
        """Test Lemur type exists."""
        assert ExternalSourceTypeChoices.TYPE_LEMUR == "lemur"

    def test_generic_rest_type(self):
        """Test Generic REST type exists."""
        assert ExternalSourceTypeChoices.TYPE_GENERIC_REST == "generic_rest"


@pytest.mark.unit
class TestAuthMethodChoices:
    """Test AuthMethodChoices."""

    def test_choices_exist(self):
        """Test that auth method choices are defined."""
        assert hasattr(AuthMethodChoices, "CHOICES")
        assert len(AuthMethodChoices.CHOICES) >= 2

    def test_bearer_method(self):
        """Test Bearer token auth exists."""
        assert AuthMethodChoices.AUTH_BEARER == "bearer"

    def test_api_key_method(self):
        """Test API key auth exists."""
        assert AuthMethodChoices.AUTH_API_KEY == "api_key"


@pytest.mark.unit
class TestSyncStatusChoices:
    """Test SyncStatusChoices."""

    def test_choices_exist(self):
        """Test that sync status choices are defined."""
        assert hasattr(SyncStatusChoices, "CHOICES")
        assert len(SyncStatusChoices.CHOICES) >= 4

    def test_all_statuses(self):
        """Test all status values exist."""
        assert SyncStatusChoices.STATUS_NEW == "new"
        assert SyncStatusChoices.STATUS_OK == "ok"
        assert SyncStatusChoices.STATUS_ERROR == "error"
        assert SyncStatusChoices.STATUS_SYNCING == "syncing"


@pytest.mark.unit
class TestURLValidator:
    """Test validate_external_source_url."""

    def test_rejects_http(self):
        """Test that HTTP URLs are rejected."""
        with pytest.raises(Exception, match="HTTPS"):
            validate_external_source_url("http://example.com/api")

    def test_rejects_localhost(self):
        """Test that localhost URLs are rejected."""
        with pytest.raises(Exception, match="loopback"):
            validate_external_source_url("https://localhost/api")

    def test_rejects_127_0_0_1(self):
        """Test that 127.0.0.1 URLs are rejected."""
        with pytest.raises(Exception, match="loopback"):
            validate_external_source_url("https://127.0.0.1/api")

    def test_rejects_private_ip(self):
        """Test that private IP addresses are rejected."""
        with pytest.raises(Exception, match="private"):
            validate_external_source_url("https://192.168.1.1/api")

    def test_rejects_ipv6_loopback(self):
        """Test that IPv6 loopback is rejected."""
        with pytest.raises(Exception, match="loopback"):
            validate_external_source_url("https://[::1]/api")

    def test_accepts_valid_https(self):
        """Test that valid HTTPS URLs are accepted."""
        # Should not raise
        validate_external_source_url("https://lemur.example.com/api")

    def test_accepts_https_with_port(self):
        """Test that HTTPS URLs with ports are accepted."""
        validate_external_source_url("https://lemur.example.com:8443/api")

    def test_accepts_public_ip(self):
        """Test that public IPs over HTTPS are accepted."""
        validate_external_source_url("https://8.8.8.8/api")


@pytest.mark.unit
class TestExternalSourceSyncLogFields:
    """Test that ExternalSourceSyncLog has the expected counter fields."""

    def test_sync_log_module_importable(self):
        """Test that the sync log class is importable."""
        if _NETBOX_AVAILABLE:
            from netbox_ssl.models.external_source import ExternalSourceSyncLog

            assert ExternalSourceSyncLog is not None
        else:
            assert hasattr(_es_mod, "ExternalSourceSyncLog")


@pytest.mark.unit
class TestMigrationExists:
    """Test that the migration file exists."""

    def test_migration_0013_exists(self):
        """Test that migration 0013 exists."""
        # Support both local (tests/ next to netbox_ssl/) and Docker (/tmp/plugin_tests/)
        base = os.path.dirname(os.path.dirname(__file__))
        migration_path = os.path.join(base, "netbox_ssl", "migrations", "0013_external_source_framework.py")
        if not os.path.exists(migration_path) and _NETBOX_AVAILABLE:
            import netbox_ssl

            migration_path = os.path.join(
                os.path.dirname(netbox_ssl.__file__),
                "migrations",
                "0013_external_source_framework.py",
            )
        assert os.path.exists(migration_path), f"Migration not found at {migration_path}"


@pytest.mark.unit
class TestPluginSettings:
    """Test that external source plugin settings exist."""

    def test_plugin_settings_defined(self):
        """Test that the plugin __init__ defines external source settings."""
        base = os.path.dirname(os.path.dirname(__file__))
        init_path = os.path.join(base, "netbox_ssl", "__init__.py")
        if not os.path.exists(init_path) and _NETBOX_AVAILABLE:
            import netbox_ssl

            init_path = os.path.join(os.path.dirname(netbox_ssl.__file__), "__init__.py")
        with open(init_path) as f:
            content = f.read()

        assert "external_source_sync_enabled" in content
        assert "external_source_default_interval" in content
        assert "external_source_never_fetch_keys" in content


@pytest.mark.unit
def test_auth_method_choices_include_cloud_methods():
    from netbox_ssl.models.external_source import AuthMethodChoices

    values = [choice[0] for choice in AuthMethodChoices.CHOICES]
    assert "bearer" in values
    assert "api_key" in values
    assert "aws_explicit" in values
    assert "aws_instance_role" in values
    assert "azure_explicit" in values
    assert "azure_managed_identity" in values


@pytest.mark.unit
def test_external_source_has_auth_credentials_field():
    if not _NETBOX_AVAILABLE:
        pytest.skip("requires Django+NetBox metaclass infrastructure")
    from netbox_ssl.models.external_source import ExternalSource

    field_names = [f.name for f in ExternalSource._meta.get_fields() if not f.many_to_many and not f.one_to_many]
    assert "auth_credentials" in field_names
    assert "auth_credentials_reference" in field_names  # still present, deprecated


@pytest.mark.unit
def test_external_source_has_region_field():
    if not _NETBOX_AVAILABLE:
        pytest.skip("requires Django+NetBox metaclass infrastructure")
    from netbox_ssl.models.external_source import ExternalSource

    field_names = [f.name for f in ExternalSource._meta.get_fields() if not f.many_to_many and not f.one_to_many]
    assert "region" in field_names


@pytest.mark.unit
def test_external_source_base_url_is_optional():
    """base_url becomes optional in v1.1 so AWS ACM sources can omit it."""
    if not _NETBOX_AVAILABLE:
        pytest.skip("requires Django+NetBox metaclass infrastructure")
    from netbox_ssl.models.external_source import ExternalSource

    base_url_field = ExternalSource._meta.get_field("base_url")
    assert base_url_field.blank is True


@pytest.mark.unit
def test_external_source_type_choices_include_aws_acm():
    from netbox_ssl.models.external_source import ExternalSourceTypeChoices

    values = [choice[0] for choice in ExternalSourceTypeChoices.CHOICES]
    assert "aws_acm" in values
    # Existing types must remain
    assert "lemur" in values
    assert "generic_rest" in values
    # Sanity check: TYPE_AWS_ACM constant exists
    assert ExternalSourceTypeChoices.TYPE_AWS_ACM == "aws_acm"
