"""
Unit tests for Django system checks.

Tests the fresh-install-friendly check messages for check_database_tables
and check_plugin_ready.
"""

import importlib.util
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Mock Django/NetBox before importing plugin code
# ---------------------------------------------------------------------------
try:
    _spec = importlib.util.find_spec("netbox")
    _NETBOX_AVAILABLE = _spec is not None and _spec.origin is not None
except (ValueError, ModuleNotFoundError):
    _NETBOX_AVAILABLE = False

if not _NETBOX_AVAILABLE:
    if "netbox" not in sys.modules:
        from datetime import datetime
        from datetime import timezone as tz

        _django_utils_timezone = MagicMock()
        _django_utils_timezone.now.return_value = datetime(2026, 6, 15, 12, 0, 0, tzinfo=tz.utc)

        for mod in [
            "django",
            "django.conf",
            "django.db",
            "django.db.models",
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
            "django.core.checks",
            "django.core.exceptions",
            "django.urls",
            "netbox",
            "netbox.models",
            "netbox.plugins",
            "utilities",
            "utilities.choices",
        ]:
            sys.modules.setdefault(mod, MagicMock())
        sys.modules["django.utils.timezone"] = _django_utils_timezone

        class _CheckMessage:
            def __init__(self, msg, hint=None, obj=None, id=None):
                self.msg = msg
                self.hint = hint
                self.obj = obj
                self.id = id

        class _Info(_CheckMessage):
            level = 20  # Match Django's real level integers

        class _Warning(_CheckMessage):
            level = 30

        class _Error(_CheckMessage):
            level = 40

        _checks_mod = sys.modules["django.core.checks"]
        _checks_mod.Info = _Info
        _checks_mod.Warning = _Warning
        _checks_mod.Error = _Error
        _checks_mod.Tags = SimpleNamespace(
            models="models",
            urls="urls",
            templates="templates",
            security="security",
            database="database",
        )
        _checks_mod.register = lambda *a, **kw: (lambda f: f)

    # Always ensure the plugin models module is mocked (even if other test files
    # already set up base Django mocks)
    sys.modules.setdefault("netbox_ssl.models", MagicMock())


from django.core.checks import Info, Warning

from netbox_ssl.checks import check_database_tables, check_plugin_ready


def _is_info(result):
    """Check if result is an Info-level message (works with real Django or mocks)."""
    return isinstance(result, Info)


def _is_warning(result):
    """Check if result is a Warning-level message (works with real Django or mocks)."""
    return isinstance(result, Warning)


# ---- check_database_tables ------------------------------------------------


class TestCheckDatabaseTables:
    """Tests for fresh-install-friendly check_database_tables."""

    @patch("django.db.connection")
    def test_all_tables_present_no_warnings(self, mock_conn):
        """No warnings when all expected tables exist."""
        mock_conn.introspection.table_names.return_value = [
            "netbox_ssl_certificate",
            "netbox_ssl_certificateassignment",
            "other_table",
        ]
        results = check_database_tables(None)
        assert len(results) == 0

    @patch("django.db.connection")
    def test_all_tables_missing_returns_info(self, mock_conn):
        """Fresh install: all tables missing -> single Info message."""
        mock_conn.introspection.table_names.return_value = ["other_table"]
        results = check_database_tables(None)
        assert len(results) == 1
        assert results[0].id == "netbox_ssl.I002"
        assert _is_info(results[0])
        assert "migrate netbox_ssl" in results[0].msg

    @patch("django.db.connection")
    def test_partial_tables_missing_returns_warnings(self, mock_conn):
        """Partial migration: only some tables missing -> individual W005."""
        mock_conn.introspection.table_names.return_value = [
            "netbox_ssl_certificate",
        ]
        results = check_database_tables(None)
        assert len(results) == 1
        assert results[0].id == "netbox_ssl.W005"
        assert _is_warning(results[0])
        assert "certificateassignment" in results[0].msg

    @patch("django.db.connection")
    def test_database_error_returns_w006(self, mock_conn):
        """Database error gives W006 with connectivity hint."""
        mock_conn.introspection.table_names.side_effect = Exception("connection refused")
        results = check_database_tables(None)
        assert len(results) == 1
        assert results[0].id == "netbox_ssl.W006"


# ---- check_plugin_ready ---------------------------------------------------


class TestCheckPluginReady:
    """Tests for fresh-install-friendly check_plugin_ready."""

    def _get_models_module(self):
        """Get the mocked netbox_ssl.models module from sys.modules."""
        return sys.modules["netbox_ssl.models"]

    def test_healthy_plugin(self):
        """Healthy plugin returns I001 info message."""
        models_mod = self._get_models_module()
        models_mod.Certificate.objects.count.return_value = 10
        models_mod.CertificateAssignment.objects.count.return_value = 5
        models_mod.Certificate.objects.filter.return_value.count.return_value = 0
        results = check_plugin_ready(None)
        assert any(r.id == "netbox_ssl.I001" for r in results)

    def test_does_not_exist_error_returns_info(self):
        """'does not exist' errors get friendly I003 instead of W009."""
        models_mod = self._get_models_module()
        models_mod.Certificate.objects.count.side_effect = Exception('relation "netbox_ssl_certificate" does not exist')
        results = check_plugin_ready(None)
        assert len(results) == 1
        assert results[0].id == "netbox_ssl.I003"
        assert _is_info(results[0])
        assert "migrate netbox_ssl" in results[0].msg
        # Reset side_effect for other tests
        models_mod.Certificate.objects.count.side_effect = None

    def test_other_error_returns_w009(self):
        """Non-table errors still give W009 warning."""
        models_mod = self._get_models_module()
        models_mod.Certificate.objects.count.side_effect = Exception("connection refused")
        results = check_plugin_ready(None)
        assert len(results) == 1
        assert results[0].id == "netbox_ssl.W009"
        assert _is_warning(results[0])
        # Reset side_effect for other tests
        models_mod.Certificate.objects.count.side_effect = None
