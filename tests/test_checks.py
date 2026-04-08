"""
Unit tests for Django system checks.

Tests the fresh-install-friendly check messages for check_database_tables
and check_plugin_ready.
"""

import importlib.util
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

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
    # Always ensure all required mocks exist, even if another test file
    # already set up some mocks. Use setdefault to avoid overwriting.
    from datetime import datetime
    from datetime import timezone as tz

    _django_utils_timezone = MagicMock()
    _django_utils_timezone.now.return_value = datetime(2026, 6, 15, 12, 0, 0, tzinfo=tz.utc)

    for mod in [
        "django",
        "django.conf",
        "django.db",
        "django.db.models",
        "django.db.models.functions",
        "django.utils",
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
        "netbox",
        "netbox.models",
        "netbox.plugins",
        "utilities",
        "utilities.choices",
    ]:
        sys.modules.setdefault(mod, MagicMock())
    # timezone mock must always win (for deterministic timestamps)
    # Force-set (not setdefault) to ensure deterministic timestamps in checks.
    sys.modules["django.utils.timezone"] = _django_utils_timezone

    # Build django.core.checks mock with proper stub classes
    class _CheckMessage:
        def __init__(self, msg, hint=None, obj=None, id=None):
            self.msg = msg
            self.hint = hint
            self.obj = obj
            self.id = id

    class _Info(_CheckMessage):
        level = 20

    class _Warning(_CheckMessage):
        level = 30

    class _Error(_CheckMessage):
        level = 40

    _checks_mod = MagicMock()
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
    # Force-set (not setdefault) to ensure our stub classes are used,
    # even if another test file created a bare MagicMock earlier.
    sys.modules["django.core.checks"] = _checks_mod

    sys.modules.setdefault("netbox_ssl.models", MagicMock())

    Info = _Info
    Warning = _Warning
else:
    from django.core.checks import Info, Warning

from netbox_ssl.checks import check_database_tables, check_plugin_ready

pytestmark = pytest.mark.unit


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

    @patch("netbox_ssl.models.CertificateAssignment")
    @patch("netbox_ssl.models.Certificate")
    def test_healthy_plugin(self, mock_cert, mock_assignment):
        """Healthy plugin returns I001 info message."""
        mock_cert.objects.count.return_value = 10
        mock_assignment.objects.count.return_value = 5
        mock_cert.objects.filter.return_value.count.return_value = 0
        results = check_plugin_ready(None)
        assert any(r.id == "netbox_ssl.I001" for r in results)

    @patch("netbox_ssl.models.CertificateAssignment")
    @patch("netbox_ssl.models.Certificate")
    def test_does_not_exist_error_returns_info(self, mock_cert, mock_assignment):
        """'does not exist' errors get friendly I003 instead of W009."""
        mock_cert.objects.count.side_effect = Exception('relation "netbox_ssl_certificate" does not exist')
        results = check_plugin_ready(None)
        assert len(results) == 1
        assert results[0].id == "netbox_ssl.I003"
        assert _is_info(results[0])
        assert "migrate netbox_ssl" in results[0].msg

    @patch("netbox_ssl.models.CertificateAssignment")
    @patch("netbox_ssl.models.Certificate")
    def test_other_error_returns_w009(self, mock_cert, mock_assignment):
        """Non-table errors still give W009 warning."""
        mock_cert.objects.count.side_effect = Exception("connection refused")
        results = check_plugin_ready(None)
        assert len(results) == 1
        assert results[0].id == "netbox_ssl.W009"
        assert _is_warning(results[0])
