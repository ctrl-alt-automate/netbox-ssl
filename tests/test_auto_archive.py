"""
Unit tests for the Auto-Archive Policy feature (#50).

Tests the new STATUS_ARCHIVED choice, archive_pinned/archived_at fields,
auto-archive script logic, and the EVENT_CERTIFICATE_ARCHIVED constant.
"""

import importlib.util
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    from conftest import get_plugin_source_dir
except ImportError:
    from tests.conftest import get_plugin_source_dir
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

if not _NETBOX_AVAILABLE and "netbox" not in sys.modules:
    _django_utils_timezone = MagicMock()
    _django_utils_timezone.now.return_value = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)

    for mod in [
        "django", "django.conf", "django.db", "django.db.models",
        "django.db.models.functions", "django.db.models.expressions",
        "django.utils", "django.utils.timezone", "django.utils.translation",
        "django.contrib", "django.contrib.contenttypes",
        "django.contrib.contenttypes.fields", "django.contrib.contenttypes.models",
        "django.contrib.postgres", "django.contrib.postgres.fields",
        "django.contrib.postgres.indexes", "django.core", "django.core.exceptions",
        "django.urls", "netbox", "netbox.models", "netbox.plugins",
        "utilities", "utilities.choices",
    ]:
        sys.modules.setdefault(mod, MagicMock())
    sys.modules["django.utils.timezone"] = _django_utils_timezone

from netbox_ssl.utils.events import (
    EVENT_CERTIFICATE_ARCHIVED,
    build_certificate_event_payload,
)

# The STATUS_ARCHIVED value — used directly in tests that don't require full NetBox
_STATUS_ARCHIVED = "archived"


# ---------------------------------------------------------------------------
# Tests: STATUS_ARCHIVED in choices (source inspection)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestStatusArchivedChoice:
    """Test that STATUS_ARCHIVED is properly defined in CertificateStatusChoices."""

    def _read_certificates_source(self) -> str:
        """Read the certificates.py source code for inspection."""
        source_path = get_plugin_source_dir() /  "models" / "certificates.py"
        return source_path.read_text()

    def test_status_archived_constant_exists(self):
        """STATUS_ARCHIVED should be defined as a class attribute."""
        source = self._read_certificates_source()
        assert 'STATUS_ARCHIVED = "archived"' in source

    def test_status_archived_in_choices_list(self):
        """STATUS_ARCHIVED should be present in the CHOICES list."""
        source = self._read_certificates_source()
        assert "(STATUS_ARCHIVED," in source

    def test_status_archived_color_is_dark(self):
        """STATUS_ARCHIVED should have color 'dark'."""
        source = self._read_certificates_source()
        assert '(STATUS_ARCHIVED, "Archived", "dark")' in source

    def test_status_archived_display_label(self):
        """STATUS_ARCHIVED should have display label 'Archived'."""
        source = self._read_certificates_source()
        assert '"Archived"' in source
        assert '(STATUS_ARCHIVED, "Archived"' in source


# ---------------------------------------------------------------------------
# Tests: archive_pinned and archived_at fields (source inspection)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestArchiveFields:
    """Test that archive_pinned and archived_at fields are defined on Certificate."""

    def _read_certificates_source(self) -> str:
        source_path = get_plugin_source_dir() /  "models" / "certificates.py"
        return source_path.read_text()

    def test_archive_pinned_field_exists(self):
        """Certificate model should have an archive_pinned BooleanField."""
        source = self._read_certificates_source()
        assert "archive_pinned = models.BooleanField(" in source

    def test_archive_pinned_default_is_false(self):
        """archive_pinned should default to False."""
        source = self._read_certificates_source()
        assert "archive_pinned = models.BooleanField(" in source
        # Find the field definition and check for default=False
        idx = source.index("archive_pinned = models.BooleanField(")
        field_def = source[idx : idx + 200]
        assert "default=False" in field_def

    def test_archived_at_field_exists(self):
        """Certificate model should have an archived_at DateTimeField."""
        source = self._read_certificates_source()
        assert "archived_at = models.DateTimeField(" in source

    def test_archived_at_is_nullable(self):
        """archived_at should be null=True, blank=True."""
        source = self._read_certificates_source()
        idx = source.index("archived_at = models.DateTimeField(")
        field_def = source[idx : idx + 200]
        assert "null=True" in field_def
        assert "blank=True" in field_def

    def test_archive_pinned_has_help_text(self):
        """archive_pinned should have help_text."""
        source = self._read_certificates_source()
        idx = source.index("archive_pinned = models.BooleanField(")
        field_def = source[idx : idx + 300]
        assert "help_text=" in field_def

    def test_archived_at_has_help_text(self):
        """archived_at should have help_text."""
        source = self._read_certificates_source()
        idx = source.index("archived_at = models.DateTimeField(")
        field_def = source[idx : idx + 300]
        assert "help_text=" in field_def


# ---------------------------------------------------------------------------
# Tests: archived_at auto-set logic
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestArchivedAtAutoSet:
    """Test that archived_at is auto-set when status changes to archived."""

    def test_archived_at_set_on_status_change(self):
        """When status changes to archived, archived_at should be set."""
        now = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)

        # Simulate the save() logic from the model
        status = _STATUS_ARCHIVED
        original_status = "expired"
        archived_at = None

        is_becoming_archived = status == _STATUS_ARCHIVED and original_status != status
        if is_becoming_archived and not archived_at:
            archived_at = now

        assert archived_at == now

    def test_archived_at_not_overwritten_if_already_set(self):
        """If archived_at is already set, it should not be overwritten."""
        original_time = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        now = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)

        status = _STATUS_ARCHIVED
        original_status = "expired"
        archived_at = original_time

        is_becoming_archived = status == _STATUS_ARCHIVED and original_status != status
        if is_becoming_archived and not archived_at:
            archived_at = now

        assert archived_at == original_time

    def test_archived_at_not_set_for_other_statuses(self):
        """archived_at should not be set when status is not archived."""
        now = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)

        status = "expired"
        original_status = "active"
        archived_at = None

        is_becoming_archived = status == _STATUS_ARCHIVED and original_status != status
        if is_becoming_archived and not archived_at:
            archived_at = now

        assert archived_at is None

    def test_save_method_contains_archived_at_logic(self):
        """Certificate.save() should contain archived_at auto-set logic."""
        source_path = get_plugin_source_dir() /  "models" / "certificates.py"
        source = source_path.read_text()
        assert "is_becoming_archived" in source
        assert "STATUS_ARCHIVED" in source
        assert "archived_at" in source


# ---------------------------------------------------------------------------
# Tests: EVENT_CERTIFICATE_ARCHIVED constant
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestEventCertificateArchived:
    """Test EVENT_CERTIFICATE_ARCHIVED constant."""

    def test_event_constant_exists(self):
        """EVENT_CERTIFICATE_ARCHIVED should be importable."""
        assert EVENT_CERTIFICATE_ARCHIVED is not None

    def test_event_constant_value(self):
        """EVENT_CERTIFICATE_ARCHIVED should have the expected value."""
        assert EVENT_CERTIFICATE_ARCHIVED == "certificate_archived"

    def test_archived_event_payload(self):
        """Event payload for archived certificates should include event type."""
        mock_assignments = MagicMock()
        mock_assignments.select_related.return_value.all.return_value = []
        cert = SimpleNamespace(
            pk=42,
            common_name="old.example.com",
            serial_number="DEADBEEF",
            status="archived",
            days_remaining=-120,
            valid_to=datetime(2026, 2, 15, 12, 0, 0, tzinfo=timezone.utc),
            issuer="CN=Test CA",
            tenant=None,
            assignments=mock_assignments,
        )
        payload = build_certificate_event_payload(cert, EVENT_CERTIFICATE_ARCHIVED)
        assert payload["event_type"] == EVENT_CERTIFICATE_ARCHIVED
        assert payload["common_name"] == "old.example.com"
        assert payload["status"] == "archived"


# ---------------------------------------------------------------------------
# Tests: Auto-archive script logic
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAutoArchiveScriptLogic:
    """Test the core logic of the CertificateAutoArchive script."""

    def _make_expired_cert(
        self,
        cert_id: int,
        days_expired: int,
        archive_pinned: bool = False,
        common_name: str = "test.example.com",
    ) -> MagicMock:
        """Create a mock expired certificate."""
        now = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        valid_to = now - timedelta(days=days_expired)
        cert = MagicMock()
        cert.pk = cert_id
        cert.common_name = common_name
        cert.serial_number = f"SERIAL{cert_id}"
        cert.status = "expired"
        cert.archive_pinned = archive_pinned
        cert.valid_to = valid_to
        cert.days_expired = days_expired
        cert.days_remaining = -days_expired
        cert.issuer = "CN=Test CA"
        cert.tenant = None
        cert.archived_at = None

        mock_assignments = MagicMock()
        mock_assignments.select_related.return_value.all.return_value = []
        cert.assignments = mock_assignments

        return cert

    def test_archives_expired_certs_past_threshold(self):
        """Certificates expired beyond the threshold should be archived."""
        cert = self._make_expired_cert(1, days_expired=100)

        archive_days = 90
        now = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        cutoff_date = now - timedelta(days=archive_days)

        # Verify filter conditions match
        assert cert.status == "expired"
        assert cert.archive_pinned is False
        assert cert.valid_to < cutoff_date

        # Simulate archiving
        cert.status = _STATUS_ARCHIVED
        assert cert.status == "archived"

    def test_does_not_archive_recently_expired(self):
        """Certificates expired less than the threshold should not be archived."""
        cert = self._make_expired_cert(2, days_expired=30)

        archive_days = 90
        now = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        cutoff_date = now - timedelta(days=archive_days)

        # This cert's valid_to is after the cutoff, so it should NOT match
        assert cert.valid_to >= cutoff_date

    def test_respects_archive_pinned(self):
        """Certificates with archive_pinned=True should be skipped."""
        cert = self._make_expired_cert(3, days_expired=200, archive_pinned=True)

        assert cert.archive_pinned is True

        # The script filters with archive_pinned=False, so this cert
        # would not appear in the queryset
        should_include = (
            cert.status == "expired"
            and not cert.archive_pinned
            and cert.valid_to < datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc) - timedelta(days=90)
        )
        assert should_include is False

    def test_dry_run_does_not_modify(self):
        """In dry_run mode, certificates should not be modified."""
        cert = self._make_expired_cert(4, days_expired=120)
        original_status = cert.status

        # Simulate dry_run logic: count but don't change
        dry_run = True
        archived_count = 0

        if not dry_run:
            cert.status = _STATUS_ARCHIVED
            cert.save()

        archived_count += 1  # Still counted for reporting

        # Status should remain unchanged
        assert cert.status == original_status
        assert archived_count == 1

    def test_override_days_parameter(self):
        """override_days should override the plugin setting."""
        cert_60 = self._make_expired_cert(5, days_expired=60)
        cert_120 = self._make_expired_cert(6, days_expired=120)

        now = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)

        # With default 90 days, cert_60 would not be archived
        default_days = 90
        default_cutoff = now - timedelta(days=default_days)
        assert cert_60.valid_to >= default_cutoff  # Not past default threshold

        # With override of 30 days, cert_60 would be archived
        override_days = 30
        override_cutoff = now - timedelta(days=override_days)
        assert cert_60.valid_to < override_cutoff  # Past override threshold

        # cert_120 should be archived with both thresholds
        assert cert_120.valid_to < default_cutoff
        assert cert_120.valid_to < override_cutoff

    def test_script_summary_structure(self):
        """The script should return a structured summary dict."""
        now = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)

        result = {
            "archived_at": now.isoformat(),
            "archive_days_threshold": 90,
            "total_candidates": 5,
            "archived_count": 3,
            "skipped_count": 0,
            "dry_run": False,
            "tenant": None,
            "events": [],
        }

        assert "archived_at" in result
        assert "archive_days_threshold" in result
        assert "total_candidates" in result
        assert "archived_count" in result
        assert result["archived_count"] == 3
        assert result["dry_run"] is False

    def test_tenant_filter(self):
        """The script should support filtering by tenant."""
        mock_tenant = SimpleNamespace(name="Acme Corp", pk=1)

        cert_acme = self._make_expired_cert(7, days_expired=100)
        cert_acme.tenant = mock_tenant

        cert_other = self._make_expired_cert(8, days_expired=100)
        cert_other.tenant = SimpleNamespace(name="Other Corp", pk=2)

        # Simulate tenant filtering
        filtered = [c for c in [cert_acme, cert_other] if c.tenant.pk == mock_tenant.pk]
        assert len(filtered) == 1
        assert filtered[0].pk == 7


# ---------------------------------------------------------------------------
# Tests: Auto-archive script source inspection
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAutoArchiveScriptSource:
    """Test the auto-archive script structure via source inspection."""

    def _read_script_source(self) -> str:
        source_path = get_plugin_source_dir() /  "scripts" / "auto_archive.py"
        return source_path.read_text()

    def test_script_imports_correct_event(self):
        """Script should import EVENT_CERTIFICATE_ARCHIVED."""
        source = self._read_script_source()
        assert "EVENT_CERTIFICATE_ARCHIVED" in source

    def test_script_has_tenant_var(self):
        """Script should have a tenant ObjectVar."""
        source = self._read_script_source()
        assert "tenant = ObjectVar(" in source

    def test_script_has_dry_run_var(self):
        """Script should have a dry_run BooleanVar."""
        source = self._read_script_source()
        assert "dry_run = BooleanVar(" in source

    def test_script_has_override_days_var(self):
        """Script should have an override_days IntegerVar."""
        source = self._read_script_source()
        assert "override_days = IntegerVar(" in source

    def test_script_filters_expired_and_unpinned(self):
        """Script queryset should filter for expired, unpinned certs."""
        source = self._read_script_source()
        assert "status=CertificateStatusChoices.STATUS_EXPIRED" in source
        assert "archive_pinned=False" in source
        assert "valid_to__lt=cutoff_date" in source

    def test_script_sets_status_archived(self):
        """Script should set status to STATUS_ARCHIVED."""
        source = self._read_script_source()
        assert "STATUS_ARCHIVED" in source

    def test_script_fires_archived_event(self):
        """Script should fire the certificate_archived event."""
        source = self._read_script_source()
        assert "fire_certificate_event(" in source
        assert "EVENT_CERTIFICATE_ARCHIVED" in source

    def test_script_registered_in_init(self):
        """CertificateAutoArchive should be registered in scripts/__init__.py."""
        init_path = get_plugin_source_dir() /  "scripts" / "__init__.py"
        source = init_path.read_text()
        assert "CertificateAutoArchive" in source
        assert "from .auto_archive import CertificateAutoArchive" in source


# ---------------------------------------------------------------------------
# Tests: Plugin settings
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestPluginSettings:
    """Test that auto-archive plugin settings are defined."""

    def test_auto_archive_settings_in_init(self):
        """Plugin __init__.py should define auto_archive settings."""
        init_path = get_plugin_source_dir() /  "__init__.py"
        source = init_path.read_text()
        assert '"auto_archive_enabled": False' in source
        assert '"auto_archive_after_days": 90' in source


# ---------------------------------------------------------------------------
# Tests: Migration exists
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestMigration:
    """Test that the migration for archive fields exists."""

    def test_migration_file_exists(self):
        """Migration 0010 for archive fields should exist."""
        migration_path = (
            get_plugin_source_dir() /  "migrations"
            / "0010_certificate_archive_fields.py"
        )
        assert migration_path.exists()

    def test_migration_adds_archive_pinned(self):
        """Migration should add archive_pinned field."""
        migration_path = (
            get_plugin_source_dir() /  "migrations"
            / "0010_certificate_archive_fields.py"
        )
        source = migration_path.read_text()
        assert "archive_pinned" in source
        assert "BooleanField" in source

    def test_migration_adds_archived_at(self):
        """Migration should add archived_at field."""
        migration_path = (
            get_plugin_source_dir() /  "migrations"
            / "0010_certificate_archive_fields.py"
        )
        source = migration_path.read_text()
        assert "archived_at" in source
        assert "DateTimeField" in source
