"""
Unit tests for the sync engine.

Tests the build_plan and execute_plan logic for diffing and applying
external source certificate data without requiring a running NetBox instance.
"""

import importlib.util
import sys
from datetime import datetime, timezone
from types import SimpleNamespace
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

if not _NETBOX_AVAILABLE and "netbox" not in sys.modules:
    _django_utils_timezone = MagicMock()
    _django_utils_timezone.now.return_value = datetime(2026, 3, 22, 12, 0, 0, tzinfo=timezone.utc)

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
        "netbox",
        "netbox.models",
        "netbox.plugins",
        "utilities",
        "utilities.choices",
    ]:
        sys.modules.setdefault(mod, MagicMock())
    sys.modules["django.utils.timezone"] = _django_utils_timezone

from netbox_ssl.adapters.base import FetchedCertificate
from netbox_ssl.utils.sync_engine import SyncAction, SyncPlan, build_plan


def _make_fetched(
    external_id: str = "ext-1",
    common_name: str = "example.com",
    serial_number: str = "AABB",
    fingerprint_sha256: str = "AA:BB:CC",
    issuer: str = "Test CA",
    **kwargs,
) -> FetchedCertificate:
    """Helper to create a FetchedCertificate for testing."""
    return FetchedCertificate(
        external_id=external_id,
        common_name=common_name,
        serial_number=serial_number,
        fingerprint_sha256=fingerprint_sha256,
        issuer=issuer,
        valid_from=datetime(2026, 1, 1, tzinfo=timezone.utc),
        valid_to=datetime(2027, 1, 1, tzinfo=timezone.utc),
        **kwargs,
    )


def _make_local_cert(
    pk: int = 1,
    external_id: str = "ext-1",
    common_name: str = "example.com",
    serial_number: str = "AABB",
    fingerprint_sha256: str = "AA:BB:CC",
    issuer: str = "Test CA",
    source_removed: bool = False,
    pem_content: str = "",
    issuer_chain: str = "",
    key_size: int | None = None,
    algorithm: str = "unknown",
) -> SimpleNamespace:
    """Helper to create a mock local certificate for testing."""
    return SimpleNamespace(
        pk=pk,
        external_id=external_id,
        common_name=common_name,
        serial_number=serial_number,
        fingerprint_sha256=fingerprint_sha256,
        issuer=issuer,
        source_removed=source_removed,
        pem_content=pem_content,
        issuer_chain=issuer_chain,
        key_size=key_size,
        algorithm=algorithm,
    )


@pytest.mark.unit
class TestSyncAction:
    """Test SyncAction dataclass."""

    def test_create_action(self):
        """Test creating a SyncAction."""
        action = SyncAction(
            action="create",
            external_id="ext-1",
            fetched=_make_fetched(),
            local_cert_id=None,
            reason="New certificate",
        )
        assert action.action == "create"
        assert action.external_id == "ext-1"
        assert action.local_cert_id is None
        assert action.reason == "New certificate"

    def test_sync_action_is_frozen(self):
        """Test that SyncAction is immutable."""
        action = SyncAction(
            action="create",
            external_id="ext-1",
            fetched=None,
            local_cert_id=None,
            reason="test",
        )
        with pytest.raises(AttributeError):
            action.action = "update"


@pytest.mark.unit
class TestSyncPlan:
    """Test SyncPlan dataclass."""

    def test_empty_plan(self):
        """Test empty plan has no changes."""
        plan = SyncPlan()
        assert plan.total_changes == 0
        assert plan.unchanged == 0

    def test_total_changes(self):
        """Test total_changes calculation."""
        plan = SyncPlan()
        plan.creates.append(SyncAction("create", "1", None, None, "new"))
        plan.updates.append(SyncAction("update", "2", None, 1, "updated"))
        plan.renewals.append(SyncAction("renew", "3", None, 2, "renewed"))
        plan.removals.append(SyncAction("mark_removed", "4", None, 3, "removed"))
        plan.unchanged = 5

        assert plan.total_changes == 4  # excludes unchanged
        assert plan.unchanged == 5

    def test_plan_defaults(self):
        """Test SyncPlan default values."""
        plan = SyncPlan()
        assert plan.creates == []
        assert plan.updates == []
        assert plan.renewals == []
        assert plan.removals == []
        assert plan.unchanged == 0


@pytest.mark.unit
class TestBuildPlan:
    """Test build_plan logic for diffing fetched vs local certificates."""

    def test_new_cert_creates(self):
        """Test that a new certificate results in a create action."""
        fetched = [_make_fetched(external_id="new-1")]
        local_qs = []
        source = SimpleNamespace(name="test-source")

        plan = build_plan(fetched, local_qs, source)

        assert len(plan.creates) == 1
        assert plan.creates[0].action == "create"
        assert plan.creates[0].external_id == "new-1"
        assert plan.unchanged == 0

    def test_matching_external_id_unchanged(self):
        """Test that matching external_id with same serial is unchanged."""
        fetched = [_make_fetched(external_id="ext-1", serial_number="AABB")]
        local = [_make_local_cert(pk=1, external_id="ext-1", serial_number="AABB")]
        source = SimpleNamespace(name="test-source")

        plan = build_plan(fetched, local, source)

        assert len(plan.creates) == 0
        assert len(plan.updates) == 0
        assert len(plan.renewals) == 0
        assert plan.unchanged == 1

    def test_matching_external_id_different_serial_renewal(self):
        """Test that same external_id + different serial triggers renewal."""
        fetched = [_make_fetched(external_id="ext-1", serial_number="CCDD")]
        local = [_make_local_cert(pk=1, external_id="ext-1", serial_number="AABB")]
        source = SimpleNamespace(name="test-source")

        plan = build_plan(fetched, local, source)

        assert len(plan.renewals) == 1
        assert plan.renewals[0].action == "renew"
        assert "Serial changed" in plan.renewals[0].reason

    def test_matching_external_id_metadata_diff_update(self):
        """Test that same external_id + metadata change triggers update."""
        fetched = [
            _make_fetched(
                external_id="ext-1",
                serial_number="AABB",
                common_name="updated.example.com",
            )
        ]
        local = [
            _make_local_cert(
                pk=1,
                external_id="ext-1",
                serial_number="AABB",
                common_name="example.com",
            )
        ]
        source = SimpleNamespace(name="test-source")

        plan = build_plan(fetched, local, source)

        assert len(plan.updates) == 1
        assert plan.updates[0].action == "update"
        assert plan.updates[0].reason == "Metadata changed"

    def test_missing_cert_mark_removed(self):
        """Test that local certs not in fetched are marked removed."""
        fetched = []
        local = [_make_local_cert(pk=1, external_id="ext-1")]
        source = SimpleNamespace(name="test-source")

        plan = build_plan(fetched, local, source)

        assert len(plan.removals) == 1
        assert plan.removals[0].action == "mark_removed"
        assert plan.removals[0].local_cert_id == 1

    def test_already_removed_not_removed_again(self):
        """Test that already-removed certs are not removed again."""
        fetched = []
        local = [_make_local_cert(pk=1, external_id="ext-1", source_removed=True)]
        source = SimpleNamespace(name="test-source")

        plan = build_plan(fetched, local, source)

        assert len(plan.removals) == 0

    def test_fingerprint_match_links_existing(self):
        """Test that fingerprint match on new external_id links existing cert."""
        fetched = [
            _make_fetched(
                external_id="new-ext-id",
                serial_number="AABB",
                fingerprint_sha256="AA:BB:CC",
            )
        ]
        local = [
            _make_local_cert(
                pk=1,
                external_id="old-ext-id",
                serial_number="AABB",
                fingerprint_sha256="AA:BB:CC",
            )
        ]
        source = SimpleNamespace(name="test-source")

        plan = build_plan(fetched, local, source)

        # Should be treated as unchanged or update (fingerprint match)
        # Since external_id differs but serial is same, it won't be renewal
        # The fingerprint match links it, and since metadata matches, it's unchanged
        assert plan.unchanged == 1 or len(plan.updates) == 1

    def test_multiple_certs_mixed_plan(self):
        """Test plan with multiple certificates of different types."""
        fetched = [
            _make_fetched(external_id="new-1", serial_number="1111", fingerprint_sha256="11:11"),
            _make_fetched(external_id="ext-2", serial_number="2222", fingerprint_sha256="22:22"),
            _make_fetched(external_id="ext-3", serial_number="NEW_SERIAL", fingerprint_sha256="33:33"),
        ]
        local = [
            _make_local_cert(pk=2, external_id="ext-2", serial_number="2222", fingerprint_sha256="22:22"),
            _make_local_cert(pk=3, external_id="ext-3", serial_number="3333", fingerprint_sha256="33:33:old"),
            _make_local_cert(pk=4, external_id="ext-4", serial_number="4444", fingerprint_sha256="44:44"),
        ]
        source = SimpleNamespace(name="test-source")

        plan = build_plan(fetched, local, source)

        assert len(plan.creates) == 1  # new-1
        assert plan.unchanged == 1  # ext-2
        assert len(plan.renewals) == 1  # ext-3 (different serial)
        assert len(plan.removals) == 1  # ext-4 (not in fetched)
