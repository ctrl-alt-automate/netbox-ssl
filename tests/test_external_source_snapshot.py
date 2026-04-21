"""Unit tests for ExternalSource.snapshot() credential scrubbing."""

import importlib.util
from unittest.mock import MagicMock, patch

import pytest

pytestmark = pytest.mark.unit

try:
    _spec = importlib.util.find_spec("netbox")
    _NETBOX_AVAILABLE = _spec is not None and _spec.origin is not None
except (ValueError, ModuleNotFoundError):
    _NETBOX_AVAILABLE = False


def _make_source_and_call_snapshot(auth_credentials=None, auth_ref=""):
    """Build a mocked ExternalSource, call snapshot(), return the prechange dict.

    Simulates NetBox's contract: super().snapshot() sets
    self._prechange_snapshot; returns None.
    """
    from netbox_ssl.models.external_source import ExternalSource

    source = MagicMock(spec=ExternalSource)
    source.auth_credentials = auth_credentials or {}
    source.auth_credentials_reference = auth_ref
    source._prechange_snapshot = None

    base_snapshot = {
        "name": "test-source",
        "auth_credentials": source.auth_credentials,
        "auth_credentials_reference": source.auth_credentials_reference,
    }

    def _side_effect(self=source):
        source._prechange_snapshot = base_snapshot

    with patch("netbox_ssl.models.external_source.NetBoxModel.snapshot", side_effect=_side_effect):
        ExternalSource.snapshot(source)

    return source._prechange_snapshot


@pytest.mark.skipif(not _NETBOX_AVAILABLE, reason="NetBox not available locally (tests run in Docker CI)")
def test_snapshot_redacts_auth_credentials_values():
    result = _make_source_and_call_snapshot(
        auth_credentials={"access_key_id": "env:AWS_KEY", "secret_access_key": "env:AWS_SECRET"},
    )
    assert result["auth_credentials"] == {
        "access_key_id": "<redacted>",
        "secret_access_key": "<redacted>",
    }


@pytest.mark.skipif(not _NETBOX_AVAILABLE, reason="NetBox not available locally (tests run in Docker CI)")
def test_snapshot_preserves_keys_for_audit():
    """Key additions/removals must be visible in diffs; values are not."""
    result = _make_source_and_call_snapshot(auth_credentials={"token": "env:FOO"})
    assert "token" in result["auth_credentials"]
    assert result["auth_credentials"]["token"] == "<redacted>"


@pytest.mark.skipif(not _NETBOX_AVAILABLE, reason="NetBox not available locally (tests run in Docker CI)")
def test_snapshot_redacts_legacy_reference():
    result = _make_source_and_call_snapshot(auth_ref="env:OLD_TOKEN")
    assert result["auth_credentials_reference"] == "<redacted>"


@pytest.mark.skipif(not _NETBOX_AVAILABLE, reason="NetBox not available locally (tests run in Docker CI)")
def test_snapshot_leaves_empty_reference_empty():
    result = _make_source_and_call_snapshot(auth_ref="")
    assert result["auth_credentials_reference"] == ""


@pytest.mark.skipif(not _NETBOX_AVAILABLE, reason="NetBox not available locally (tests run in Docker CI)")
def test_snapshot_empty_credentials_dict_stays_empty():
    result = _make_source_and_call_snapshot(auth_credentials={})
    assert result["auth_credentials"] == {}


@pytest.mark.skipif(not _NETBOX_AVAILABLE, reason="NetBox not available locally (tests run in Docker CI)")
def test_snapshot_never_leaks_env_var_names():
    """Full security assertion: no env var name must appear in the snapshot."""
    result = _make_source_and_call_snapshot(
        auth_credentials={"token": "env:SUPER_SECRET_VAR_NAME"},
        auth_ref="env:ANOTHER_SECRET",
    )
    snapshot_repr = str(result)
    assert "SUPER_SECRET_VAR_NAME" not in snapshot_repr
    assert "ANOTHER_SECRET" not in snapshot_repr
