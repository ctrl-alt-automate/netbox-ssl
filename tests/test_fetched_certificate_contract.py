"""The shared adapter contract must grow without changing existing behaviour.

`FetchedCertificate` is consumed by four adapters and by the sync engine. Fields
added for Azure Key Vault (#101) carry defaults that reproduce exactly what the
engine did before they existed, so Lemur, Generic REST and AWS ACM keep working
untouched.
"""

import importlib.util
import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.unit

# ---------------------------------------------------------------------------
# Mock Django/NetBox before importing plugin code (host lane: NetBox is not
# installed, so `netbox_ssl.adapters.base` -> `netbox_ssl/__init__.py` ->
# `netbox.plugins` must be stubbed out; skipped inside Docker where the real
# netbox package is importable).
# ---------------------------------------------------------------------------
try:
    _spec = importlib.util.find_spec("netbox")
    _NETBOX_AVAILABLE = _spec is not None and _spec.origin is not None
except (ValueError, ModuleNotFoundError):
    _NETBOX_AVAILABLE = False

if not _NETBOX_AVAILABLE:
    for _mod in [
        "django",
        "django.conf",
        "django.db",
        "django.db.models",
        "django.db.models.functions",
        "django.utils",
        "django.utils.timezone",
        "django.utils.translation",
        "netbox",
        "netbox.plugins",
    ]:
        sys.modules.setdefault(_mod, MagicMock())

from netbox_ssl.adapters.base import FetchedCertificate  # noqa: E402


def _minimal() -> FetchedCertificate:
    """Build a FetchedCertificate using only the pre-#101 required fields."""
    return FetchedCertificate(
        external_id="https://kv.vault.azure.net/certificates/example",
        common_name="a.example.com",
        serial_number="01:02:03",
        fingerprint_sha256="AA:BB:CC",
        issuer="Test CA",
        valid_from=datetime(2026, 1, 1, tzinfo=timezone.utc),
        valid_to=datetime(2027, 1, 1, tzinfo=timezone.utc),
    )


def test_new_fields_default_to_no_opinion():
    """Every default must be distinguishable from a real adapter-supplied value.

    `certificate_type` defaults to None rather than "server" so the engine can
    tell "this adapter does not know" from "this adapter says server". Without
    that distinction, updating a Lemur / Generic REST / AWS ACM certificate
    reverts an operator's `mtls` override to `server` on every sync.
    """
    fetched = _minimal()
    assert fetched.tags == ()
    assert fetched.certificate_type is None
    assert fetched.status is None


def test_new_fields_are_settable():
    fetched = FetchedCertificate(
        external_id="x",
        common_name="a.example.com",
        serial_number="01",
        fingerprint_sha256="AA",
        issuer="CA",
        valid_from=datetime(2026, 1, 1, tzinfo=timezone.utc),
        valid_to=datetime(2027, 1, 1, tzinfo=timezone.utc),
        tags=("env=prod", "owner=team-a"),
        certificate_type="mtls",
        status="archived",
    )
    assert fetched.tags == ("env=prod", "owner=team-a")
    assert fetched.certificate_type == "mtls"
    assert fetched.status == "archived"


def test_existing_adapters_construct_without_the_new_fields():
    """Guard the whole point: no adapter is forced to know about them."""
    import inspect

    from netbox_ssl.adapters.base import FetchedCertificate as FC

    params = inspect.signature(FC).parameters
    for name in ("tags", "certificate_type", "status"):
        assert params[name].default is not inspect.Parameter.empty, (
            f"{name} must have a default, or existing adapters break"
        )
