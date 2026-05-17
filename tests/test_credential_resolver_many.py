"""Unit tests for CredentialResolver.resolve_many()."""

import importlib.util
import os
import sys
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

pytestmark = pytest.mark.unit


def test_resolve_many_empty_dict_returns_empty_dict():
    from netbox_ssl.utils.credential_resolver import CredentialResolver

    assert CredentialResolver.resolve_many({}) == {}


def test_resolve_many_resolves_each_env_ref():
    from netbox_ssl.utils.credential_resolver import CredentialResolver

    refs = {"access_key_id": "env:TEST_KEY_ID", "secret_access_key": "env:TEST_SECRET"}
    with patch.dict(os.environ, {"TEST_KEY_ID": "AKIATEST", "TEST_SECRET": "secretval"}):
        result = CredentialResolver.resolve_many(refs)
    assert result == {"access_key_id": "AKIATEST", "secret_access_key": "secretval"}


def test_resolve_many_accepts_bare_varname_as_env():
    from netbox_ssl.utils.credential_resolver import CredentialResolver

    refs = {"token": "LEGACY_BARE_VAR"}
    with patch.dict(os.environ, {"LEGACY_BARE_VAR": "legacy_value"}):
        result = CredentialResolver.resolve_many(refs)
    assert result == {"token": "legacy_value"}


def test_resolve_many_fails_fast_on_missing_env_var():
    from netbox_ssl.utils.credential_resolver import (
        CredentialResolveError,
        CredentialResolver,
    )

    refs = {"present": "env:PRESENT_VAR", "missing": "env:MISSING_VAR_12345"}
    with patch.dict(os.environ, {"PRESENT_VAR": "x"}, clear=False):
        os.environ.pop("MISSING_VAR_12345", None)
        with pytest.raises(CredentialResolveError, match="MISSING_VAR_12345"):
            CredentialResolver.resolve_many(refs)


def test_resolve_many_rejects_unsupported_scheme():
    from netbox_ssl.utils.credential_resolver import (
        CredentialResolveError,
        CredentialResolver,
    )

    refs = {"token": "vault:secret/foo"}
    with pytest.raises(CredentialResolveError, match="Unsupported"):
        CredentialResolver.resolve_many(refs)
