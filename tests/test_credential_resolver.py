"""
Unit tests for the CredentialResolver utility.

Tests credential reference resolution from environment variables
without requiring a running NetBox instance.
"""

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

from netbox_ssl.utils.credential_resolver import (
    CredentialResolveError,
    CredentialResolver,
)


@pytest.mark.unit
class TestCredentialResolver:
    """Test CredentialResolver.resolve() with various inputs."""

    def test_env_scheme_resolution(self):
        """Test env: scheme resolves environment variables."""
        with patch.dict(os.environ, {"MY_API_TOKEN": "secret123"}):
            result = CredentialResolver.resolve("env:MY_API_TOKEN")
            assert result == "secret123"

    def test_bare_string_resolution(self):
        """Test bare string (no scheme) is treated as env var name."""
        with patch.dict(os.environ, {"LEMUR_TOKEN": "lemur-secret"}):
            result = CredentialResolver.resolve("LEMUR_TOKEN")
            assert result == "lemur-secret"

    def test_invalid_env_var_name_rejected(self):
        """Test that invalid env var names are rejected."""
        with pytest.raises(CredentialResolveError, match="Invalid environment variable name"):
            CredentialResolver.resolve("env:invalid-name-with-dashes")

    def test_lowercase_env_var_rejected(self):
        """Test that lowercase env var names are rejected."""
        with pytest.raises(CredentialResolveError, match="Invalid environment variable name"):
            CredentialResolver.resolve("env:lowercase_var")

    def test_missing_env_var_raises_error(self):
        """Test that missing env var raises an error."""
        env = os.environ.copy()
        env.pop("NONEXISTENT_VAR_12345", None)
        with patch.dict(os.environ, env, clear=True), pytest.raises(CredentialResolveError, match="is not set"):
            CredentialResolver.resolve("env:NONEXISTENT_VAR_12345")

    def test_empty_reference_raises_error(self):
        """Test that empty reference raises an error."""
        with pytest.raises(CredentialResolveError, match="Empty credential reference"):
            CredentialResolver.resolve("")

    def test_unsupported_scheme_raises_error(self):
        """Test that unsupported schemes raise an error."""
        with pytest.raises(CredentialResolveError, match="Unsupported credential scheme"):
            CredentialResolver.resolve("vault:secret/data/token")

    def test_env_scheme_case_insensitive(self):
        """Test that the scheme is case-insensitive."""
        with patch.dict(os.environ, {"MY_TOKEN": "case-test"}):
            result = CredentialResolver.resolve("ENV:MY_TOKEN")
            assert result == "case-test"

    def test_supported_schemes_frozenset(self):
        """Test that SUPPORTED_SCHEMES is a frozenset."""
        assert isinstance(CredentialResolver.SUPPORTED_SCHEMES, frozenset)
        assert "env" in CredentialResolver.SUPPORTED_SCHEMES

    def test_env_var_with_underscore_prefix(self):
        """Test env var starting with underscore."""
        with patch.dict(os.environ, {"_PRIVATE_TOKEN": "underscore"}):
            result = CredentialResolver.resolve("env:_PRIVATE_TOKEN")
            assert result == "underscore"
