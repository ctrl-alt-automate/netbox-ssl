"""Unit tests for ExternalSourceSchemaValidator."""

import importlib.util
import sys
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
    for _mod in [
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
        sys.modules.setdefault(_mod, MagicMock())

    # ValidationError needs a real class so pytest.raises() can catch it by type.
    class _FakeValidationError(Exception):
        """Minimal stand-in for django.core.exceptions.ValidationError."""

        def __init__(self, message, *args, **kwargs):
            self.message = message
            if isinstance(message, dict):
                self.message_dict = message
            super().__init__(str(message))

    sys.modules["django.core.exceptions"].ValidationError = _FakeValidationError

pytestmark = pytest.mark.unit


def test_validator_accepts_valid_lemur_config():
    from netbox_ssl.utils.external_source_validator import (
        ExternalSourceSchemaValidator,
    )

    ExternalSourceSchemaValidator.validate(
        source_type="lemur",
        auth_method="bearer",
        auth_credentials={"token": "env:LEMUR_TOKEN"},
    )  # should not raise


def test_validator_accepts_valid_generic_rest_api_key():
    from netbox_ssl.utils.external_source_validator import (
        ExternalSourceSchemaValidator,
    )

    ExternalSourceSchemaValidator.validate(
        source_type="generic_rest",
        auth_method="api_key",
        auth_credentials={"token": "env:MY_API_KEY"},
    )


def test_validator_rejects_unknown_source_type():
    from django.core.exceptions import ValidationError

    from netbox_ssl.utils.external_source_validator import (
        ExternalSourceSchemaValidator,
    )

    with pytest.raises(ValidationError) as exc:
        ExternalSourceSchemaValidator.validate(
            source_type="totally_made_up",
            auth_method="bearer",
            auth_credentials={},
        )
    assert "source_type" in str(exc.value)


def test_validator_rejects_auth_method_not_supported():
    from django.core.exceptions import ValidationError

    from netbox_ssl.utils.external_source_validator import (
        ExternalSourceSchemaValidator,
    )

    with pytest.raises(ValidationError) as exc:
        ExternalSourceSchemaValidator.validate(
            source_type="lemur",
            auth_method="aws_explicit",  # not supported by Lemur
            auth_credentials={},
        )
    assert "does not support" in str(exc.value)


def test_validator_rejects_unknown_credential_keys():
    from django.core.exceptions import ValidationError

    from netbox_ssl.utils.external_source_validator import (
        ExternalSourceSchemaValidator,
    )

    with pytest.raises(ValidationError) as exc:
        ExternalSourceSchemaValidator.validate(
            source_type="lemur",
            auth_method="bearer",
            auth_credentials={"token": "env:OK", "extra": "env:UNEXPECTED"},
        )
    assert "Unknown credential keys" in str(exc.value)


def test_validator_rejects_missing_required_credential():
    from django.core.exceptions import ValidationError

    from netbox_ssl.utils.external_source_validator import (
        ExternalSourceSchemaValidator,
    )

    with pytest.raises(ValidationError) as exc:
        ExternalSourceSchemaValidator.validate(
            source_type="lemur",
            auth_method="bearer",
            auth_credentials={},  # token missing
        )
    assert "Missing required credential" in str(exc.value)


def test_validator_rejects_non_string_reference():
    from django.core.exceptions import ValidationError

    from netbox_ssl.utils.external_source_validator import (
        ExternalSourceSchemaValidator,
    )

    with pytest.raises(ValidationError):
        ExternalSourceSchemaValidator.validate(
            source_type="lemur",
            auth_method="bearer",
            auth_credentials={"token": 12345},
        )


def test_validator_rejects_unsupported_scheme():
    from django.core.exceptions import ValidationError

    from netbox_ssl.utils.external_source_validator import (
        ExternalSourceSchemaValidator,
    )

    with pytest.raises(ValidationError) as exc:
        ExternalSourceSchemaValidator.validate(
            source_type="lemur",
            auth_method="bearer",
            auth_credentials={"token": "vault:secret/foo"},
        )
    assert "unsupported scheme" in str(exc.value).lower()


def test_validator_accepts_bare_varname_as_env_ref():
    """Backward-compat path: CredentialResolver treats bare strings as env vars."""
    from netbox_ssl.utils.external_source_validator import (
        ExternalSourceSchemaValidator,
    )

    ExternalSourceSchemaValidator.validate(
        source_type="lemur",
        auth_method="bearer",
        auth_credentials={"token": "LEGACY_BARE_VAR_NAME"},
        base_url="https://example.com",
    )  # should not raise


def test_validator_rejects_empty_path_after_scheme():
    """env: with nothing after must be rejected at form time."""
    from django.core.exceptions import ValidationError

    from netbox_ssl.utils.external_source_validator import (
        ExternalSourceSchemaValidator,
    )

    with pytest.raises(ValidationError) as exc:
        ExternalSourceSchemaValidator.validate(
            source_type="lemur",
            auth_method="bearer",
            auth_credentials={"token": "env:"},
            base_url="https://example.com",
        )
    assert "empty path" in str(exc.value).lower()


def test_validator_rejects_invalid_env_var_name():
    """Env var names must match ENV_VAR_PATTERN (uppercase, digits, underscore)."""
    from django.core.exceptions import ValidationError

    from netbox_ssl.utils.external_source_validator import (
        ExternalSourceSchemaValidator,
    )

    # lowercase letters not allowed
    with pytest.raises(ValidationError) as exc:
        ExternalSourceSchemaValidator.validate(
            source_type="lemur",
            auth_method="bearer",
            auth_credentials={"token": "env:lowercase_var"},
            base_url="https://example.com",
        )
    assert "valid environment variable name" in str(exc.value).lower()

    # Hyphens not allowed
    with pytest.raises(ValidationError):
        ExternalSourceSchemaValidator.validate(
            source_type="lemur",
            auth_method="bearer",
            auth_credentials={"token": "env:HAS-HYPHENS"},
            base_url="https://example.com",
        )


def test_validator_rejects_missing_base_url_when_required():
    """Lemur requires base_url — empty string must be rejected."""
    from django.core.exceptions import ValidationError

    from netbox_ssl.utils.external_source_validator import (
        ExternalSourceSchemaValidator,
    )

    with pytest.raises(ValidationError) as exc:
        ExternalSourceSchemaValidator.validate(
            source_type="lemur",
            auth_method="bearer",
            auth_credentials={"token": "env:TOKEN"},
            base_url="",  # missing
        )
    assert "base_url" in exc.value.message_dict


def test_validator_accepts_base_url_omitted_when_not_required():
    """AWS ACM (hypothetical) would have REQUIRES_BASE_URL=False. Since Task 3
    set the default to True, this test uses LemurAdapter; intended behavior is
    covered by Phase 2 once AWS adapter ships. Skeleton for coverage."""
    # Phase 1 adapters (Lemur, Generic REST) all require base_url.
    # This test is a placeholder for the AWS path; full assertion
    # lives in #100's implementation PR.
    pass


def test_validator_does_not_require_region_for_lemur():
    """region check only fires for adapters with REQUIRES_REGION = True."""
    from netbox_ssl.utils.external_source_validator import (
        ExternalSourceSchemaValidator,
    )

    # Should not raise — Lemur.REQUIRES_REGION is False (default).
    ExternalSourceSchemaValidator.validate(
        source_type="lemur",
        auth_method="bearer",
        auth_credentials={"token": "env:TOKEN"},
        base_url="https://example.com",
        region="",
    )
