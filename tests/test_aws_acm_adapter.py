"""Unit tests for AwsAcmAdapter."""

import importlib.util
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

# Allow importing adapters directly without loading the full netbox_ssl package
# This enables running tests locally without NetBox installed
_project_root = Path(__file__).parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

# Mock netbox.plugins if not available (skip in Docker with real NetBox)
try:
    _spec = importlib.util.find_spec("netbox")
    _NETBOX_AVAILABLE = _spec is not None and _spec.origin is not None
except (ValueError, ModuleNotFoundError):
    _NETBOX_AVAILABLE = False

if not _NETBOX_AVAILABLE and "netbox" not in sys.modules:
    from unittest.mock import MagicMock

    sys.modules["netbox"] = MagicMock()
    sys.modules["netbox.plugins"] = MagicMock()


def test_aws_acm_adapter_class_exists():
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    assert AwsAcmAdapter.__name__ == "AwsAcmAdapter"


def test_aws_acm_adapter_supported_auth_methods():
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    assert AwsAcmAdapter.SUPPORTED_AUTH_METHODS == ("aws_explicit", "aws_instance_role")


def test_aws_acm_adapter_implicit_auth_methods():
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    assert AwsAcmAdapter.IMPLICIT_AUTH_METHODS == ("aws_instance_role",)


def test_aws_acm_adapter_requires_base_url_false():
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    assert AwsAcmAdapter.REQUIRES_BASE_URL is False


def test_aws_acm_adapter_requires_region_true():
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    assert AwsAcmAdapter.REQUIRES_REGION is True


def test_aws_acm_adapter_inherits_from_base_adapter():
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter
    from netbox_ssl.adapters.base import BaseAdapter

    assert issubclass(AwsAcmAdapter, BaseAdapter)


def test_credential_schema_aws_explicit_returns_three_fields():
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    schema = AwsAcmAdapter.credential_schema("aws_explicit")
    assert set(schema.keys()) == {"access_key_id", "secret_access_key", "session_token"}


def test_credential_schema_aws_explicit_required_and_secret_flags():
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    schema = AwsAcmAdapter.credential_schema("aws_explicit")
    assert schema["access_key_id"].required is True
    assert schema["access_key_id"].secret is True
    assert schema["secret_access_key"].required is True
    assert schema["secret_access_key"].secret is True
    assert schema["session_token"].required is False
    assert schema["session_token"].secret is True


def test_credential_schema_aws_instance_role_returns_empty():
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    schema = AwsAcmAdapter.credential_schema("aws_instance_role")
    assert schema == {}


def test_credential_schema_rejects_unsupported_method():
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    with pytest.raises(ValueError, match="does not support"):
        AwsAcmAdapter.credential_schema("bearer")


def test_map_acm_status_issued_to_active():
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    assert AwsAcmAdapter._map_acm_status("ISSUED") == "active"


def test_map_acm_status_expired_to_expired():
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    assert AwsAcmAdapter._map_acm_status("EXPIRED") == "expired"


def test_map_acm_status_revoked_to_revoked():
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    assert AwsAcmAdapter._map_acm_status("REVOKED") == "revoked"


def test_map_acm_status_pending_validation_to_pending():
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    assert AwsAcmAdapter._map_acm_status("PENDING_VALIDATION") == "pending"


def test_map_acm_status_failed_returns_none():
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    assert AwsAcmAdapter._map_acm_status("FAILED") is None


def test_map_acm_status_inactive_returns_none():
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    assert AwsAcmAdapter._map_acm_status("INACTIVE") is None


def test_map_acm_status_validation_timed_out_returns_none():
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    assert AwsAcmAdapter._map_acm_status("VALIDATION_TIMED_OUT") is None


def test_map_acm_status_unknown_returns_none():
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    assert AwsAcmAdapter._map_acm_status("BOGUS_STATUS") is None
