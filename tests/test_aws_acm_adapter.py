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


def test_build_client_kwargs_aws_explicit_minimal():
    """Explicit creds with only required fields (no session_token)."""
    import os
    from unittest.mock import MagicMock, patch
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    source = MagicMock()
    source.region = "eu-west-1"
    source.auth_method = "aws_explicit"
    source.auth_credentials = {
        "access_key_id": "env:TEST_AKID",
        "secret_access_key": "env:TEST_SECRET",
    }
    adapter = AwsAcmAdapter(source)

    with patch.dict(os.environ, {"TEST_AKID": "AKIATEST", "TEST_SECRET": "secretval"}):
        kwargs = adapter._build_client_kwargs()

    assert kwargs == {
        "region_name": "eu-west-1",
        "aws_access_key_id": "AKIATEST",
        "aws_secret_access_key": "secretval",
    }


def test_build_client_kwargs_aws_explicit_with_session_token():
    """Explicit creds with optional session_token."""
    import os
    from unittest.mock import MagicMock, patch
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    source = MagicMock()
    source.region = "us-east-1"
    source.auth_method = "aws_explicit"
    source.auth_credentials = {
        "access_key_id": "env:TEST_AKID",
        "secret_access_key": "env:TEST_SECRET",
        "session_token": "env:TEST_SESSION",
    }
    adapter = AwsAcmAdapter(source)

    with patch.dict(os.environ, {
        "TEST_AKID": "AKIATEST",
        "TEST_SECRET": "secretval",
        "TEST_SESSION": "sessionval",
    }):
        kwargs = adapter._build_client_kwargs()

    assert kwargs == {
        "region_name": "us-east-1",
        "aws_access_key_id": "AKIATEST",
        "aws_secret_access_key": "secretval",
        "aws_session_token": "sessionval",
    }


def test_build_client_kwargs_aws_instance_role_omits_credentials():
    """Instance-role auth: only region, no credential kwargs."""
    from unittest.mock import MagicMock
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    source = MagicMock()
    source.region = "ap-southeast-2"
    source.auth_method = "aws_instance_role"
    source.auth_credentials = {}
    adapter = AwsAcmAdapter(source)

    kwargs = adapter._build_client_kwargs()

    assert kwargs == {"region_name": "ap-southeast-2"}


def test_get_client_builds_lazily():
    """First call builds the client; second call returns the cached one."""
    from unittest.mock import MagicMock, patch
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    source = MagicMock()
    source.region = "eu-west-1"
    source.auth_method = "aws_instance_role"
    source.auth_credentials = {}
    adapter = AwsAcmAdapter(source)

    assert adapter._client is None  # not built yet

    with patch("netbox_ssl.adapters.aws_acm.boto3.client") as mock_client_factory:
        mock_client_factory.return_value = MagicMock(name="acm_client")
        client1 = adapter._get_client()
        client2 = adapter._get_client()

    assert client1 is client2  # cached
    assert mock_client_factory.call_count == 1  # built only once
    mock_client_factory.assert_called_once_with("acm", region_name="eu-west-1")


def test_get_client_passes_explicit_credentials():
    """boto3.client called with credential kwargs when aws_explicit."""
    import os
    from unittest.mock import MagicMock, patch
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    source = MagicMock()
    source.region = "eu-west-1"
    source.auth_method = "aws_explicit"
    source.auth_credentials = {
        "access_key_id": "env:T_AKID",
        "secret_access_key": "env:T_SECRET",
    }
    adapter = AwsAcmAdapter(source)

    with patch.dict(os.environ, {"T_AKID": "AKIA", "T_SECRET": "shh"}):
        with patch("netbox_ssl.adapters.aws_acm.boto3.client") as mock_factory:
            adapter._get_client()

    mock_factory.assert_called_once_with(
        "acm",
        region_name="eu-west-1",
        aws_access_key_id="AKIA",
        aws_secret_access_key="shh",
    )


def test_assert_no_prohibited_keys_clean_response_passes():
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    clean_response = {"CertificateArn": "arn:aws:acm:...", "DomainName": "example.com"}
    # Should not raise
    AwsAcmAdapter._assert_no_prohibited_keys(clean_response)


def test_assert_no_prohibited_keys_with_private_key_raises():
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    dirty_response = {"CertificateArn": "arn:aws:acm:...", "private_key": "-----BEGIN..."}
    with pytest.raises(ValueError, match="failed safety check"):
        AwsAcmAdapter._assert_no_prohibited_keys(dirty_response)


def test_assert_no_prohibited_keys_case_insensitive():
    """PROHIBITED_SYNC_FIELDS is lowercase; check normalises response keys."""
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    dirty_response = {"PRIVATE_KEY": "..."}  # uppercase version
    with pytest.raises(ValueError, match="failed safety check"):
        AwsAcmAdapter._assert_no_prohibited_keys(dirty_response)


def test_assert_no_prohibited_keys_pem_bundle_aws_alias_raises():
    """v1.1 PROHIBITED_SYNC_FIELDS includes pem_bundle (AWS ACM alias)."""
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    dirty_response = {"pem_bundle": "..."}
    with pytest.raises(ValueError, match="failed safety check"):
        AwsAcmAdapter._assert_no_prohibited_keys(dirty_response)
