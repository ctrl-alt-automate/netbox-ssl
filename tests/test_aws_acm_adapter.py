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

# Add tests/ dir so cert_factory can be imported as a top-level module
_tests_dir = Path(__file__).parent
if str(_tests_dir) not in sys.path:
    sys.path.insert(0, str(_tests_dir))

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

    with patch.dict(
        os.environ,
        {
            "TEST_AKID": "AKIATEST",
            "TEST_SECRET": "secretval",
            "TEST_SESSION": "sessionval",
        },
    ):
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

    with (
        patch.dict(os.environ, {"T_AKID": "AKIA", "T_SECRET": "shh"}),
        patch("netbox_ssl.adapters.aws_acm.boto3.client") as mock_factory,
    ):
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


# ---------------------------------------------------------------------------
# _parse_acm_certificate() tests
# ---------------------------------------------------------------------------


def _make_describe_response(**overrides):
    """Build a realistic DescribeCertificate response dict with sensible defaults."""
    from datetime import datetime, timezone

    base = {
        "CertificateArn": "arn:aws:acm:eu-west-1:123456789012:certificate/abc-def-ghi",
        "DomainName": "example.com",
        "SubjectAlternativeNames": ["example.com", "www.example.com"],
        "NotBefore": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "NotAfter": datetime(2027, 1, 1, tzinfo=timezone.utc),
        "Status": "ISSUED",
        "Issuer": "Amazon",
        "Serial": "0a:1b:2c:3d:4e:5f",
        "KeyAlgorithm": "RSA_2048",
        "Type": "AMAZON_ISSUED",
    }
    base.update(overrides)
    return {"Certificate": base}


def _make_get_response(pem: str, chain: str = "") -> dict:
    """Build a realistic GetCertificate response dict."""
    return {"Certificate": pem, "CertificateChain": chain}


def test_parse_acm_certificate_happy_path_amazon_issued():
    from cert_factory import CertFactory

    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    pem = CertFactory.create(cn="example.com", sans=["www.example.com"])
    chain_pem = CertFactory.create(cn="Test CA", issuer_cn="Test Root")
    describe = _make_describe_response()
    get = _make_get_response(pem=pem, chain=chain_pem)

    cert = AwsAcmAdapter._parse_acm_certificate(describe, get)

    assert cert is not None
    assert cert.external_id == "arn:aws:acm:eu-west-1:123456789012:certificate/abc-def-ghi"
    assert cert.common_name == "example.com"
    assert cert.serial_number == "0a:1b:2c:3d:4e:5f"
    assert cert.issuer == "Amazon"
    assert cert.algorithm == "rsa"
    assert cert.key_size == 2048
    assert cert.pem_content == pem
    assert cert.issuer_chain == chain_pem
    assert cert.sans == ("example.com", "www.example.com")
    # SHA256 fingerprint in uppercase colon-separated form to match CertificateParser._calculate_fingerprint
    assert len(cert.fingerprint_sha256) == 95  # 32 bytes × 2 hex + 31 colons
    assert cert.fingerprint_sha256.count(":") == 31
    assert cert.fingerprint_sha256.upper() == cert.fingerprint_sha256  # uppercase


def test_parse_acm_certificate_imported_no_chain():
    """IMPORTED certs may have empty CertificateChain — handle gracefully."""
    from cert_factory import CertFactory

    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    pem = CertFactory.create(cn="imported.example.com")
    describe = _make_describe_response(Type="IMPORTED")
    get = _make_get_response(pem=pem, chain="")  # no chain

    cert = AwsAcmAdapter._parse_acm_certificate(describe, get)

    assert cert is not None
    assert cert.issuer_chain == ""


def test_parse_acm_certificate_skips_failed_status():
    from cert_factory import CertFactory

    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    pem = CertFactory.create(cn="failed.example.com")
    describe = _make_describe_response(Status="FAILED")
    get = _make_get_response(pem=pem)

    assert AwsAcmAdapter._parse_acm_certificate(describe, get) is None


def test_parse_acm_certificate_skips_inactive_status():
    from cert_factory import CertFactory

    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    pem = CertFactory.create(cn="inactive.example.com")
    describe = _make_describe_response(Status="INACTIVE")
    get = _make_get_response(pem=pem)

    assert AwsAcmAdapter._parse_acm_certificate(describe, get) is None


def test_parse_acm_certificate_ecdsa_algorithm():
    from cert_factory import CertFactory

    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    pem = CertFactory.create(cn="ecdsa.example.com")
    describe = _make_describe_response(KeyAlgorithm="EC_prime256v1")
    get = _make_get_response(pem=pem)

    cert = AwsAcmAdapter._parse_acm_certificate(describe, get)

    assert cert is not None
    assert cert.algorithm == "ecdsa"
    assert cert.key_size is None  # ECDSA doesn't carry a parseable size in KeyAlgorithm


def test_parse_acm_certificate_rsa_4096():
    from cert_factory import CertFactory

    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    pem = CertFactory.create(cn="rsa4k.example.com")
    describe = _make_describe_response(KeyAlgorithm="RSA_4096")
    get = _make_get_response(pem=pem)

    cert = AwsAcmAdapter._parse_acm_certificate(describe, get)

    assert cert is not None
    assert cert.algorithm == "rsa"
    assert cert.key_size == 4096


def test_parse_acm_certificate_invalid_pem_returns_none():
    """If PEM is unparseable, return None (skip cert) rather than raise."""
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    describe = _make_describe_response()
    get = _make_get_response(pem="-----BEGIN CERTIFICATE-----\nNOT-VALID\n-----END CERTIFICATE-----")

    assert AwsAcmAdapter._parse_acm_certificate(describe, get) is None


def test_parse_acm_certificate_missing_optional_fields():
    """Defensive parsing: missing SANs / Issuer / Serial — use sensible defaults."""
    from datetime import datetime, timezone

    from cert_factory import CertFactory

    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    pem = CertFactory.create(cn="minimal.example.com")
    # describe response with only the essentials
    describe = {
        "Certificate": {
            "CertificateArn": "arn:aws:acm:eu-west-1:000:certificate/min",
            "DomainName": "minimal.example.com",
            "NotBefore": datetime(2026, 1, 1, tzinfo=timezone.utc),
            "NotAfter": datetime(2027, 1, 1, tzinfo=timezone.utc),
            "Status": "ISSUED",
            "KeyAlgorithm": "RSA_2048",
            # No SANs, no Issuer, no Serial
        }
    }
    get = _make_get_response(pem=pem)

    cert = AwsAcmAdapter._parse_acm_certificate(describe, get)

    assert cert is not None
    assert cert.sans == ()
    assert cert.issuer == ""
    assert cert.serial_number == ""


def test_list_certificate_arns_empty_account():
    from unittest.mock import MagicMock

    from moto import mock_aws

    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    @mock_aws
    def run():
        source = MagicMock()
        source.region = "eu-west-1"
        source.auth_method = "aws_instance_role"
        source.auth_credentials = {}
        adapter = AwsAcmAdapter(source)

        arns = list(adapter._list_certificate_arns())
        return arns

    assert run() == []


def test_list_certificate_arns_single_cert():
    from unittest.mock import MagicMock

    import boto3
    from cert_factory import CertFactory
    from moto import mock_aws

    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    @mock_aws
    def run():
        client = boto3.client("acm", region_name="eu-west-1")
        pem = CertFactory.create(cn="single.example.com")
        # Use any non-empty private key — moto only validates basic shape
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key_pem = (
            rsa.generate_private_key(public_exponent=65537, key_size=2048)
            .private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            .decode()
        )
        client.import_certificate(Certificate=pem.encode(), PrivateKey=key_pem.encode())

        source = MagicMock()
        source.region = "eu-west-1"
        source.auth_method = "aws_instance_role"
        source.auth_credentials = {}
        adapter = AwsAcmAdapter(source)
        return list(adapter._list_certificate_arns())

    arns = run()
    assert len(arns) == 1
    assert arns[0].startswith("arn:aws:acm:eu-west-1:")


# ---------------------------------------------------------------------------
# _describe_and_get() tests
# ---------------------------------------------------------------------------


def test_describe_and_get_happy_path():
    from unittest.mock import MagicMock

    import boto3
    from cert_factory import CertFactory
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from moto import mock_aws

    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    @mock_aws
    def run():
        client = boto3.client("acm", region_name="eu-west-1")
        pem = CertFactory.create(cn="happy.example.com")
        key_pem = (
            rsa.generate_private_key(public_exponent=65537, key_size=2048)
            .private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            .decode()
        )
        arn = client.import_certificate(Certificate=pem.encode(), PrivateKey=key_pem.encode())["CertificateArn"]

        source = MagicMock()
        source.region = "eu-west-1"
        source.auth_method = "aws_instance_role"
        source.auth_credentials = {}
        adapter = AwsAcmAdapter(source)
        return adapter._describe_and_get(arn)

    cert = run()
    assert cert is not None
    assert cert.common_name == "happy.example.com"


def test_describe_and_get_returns_none_on_describe_client_error():
    """Per-cert ClientError on DescribeCertificate → return None (skip)."""
    from unittest.mock import MagicMock, patch

    from botocore.exceptions import ClientError

    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    source = MagicMock()
    source.region = "eu-west-1"
    source.auth_method = "aws_instance_role"
    source.auth_credentials = {}
    adapter = AwsAcmAdapter(source)

    mock_client = MagicMock()
    mock_client.describe_certificate.side_effect = ClientError(
        error_response={"Error": {"Code": "ResourceNotFoundException", "Message": "Cert deleted"}},
        operation_name="DescribeCertificate",
    )
    with patch.object(adapter, "_get_client", return_value=mock_client):
        result = adapter._describe_and_get("arn:aws:acm:eu-west-1:000:certificate/missing")

    assert result is None


def test_describe_and_get_returns_none_on_get_client_error():
    """Per-cert ClientError on GetCertificate → return None (skip)."""
    from datetime import datetime, timezone
    from unittest.mock import MagicMock, patch

    from botocore.exceptions import ClientError

    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    source = MagicMock()
    source.region = "eu-west-1"
    source.auth_method = "aws_instance_role"
    source.auth_credentials = {}
    adapter = AwsAcmAdapter(source)

    mock_client = MagicMock()
    mock_client.describe_certificate.return_value = {
        "Certificate": {
            "CertificateArn": "arn:test",
            "DomainName": "x.example.com",
            "Status": "ISSUED",
            "NotBefore": datetime(2026, 1, 1, tzinfo=timezone.utc),
            "NotAfter": datetime(2027, 1, 1, tzinfo=timezone.utc),
            "KeyAlgorithm": "RSA_2048",
        }
    }
    mock_client.get_certificate.side_effect = ClientError(
        error_response={"Error": {"Code": "AccessDeniedException", "Message": "no perm"}},
        operation_name="GetCertificate",
    )
    with patch.object(adapter, "_get_client", return_value=mock_client):
        result = adapter._describe_and_get("arn:test")

    assert result is None


def test_describe_and_get_returns_none_for_filtered_status():
    """Status FAILED → describe still called, but parser returns None."""
    from datetime import datetime, timezone
    from unittest.mock import MagicMock, patch

    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    source = MagicMock()
    source.region = "eu-west-1"
    source.auth_method = "aws_instance_role"
    source.auth_credentials = {}
    adapter = AwsAcmAdapter(source)

    mock_client = MagicMock()
    mock_client.describe_certificate.return_value = {
        "Certificate": {
            "CertificateArn": "arn:failed",
            "DomainName": "f.example.com",
            "Status": "FAILED",
            "NotBefore": datetime(2026, 1, 1, tzinfo=timezone.utc),
            "NotAfter": datetime(2027, 1, 1, tzinfo=timezone.utc),
            "KeyAlgorithm": "RSA_2048",
        }
    }
    # get_certificate should NOT be called since status filter trips first
    with patch.object(adapter, "_get_client", return_value=mock_client):
        result = adapter._describe_and_get("arn:failed")

    assert result is None
    mock_client.get_certificate.assert_not_called()
