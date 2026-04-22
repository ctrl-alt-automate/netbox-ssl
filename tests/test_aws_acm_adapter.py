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
