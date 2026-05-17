"""Unit tests verifying GraphQL scrubbing of ExternalSource credentials."""

import importlib.util

import pytest

pytestmark = pytest.mark.unit

try:
    _spec = importlib.util.find_spec("netbox")
    _NETBOX_AVAILABLE = _spec is not None and _spec.origin is not None
except (ValueError, ModuleNotFoundError):
    _NETBOX_AVAILABLE = False


@pytest.mark.skipif(not _NETBOX_AVAILABLE, reason="NetBox not available locally (tests run in Docker CI)")
def test_external_source_type_has_no_auth_credentials_field():
    from netbox_ssl.graphql.types import ExternalSourceType

    # Inspect the class annotations (strawberry/strawberry-django uses these)
    annotations = getattr(ExternalSourceType, "__annotations__", {})
    assert "auth_credentials" not in annotations
    assert "auth_credentials_reference" not in annotations


@pytest.mark.skipif(not _NETBOX_AVAILABLE, reason="NetBox not available locally (tests run in Docker CI)")
def test_external_source_type_has_has_credentials_field():
    from netbox_ssl.graphql.types import ExternalSourceType

    # has_credentials is exposed as a strawberry_django.field
    assert hasattr(ExternalSourceType, "has_credentials")
