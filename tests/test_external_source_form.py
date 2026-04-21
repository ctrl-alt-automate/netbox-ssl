"""Unit tests for ExternalSourceForm.clean() validation."""

import importlib.util

import pytest

pytestmark = pytest.mark.unit

try:
    _spec = importlib.util.find_spec("netbox")
    _NETBOX_AVAILABLE = _spec is not None and _spec.origin is not None
except (ValueError, ModuleNotFoundError):
    _NETBOX_AVAILABLE = False


def _base_form_data(**overrides):
    data = {
        "name": "test",
        "source_type": "lemur",
        "base_url": "https://example.com",
        "auth_method": "bearer",
        "auth_credentials": {"token": "env:LEMUR_TOKEN"},
        "field_mapping": {},
        "sync_interval_minutes": 60,
        "enabled": True,
        "verify_ssl": True,
    }
    data.update(overrides)
    return data


@pytest.mark.skipif(not _NETBOX_AVAILABLE, reason="NetBox not available locally (tests run in Docker CI)")
def test_form_accepts_valid_lemur_config():
    from netbox_ssl.forms.external_sources import ExternalSourceForm

    form = ExternalSourceForm(data=_base_form_data())
    assert form.is_valid(), form.errors


@pytest.mark.skipif(not _NETBOX_AVAILABLE, reason="NetBox not available locally (tests run in Docker CI)")
def test_form_rejects_unknown_credential_key():
    from netbox_ssl.forms.external_sources import ExternalSourceForm

    form = ExternalSourceForm(
        data=_base_form_data(
            auth_credentials={"token": "env:OK", "extra": "env:BAD"},
        )
    )
    assert not form.is_valid()
    assert "Unknown credential keys" in str(form.errors)


@pytest.mark.skipif(not _NETBOX_AVAILABLE, reason="NetBox not available locally (tests run in Docker CI)")
def test_form_rejects_missing_required_credential():
    from netbox_ssl.forms.external_sources import ExternalSourceForm

    form = ExternalSourceForm(data=_base_form_data(auth_credentials={}))
    assert not form.is_valid()
    assert "Missing required credential" in str(form.errors)


@pytest.mark.skipif(not _NETBOX_AVAILABLE, reason="NetBox not available locally (tests run in Docker CI)")
def test_form_rejects_auth_method_not_supported_by_source_type():
    from netbox_ssl.forms.external_sources import ExternalSourceForm

    form = ExternalSourceForm(
        data=_base_form_data(
            source_type="lemur",
            auth_method="aws_explicit",
        )
    )
    assert not form.is_valid()
    assert "does not support" in str(form.errors)
