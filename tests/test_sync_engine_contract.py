"""The sync engine must honour the fields added in #101, and only those.

Before #101 the engine hardcoded `status=STATUS_ACTIVE` and never set
`certificate_type`, so a certificate that was expired or disabled at the source
still landed as Active, and EKU detection (v1.4.0) never reached sync imports.
"""

from datetime import datetime, timedelta, timezone

import pytest

from netbox_ssl.adapters.base import FetchedCertificate


def _fetched(**overrides) -> FetchedCertificate:
    base = {
        "external_id": "https://kv.vault.azure.net/certificates/x",
        "common_name": "sync.example.com",
        "serial_number": "0A:0B",
        "fingerprint_sha256": "AA:BB:CC:DD",
        "issuer": "Test CA",
        "valid_from": datetime.now(timezone.utc) - timedelta(days=1),
        "valid_to": datetime.now(timezone.utc) + timedelta(days=365),
        "pem_content": "",
    }
    base.update(overrides)
    return FetchedCertificate(**base)


@pytest.mark.django_db
class TestSyncEngineHonoursNewFields:
    def _source(self, **overrides):
        from netbox_ssl.models import ExternalSource

        defaults = {
            "name": f"src-{overrides.pop('suffix', 'a')}",
            "source_type": "azure_kv",
            "base_url": "https://kv-test.vault.azure.net/",
            "auth_method": "azure_managed_identity",
            "sync_tags": False,
        }
        defaults.update(overrides)
        return ExternalSource.objects.create(**defaults)

    def test_status_is_used_when_provided(self):
        from netbox_ssl.models import Certificate
        from netbox_ssl.utils.sync_engine import _create_certificate

        _create_certificate(_fetched(status="archived"), self._source(suffix="s1"))
        assert Certificate.objects.get(common_name="sync.example.com").status == "archived"

    def test_status_falls_back_to_active_when_absent(self):
        """Pre-#101 behaviour, preserved for adapters that set no status."""
        from netbox_ssl.models import Certificate
        from netbox_ssl.utils.sync_engine import _create_certificate

        _create_certificate(_fetched(), self._source(suffix="s2"))
        assert Certificate.objects.get(common_name="sync.example.com").status == "active"

    def test_certificate_type_is_carried_through(self):
        from netbox_ssl.models import Certificate
        from netbox_ssl.utils.sync_engine import _create_certificate

        _create_certificate(_fetched(certificate_type="mtls"), self._source(suffix="s3"))
        assert Certificate.objects.get(common_name="sync.example.com").certificate_type == "mtls"

    def test_tags_are_ignored_when_sync_tags_is_off(self):
        from netbox_ssl.models import Certificate
        from netbox_ssl.utils.sync_engine import _create_certificate

        source = self._source(suffix="s4", sync_tags=False)
        _create_certificate(_fetched(tags=("env=prod",)), source)
        cert = Certificate.objects.get(common_name="sync.example.com")
        assert cert.tags.count() == 0

    def test_tags_are_applied_when_sync_tags_is_on(self):
        from netbox_ssl.models import Certificate
        from netbox_ssl.utils.sync_engine import _create_certificate

        source = self._source(suffix="s5", sync_tags=True)
        _create_certificate(_fetched(tags=("env=prod", "owner")), source)
        cert = Certificate.objects.get(common_name="sync.example.com")
        assert set(cert.tags.values_list("name", flat=True)) == {"env=prod", "owner"}
