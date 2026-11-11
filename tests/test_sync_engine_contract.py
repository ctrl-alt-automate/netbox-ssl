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


@pytest.mark.django_db
class TestSyncEngineUpdatePathHonoursNewFields:
    """The update path must not overwrite operator data with adapter defaults.

    Lemur, Generic REST and AWS ACM never populate the #101 fields. An update
    driven by one of them must therefore leave `certificate_type` and `status`
    exactly as the operator set them — the engine did not touch those fields on
    update before #101, so writing an adapter default here is data loss.
    """

    def _source(self, **overrides):
        from netbox_ssl.models import ExternalSource

        defaults = {
            "name": f"upd-{overrides.pop('suffix', 'a')}",
            "source_type": "azure_kv",
            "base_url": "https://kv-test.vault.azure.net/",
            "auth_method": "azure_managed_identity",
            "sync_tags": False,
        }
        defaults.update(overrides)
        return ExternalSource.objects.create(**defaults)

    def _existing(self, source, **cert_overrides):
        """Create a local certificate through the engine, then apply overrides."""
        from netbox_ssl.models import Certificate
        from netbox_ssl.utils.sync_engine import _create_certificate

        _create_certificate(_fetched(), source)
        cert = Certificate.objects.get(common_name="sync.example.com")
        for attr, value in cert_overrides.items():
            setattr(cert, attr, value)
        if cert_overrides:
            cert.save()
        return cert

    def test_update_keeps_operator_certificate_type_when_adapter_supplies_none(self):
        """Finding 1: the regression that silently reverted `mtls` to `server`."""
        from netbox_ssl.models import Certificate
        from netbox_ssl.utils.sync_engine import _update_certificate

        source = self._source(suffix="u1")
        cert = self._existing(source, certificate_type="mtls")

        _update_certificate(cert.pk, _fetched(), source)

        assert Certificate.objects.get(pk=cert.pk).certificate_type == "mtls"

    def test_update_applies_certificate_type_when_the_adapter_supplies_one(self):
        from netbox_ssl.models import Certificate
        from netbox_ssl.utils.sync_engine import _update_certificate

        source = self._source(suffix="u2")
        cert = self._existing(source, certificate_type="mtls")

        _update_certificate(cert.pk, _fetched(certificate_type="client"), source)

        assert Certificate.objects.get(pk=cert.pk).certificate_type == "client"

    def test_update_keeps_operator_status_when_adapter_supplies_none(self):
        """The same invariant as above, for the field that already guards it."""
        from netbox_ssl.models import Certificate
        from netbox_ssl.utils.sync_engine import _update_certificate

        source = self._source(suffix="u3")
        cert = self._existing(source, status="revoked")

        _update_certificate(cert.pk, _fetched(), source)

        assert Certificate.objects.get(pk=cert.pk).status == "revoked"

    def test_update_applies_status_when_the_adapter_supplies_one(self):
        from netbox_ssl.models import Certificate
        from netbox_ssl.utils.sync_engine import _update_certificate

        source = self._source(suffix="u4")
        cert = self._existing(source, status="revoked")

        _update_certificate(cert.pk, _fetched(status="archived"), source)

        assert Certificate.objects.get(pk=cert.pk).status == "archived"

    def test_update_leaves_operator_tags_alone_when_sync_tags_is_off(self):
        from extras.models import Tag

        from netbox_ssl.models import Certificate
        from netbox_ssl.utils.sync_engine import _update_certificate

        source = self._source(suffix="u5", sync_tags=False)
        cert = self._existing(source)
        cert.tags.set([Tag.objects.create(name="hand-added", slug="hand-added")])

        _update_certificate(cert.pk, _fetched(tags=("env=prod",)), source)

        assert set(Certificate.objects.get(pk=cert.pk).tags.values_list("name", flat=True)) == {"hand-added"}

    def test_update_replaces_tags_when_sync_tags_is_on(self):
        from extras.models import Tag

        from netbox_ssl.models import Certificate
        from netbox_ssl.utils.sync_engine import _update_certificate

        source = self._source(suffix="u6", sync_tags=True)
        cert = self._existing(source)
        cert.tags.set([Tag.objects.create(name="hand-added", slug="hand-added")])

        _update_certificate(cert.pk, _fetched(tags=("env=prod",)), source)

        assert set(Certificate.objects.get(pk=cert.pk).tags.values_list("name", flat=True)) == {"env=prod"}

    def test_update_clears_tags_when_an_authoritative_source_has_none(self):
        """Finding 2: `sync_tags` means authoritative, with no special case.

        An empty tag set at the source must clear NetBox's tags, exactly as a
        non-empty one replaces them. The previous early return made an empty
        vault tag set silently preserve stale tags forever.
        """
        from extras.models import Tag

        from netbox_ssl.models import Certificate
        from netbox_ssl.utils.sync_engine import _update_certificate

        source = self._source(suffix="u7", sync_tags=True)
        cert = self._existing(source)
        cert.tags.set([Tag.objects.create(name="stale", slug="stale")])

        _update_certificate(cert.pk, _fetched(tags=()), source)

        assert Certificate.objects.get(pk=cert.pk).tags.count() == 0


@pytest.mark.django_db
class TestSyncEngineRenewPathHonoursNewFields:
    """Renewal is Azure Key Vault's primary path, so it must carry the fields.

    A rotating vault certificate keeps its version-independent `external_id`
    and changes serial, which `build_plan` classifies as a renewal — not a
    create and not an update.
    """

    def _source(self, **overrides):
        from netbox_ssl.models import ExternalSource

        defaults = {
            "name": f"ren-{overrides.pop('suffix', 'a')}",
            "source_type": "azure_kv",
            "base_url": "https://kv-test.vault.azure.net/",
            "auth_method": "azure_managed_identity",
            "sync_tags": False,
        }
        defaults.update(overrides)
        return ExternalSource.objects.create(**defaults)

    def _renewed(self, **overrides):
        """A FetchedCertificate for the same external_id with fresh identity."""
        base = {"serial_number": "0C:0D", "fingerprint_sha256": "EE:FF:00:11"}
        base.update(overrides)
        return _fetched(**base)

    def _old_cert(self, source):
        from netbox_ssl.models import Certificate
        from netbox_ssl.utils.sync_engine import _create_certificate

        _create_certificate(_fetched(), source)
        return Certificate.objects.get(serial_number="0A:0B")

    def _new_cert(self):
        from netbox_ssl.models import Certificate

        return Certificate.objects.get(serial_number="0C:0D")

    def test_renew_carries_certificate_type(self):
        """Finding 6: an mTLS certificate came back from renewal as `server`."""
        from netbox_ssl.utils.sync_engine import _renew_certificate

        source = self._source(suffix="r1")
        old = self._old_cert(source)

        _renew_certificate(old.pk, self._renewed(certificate_type="mtls"), source)

        assert self._new_cert().certificate_type == "mtls"

    def test_renew_carries_status(self):
        """Finding 6: a disabled-in-vault certificate came back `active`."""
        from netbox_ssl.utils.sync_engine import _renew_certificate

        source = self._source(suffix="r2")
        old = self._old_cert(source)

        _renew_certificate(old.pk, self._renewed(status="archived"), source)

        assert self._new_cert().status == "archived"

    def test_renew_carries_tags(self):
        """Finding 6: `_apply_tags` was never called on the renewal path."""
        from netbox_ssl.utils.sync_engine import _renew_certificate

        source = self._source(suffix="r3", sync_tags=True)
        old = self._old_cert(source)

        _renew_certificate(old.pk, self._renewed(tags=("env=prod",)), source)

        assert set(self._new_cert().tags.values_list("name", flat=True)) == {"env=prod"}

    def test_renew_falls_back_to_todays_defaults_when_the_adapter_supplies_nothing(self):
        """Protects Lemur, Generic REST and AWS ACM: unchanged renewal output."""
        from netbox_ssl.utils.sync_engine import _renew_certificate

        source = self._source(suffix="r4", sync_tags=True)
        old = self._old_cert(source)

        _renew_certificate(old.pk, self._renewed(), source)

        new = self._new_cert()
        assert new.status == "active"
        assert new.certificate_type == "server"
        assert new.tags.count() == 0

    def test_renew_still_replaces_the_old_certificate(self):
        """Guard the Janus behaviour the new field wiring must not disturb."""
        from netbox_ssl.models import Certificate
        from netbox_ssl.utils.sync_engine import _renew_certificate

        source = self._source(suffix="r5")
        old = self._old_cert(source)

        _renew_certificate(old.pk, self._renewed(), source)

        old.refresh_from_db()
        assert old.status == "replaced"
        assert old.replaced_by_id == self._new_cert().pk
        assert Certificate.objects.filter(external_id=_fetched().external_id).count() == 2


@pytest.mark.django_db
class TestTagApplicationIsRobust:
    """One awkward Azure tag must never cost the operator the whole sync run.

    `ExternalSourceSync` runs inside NetBox's own `transaction.atomic()`, so an
    escaping database error aborts the connection and rolls back every earlier
    certificate, surfacing an opaque transaction error rather than a tag problem.
    """

    def _source(self, **overrides):
        from netbox_ssl.models import ExternalSource

        defaults = {
            "name": f"tag-{overrides.pop('suffix', 'a')}",
            "source_type": "azure_kv",
            "base_url": "https://kv-test.vault.azure.net/",
            "auth_method": "azure_managed_identity",
            "sync_tags": True,
        }
        defaults.update(overrides)
        return ExternalSource.objects.create(**defaults)

    def _cert(self, source, tags):
        from netbox_ssl.models import Certificate
        from netbox_ssl.utils.sync_engine import _create_certificate

        _create_certificate(_fetched(tags=tags), source)
        return Certificate.objects.get(common_name="sync.example.com")

    def _cert_for(self, source):
        """A synced certificate with no tags of its own."""
        return self._cert(source, ())

    def test_names_that_slugify_identically_become_two_distinct_tags(self):
        """Finding 2.1: `Tag.slug` is unique and `slugify` strips `=` and `:`."""
        cert = self._cert(self._source(suffix="t1"), ("env=prod", "env:prod"))

        assert set(cert.tags.values_list("name", flat=True)) == {"env=prod", "env:prod"}

    def test_a_slug_collision_does_not_poison_the_surrounding_transaction(self):
        """Finding 2.3: an escaping IntegrityError aborts the whole sync run."""
        from netbox_ssl.models import Certificate

        source = self._source(suffix="t2")
        self._cert(source, ("env=prod", "env:prod"))

        # Any ORM write after the tag work proves the connection is still usable.
        Certificate.objects.filter(common_name="sync.example.com").update(renewal_note="ok")
        assert Certificate.objects.get(common_name="sync.example.com").renewal_note == "ok"

    def test_a_name_longer_than_the_tag_column_is_truncated_not_fatal(self):
        """Finding 2.2: Azure keys run to 512 chars and values to 256."""
        from extras.models import Tag

        long_name = "k" * 400 + "=" + "v" * 400
        cert = self._cert(self._source(suffix="t3"), (long_name,))

        limit = Tag._meta.get_field("name").max_length
        names = list(cert.tags.values_list("name", flat=True))
        assert len(names) == 1
        assert len(names[0]) <= limit

    def test_two_overlong_names_sharing_a_prefix_stay_distinct(self):
        """Truncation must not silently merge two different Azure tags."""
        prefix = "owner=" + "x" * 200
        cert = self._cert(self._source(suffix="t4"), (prefix + "alice", prefix + "bob"))

        assert cert.tags.count() == 2

    def test_sync_tags_on_a_non_tag_capable_source_never_touches_tags(self):
        """`sync_tags` is offered on every source type, but only Azure supplies tags.

        Gating on "the fetched tag tuple is empty" is not enough: a Lemur,
        Generic REST or AWS ACM source with the box ticked would reach
        `tags.set([])` and delete every tag on the certificate while copying
        none back. The gate has to be the adapter's declared capability.
        """
        from extras.models import Tag

        from netbox_ssl.models import Certificate
        from netbox_ssl.utils.sync_engine import _update_certificate

        source = self._source(suffix="t6", source_type="lemur", auth_method="bearer", sync_tags=True)
        cert = self._cert_for(source)
        cert.tags.set([Tag.objects.create(name="operator-owned", slug="operator-owned")])

        # Lemur never populates fetched.tags — this is what its sync looks like.
        _update_certificate(cert.pk, _fetched(), source)

        assert set(Certificate.objects.get(pk=cert.pk).tags.values_list("name", flat=True)) == {"operator-owned"}

    def test_an_unresolvable_tag_is_skipped_and_the_others_still_apply(self):
        """Per-tag failure is non-fatal, matching the per-certificate posture."""
        from netbox_ssl.utils import sync_engine

        real_resolve = sync_engine._resolve_tag

        def _explode(name: str):
            if name == "boom":
                raise RuntimeError("simulated tag backend failure")
            return real_resolve(name)

        sync_engine._resolve_tag = _explode
        try:
            cert = self._cert(self._source(suffix="t5"), ("boom", "fine"))
        finally:
            sync_engine._resolve_tag = real_resolve

        assert set(cert.tags.values_list("name", flat=True)) == {"fine"}
