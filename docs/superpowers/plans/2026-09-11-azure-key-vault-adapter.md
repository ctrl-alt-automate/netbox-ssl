# Azure Key Vault Read-Only Adapter — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ingest certificate metadata from Azure Key Vault as a read-only External Source, so operators with Azure-managed PKI get their inventory in NetBox without rekeying it.

**Architecture:** A new `AzureKvAdapter` implements the existing `BaseAdapter` contract, mirroring `AwsAcmAdapter`. It lists certificates via the Azure SDK, hands each certificate's DER bytes to the plugin's own `CertificateParser`, and returns `FetchedCertificate` objects. Three optional fields are added to that shared dataclass (`tags`, `certificate_type`, `status`) whose defaults reproduce today's behaviour exactly, so the other three adapters are untouched.

**Tech Stack:** Python 3.10+, Django, NetBox 4.4–4.7, `azure-identity`, `azure-keyvault-certificates`, pytest.

**Spec:** `docs/superpowers/specs/2026-09-11-azure-key-vault-adapter-design.md`

## Global Constraints

- Python floor `>=3.10`; NetBox 4.4.0–4.7.99. All work must pass on every lane in the CI matrix.
- Azure SDK pins: `azure-identity>=1.25,<2.0`, `azure-keyvault-certificates>=4.11,<5.0`. Optional extra named `azure`.
- The adapter must **never** construct `SecretClient` or `KeyClient`, and never dereference the `kid` or `sid` fields present in a certificate response.
- Documented minimum Azure RBAC role is **`Key Vault Reader`** — never `Key Vault Certificate User`, which grants `secrets/getSecret/action` and therefore private-key access.
- Credentials are resolved only through the existing `env:VAR_NAME` resolver, are `secret=True` where applicable, and never appear in logs, serializers, GraphQL or the changelog.
- New `FetchedCertificate` fields must have defaults that leave Lemur, Generic REST and AWS ACM behaviour byte-for-byte unchanged.
- `sync_tags` defaults to `False`. Upgrading must never start writing tags to existing certificates.
- Every new pytest marker must be registered in `pytest.ini`; the host lane runs `--strict-markers`.
- Ruff must pass: `ruff check netbox_ssl/ tests/ && ruff format --check netbox_ssl/ tests/`.

## File Structure

**Create**

| File | Responsibility |
|---|---|
| `netbox_ssl/adapters/azure_kv.py` | The adapter. Auth, listing, fetching, mapping, error tolerance. |
| `netbox_ssl/migrations/0028_azure_kv_source.py` | `TYPE_AZURE_KV` choice + `sync_tags` field. |
| `tests/test_azure_kv_adapter.py` | Adapter unit tests against a mocked SDK. |
| `tests/test_azure_kv_live.py` | Live tests against the provisioned vault, marker `azure_live`. |
| `.github/workflows/azure-integration.yml` | Maintainer-only OIDC workflow. |
| `docs/how-to/azure-key-vault-sync.md` | Operator guide. |

**Modify**

| File | Change |
|---|---|
| `netbox_ssl/adapters/base.py` | Three optional fields on `FetchedCertificate`. |
| `netbox_ssl/utils/sync_engine.py` | Honour the new fields in create/update. |
| `netbox_ssl/models/external_source.py` | `TYPE_AZURE_KV`, `sync_tags`. |
| `netbox_ssl/adapters/__init__.py` | Registry entry. |
| `pyproject.toml` | `azure` extra. |
| `netbox_ssl/forms/external_sources.py` | Expose `sync_tags`. |
| `netbox_ssl/api/serializers/external_sources.py` | Expose `sync_tags`. |
| `netbox_ssl/graphql/types.py` | Expose `sync_tags`. |
| `pytest.ini` | Register `azure_live`. |
| `tests/test_sync_engine.py` | Cover the new engine behaviour. |
| `docs/reference/data-models.md`, `docs/reference/api.md`, `mkdocs.yml`, `CHANGELOG.md`, `COMPATIBILITY.md` | Documentation. |

---

### Task 1: Extend the shared `FetchedCertificate` contract

Three optional fields. Nothing consumes them yet; this task only proves the defaults preserve current behaviour.

**Files:**
- Modify: `netbox_ssl/adapters/base.py` (the `FetchedCertificate` dataclass)
- Test: `tests/test_fetched_certificate_contract.py` (create)

**Interfaces:**
- Consumes: nothing.
- Produces: `FetchedCertificate(..., tags: tuple[str, ...] = (), certificate_type: str = "server", status: str | None = None)` — consumed by Tasks 3, 6 and 7.

- [ ] **Step 1: Write the failing test**

Create `tests/test_fetched_certificate_contract.py`:

```python
"""The shared adapter contract must grow without changing existing behaviour.

`FetchedCertificate` is consumed by four adapters and by the sync engine. Fields
added for Azure Key Vault (#101) carry defaults that reproduce exactly what the
engine did before they existed, so Lemur, Generic REST and AWS ACM keep working
untouched.
"""

from datetime import datetime, timezone

import pytest

pytestmark = pytest.mark.unit

from netbox_ssl.adapters.base import FetchedCertificate


def _minimal() -> FetchedCertificate:
    """Build a FetchedCertificate using only the pre-#101 required fields."""
    return FetchedCertificate(
        external_id="https://kv.vault.azure.net/certificates/example",
        common_name="a.example.com",
        serial_number="01:02:03",
        fingerprint_sha256="AA:BB:CC",
        issuer="Test CA",
        valid_from=datetime(2026, 1, 1, tzinfo=timezone.utc),
        valid_to=datetime(2027, 1, 1, tzinfo=timezone.utc),
    )


def test_new_fields_have_behaviour_preserving_defaults():
    fetched = _minimal()
    assert fetched.tags == ()
    assert fetched.certificate_type == "server"
    assert fetched.status is None


def test_new_fields_are_settable():
    fetched = FetchedCertificate(
        external_id="x",
        common_name="a.example.com",
        serial_number="01",
        fingerprint_sha256="AA",
        issuer="CA",
        valid_from=datetime(2026, 1, 1, tzinfo=timezone.utc),
        valid_to=datetime(2027, 1, 1, tzinfo=timezone.utc),
        tags=("env=prod", "owner=team-a"),
        certificate_type="mtls",
        status="archived",
    )
    assert fetched.tags == ("env=prod", "owner=team-a")
    assert fetched.certificate_type == "mtls"
    assert fetched.status == "archived"


def test_existing_adapters_construct_without_the_new_fields():
    """Guard the whole point: no adapter is forced to know about them."""
    import inspect

    from netbox_ssl.adapters.base import FetchedCertificate as FC

    params = inspect.signature(FC).parameters
    for name in ("tags", "certificate_type", "status"):
        assert params[name].default is not inspect.Parameter.empty, (
            f"{name} must have a default, or existing adapters break"
        )
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `python -m pytest tests/test_fetched_certificate_contract.py -v -p no:django`
Expected: FAIL — `TypeError: FetchedCertificate.__init__() got an unexpected keyword argument 'tags'`, and `KeyError: 'tags'` in the signature test.

- [ ] **Step 3: Add the fields**

In `netbox_ssl/adapters/base.py`, replace the `FetchedCertificate` body:

```python
@dataclass(frozen=True)
class FetchedCertificate:
    """Normalized certificate data from an external source."""

    external_id: str
    common_name: str
    serial_number: str
    fingerprint_sha256: str
    issuer: str
    valid_from: datetime
    valid_to: datetime
    sans: tuple[str, ...] = field(default_factory=tuple)
    key_size: int | None = None
    algorithm: str = "unknown"
    pem_content: str = ""
    issuer_chain: str = ""

    # Added for #101. Every default reproduces the behaviour the sync engine
    # had before these existed, so an adapter that ignores them is unaffected:
    #   tags             -> engine applies none
    #   certificate_type -> the model default, which is what sync produced
    #   status           -> engine falls back to STATUS_ACTIVE
    tags: tuple[str, ...] = field(default_factory=tuple)
    certificate_type: str = "server"
    status: str | None = None
```

- [ ] **Step 4: Run the test and confirm it passes**

Run: `python -m pytest tests/test_fetched_certificate_contract.py -v -p no:django`
Expected: 3 passed.

- [ ] **Step 5: Run the full unit suite to prove nothing regressed**

Run: `python -m pytest tests/ -m unit -q -p no:django`
Expected: all pass, count increased by 3.

- [ ] **Step 6: Commit**

```bash
git add netbox_ssl/adapters/base.py tests/test_fetched_certificate_contract.py
git commit -m "feat: add tags, certificate_type and status to FetchedCertificate

Three optional fields on the shared adapter contract, each defaulting to
the behaviour the sync engine already had. Nothing consumes them yet;
this commit only establishes the contract and proves the other three
adapters are unaffected."
```

---

### Task 2: Add the source type and `sync_tags` field

**Files:**
- Modify: `netbox_ssl/models/external_source.py`
- Create: `netbox_ssl/migrations/0028_azure_kv_source.py`
- Test: `tests/test_azure_kv_model.py` (create)

**Interfaces:**
- Consumes: nothing.
- Produces: `ExternalSourceTypeChoices.TYPE_AZURE_KV == "azure_kv"`; `ExternalSource.sync_tags` (BooleanField, default `False`) — consumed by Tasks 3, 4 and 9.

- [ ] **Step 1: Write the failing test**

Create `tests/test_azure_kv_model.py`:

```python
"""Model-level additions for the Azure Key Vault adapter (#101).

`netbox_ssl.models` cannot be imported on the host lane — Django models need
configured settings — so the shape assertions read the model source, the same
way tests/test_permission_names.py does. The behavioural assertion that the
default actually applies runs in the container lane.
"""

import ast
from pathlib import Path

import pytest

MODEL_SOURCE = Path(__file__).parent.parent / "netbox_ssl" / "models" / "external_source.py"


def _choice_values(class_name: str) -> set[str]:
    """Return every string constant assigned inside a ChoiceSet class."""
    tree = ast.parse(MODEL_SOURCE.read_text())
    for cls in tree.body:
        if isinstance(cls, ast.ClassDef) and cls.name == class_name:
            return {
                node.value
                for stmt in cls.body
                if isinstance(stmt, ast.Assign)
                for node in ast.walk(stmt)
                if isinstance(node, ast.Constant) and isinstance(node.value, str)
            }
    raise AssertionError(f"{class_name} not found in {MODEL_SOURCE.name}")


@pytest.mark.unit
def test_azure_kv_source_type_exists():
    assert "azure_kv" in _choice_values("ExternalSourceTypeChoices")


@pytest.mark.unit
def test_azure_kv_has_a_human_label():
    """A choice value with no label renders as a raw slug in the UI."""
    assert "Azure Key Vault" in _choice_values("ExternalSourceTypeChoices")


@pytest.mark.unit
def test_sync_tags_field_is_declared():
    assert "sync_tags = models.BooleanField(" in MODEL_SOURCE.read_text()


@pytest.mark.django_db
def test_sync_tags_defaults_to_false():
    """Opt-in: upgrading must never start writing tags to existing certificates."""
    from netbox_ssl.models import ExternalSource

    field = ExternalSource._meta.get_field("sync_tags")
    assert field.default is False
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `python -m pytest tests/test_azure_kv_model.py -v -p no:django -m unit`
Expected: FAIL — `'azure_kv' not in {...}` and the `sync_tags = models.BooleanField(` assertion. The `django_db` test is deselected on the host lane; it runs in the container in Step 6.

- [ ] **Step 3: Add the choice and the field**

In `netbox_ssl/models/external_source.py`, extend `ExternalSourceTypeChoices`:

```python
class ExternalSourceTypeChoices(ChoiceSet):
    """Type choices for external sources."""

    TYPE_LEMUR = "lemur"
    TYPE_GENERIC_REST = "generic_rest"
    TYPE_AWS_ACM = "aws_acm"
    TYPE_AZURE_KV = "azure_kv"

    CHOICES = [
        (TYPE_LEMUR, "Lemur", "purple"),
        (TYPE_GENERIC_REST, "Generic REST API", "blue"),
        (TYPE_AWS_ACM, "AWS Certificate Manager", "orange"),
        (TYPE_AZURE_KV, "Azure Key Vault", "cyan"),
    ]
```

Then add the field to `ExternalSource`, immediately after `verify_ssl`:

```python
    sync_tags = models.BooleanField(
        default=False,
        help_text="Copy tags from the external source onto imported certificates",
    )
```

- [ ] **Step 4: Write the migration**

Create `netbox_ssl/migrations/0028_azure_kv_source.py`. Kwargs are alphabetical and choices render as 2-tuples — match what `makemigrations` generates, because CI runs `makemigrations --check`:

```python
"""
Azure Key Vault source type and opt-in tag sync (#101).

Additive and reversible: one new `source_type` choice and one boolean field
defaulting to False, so existing sources are untouched and no tags are written
to existing certificates on upgrade.
"""

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_ssl", "0027_certificate_type"),
    ]

    operations = [
        migrations.AlterField(
            model_name="externalsource",
            name="source_type",
            field=models.CharField(
                choices=[
                    ("lemur", "Lemur"),
                    ("generic_rest", "Generic REST API"),
                    ("aws_acm", "AWS Certificate Manager"),
                    ("azure_kv", "Azure Key Vault"),
                ],
                help_text="Type of external source backend",
                max_length=30,
            ),
        ),
        migrations.AddField(
            model_name="externalsource",
            name="sync_tags",
            field=models.BooleanField(
                default=False,
                help_text="Copy tags from the external source onto imported certificates",
            ),
        ),
    ]
```

- [ ] **Step 5: Run the tests and confirm they pass**

Run: `python -m pytest tests/test_azure_kv_model.py -v -p no:django -m unit`
Expected: 3 passed, 1 deselected.

- [ ] **Step 6: Verify the migration matches Django's own output**

Run in the container (NetBox must be running; see `CLAUDE.md`):

```bash
docker compose up -d
docker exec netbox-ssl-netbox-1 python /opt/netbox/netbox/manage.py makemigrations netbox_ssl --check --dry-run
```

Expected: `No changes detected`. If it reports drift, copy the generated field definition verbatim into `0028`.

- [ ] **Step 7: Commit**

```bash
git add netbox_ssl/models/external_source.py netbox_ssl/migrations/0028_azure_kv_source.py tests/test_azure_kv_model.py
git commit -m "feat: add azure_kv source type and opt-in sync_tags (#101)

Migration 0028 is additive: one source_type choice and one boolean
defaulting to False, so upgrading never starts writing tags."
```

---

### Task 3: Teach the sync engine to honour the new fields

**Files:**
- Modify: `netbox_ssl/utils/sync_engine.py` (`_create_certificate`, `_update_certificate`, and the call site at line ~259)
- Test: `tests/test_sync_engine_contract.py` (create)

**Interfaces:**
- Consumes: `FetchedCertificate.tags / .certificate_type / .status` (Task 1); `ExternalSource.sync_tags` (Task 2).
- Produces: `_update_certificate(local_cert_id, fetched, source)` — a **changed signature**, third positional parameter added. `_apply_tags(cert, fetched, source)` helper.

**Decision recorded here (the spec left the format open):** an Azure tag pair becomes the NetBox tag name `key=value`, or just `key` when the value is empty. Deterministic and reversible.

- [ ] **Step 1: Write the failing test**

Create `tests/test_sync_engine_contract.py`:

```python
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
```

- [ ] **Step 2: Run the test and confirm it fails**

Run in the container:

```bash
docker cp tests/. netbox-ssl-netbox-1:/tmp/plugin_tests/
docker exec -w /opt/netbox/netbox netbox-ssl-netbox-1 \
  /opt/netbox/venv/bin/python -m pytest /tmp/plugin_tests/test_sync_engine_contract.py -v
```

Expected: FAIL — status is `active` where `archived` was expected; `certificate_type` is `server`; tags are never applied.

- [ ] **Step 3: Implement the engine changes**

In `netbox_ssl/utils/sync_engine.py`, add the tag helper above `_create_certificate`:

```python
def _apply_tags(cert: Any, fetched: FetchedCertificate, source: Any) -> None:
    """Apply source tags to a certificate, when the source opts in.

    Tag names arrive already flattened by the adapter (an Azure `key`/`value`
    pair becomes `key=value`). Tags are created on demand; NetBox requires a
    slug, so one is derived from the name.
    """
    if not getattr(source, "sync_tags", False) or not fetched.tags:
        return

    from django.utils.text import slugify
    from extras.models import Tag

    tags = []
    for name in fetched.tags:
        tag, _ = Tag.objects.get_or_create(name=name, defaults={"slug": slugify(name)[:100]})
        tags.append(tag)
    cert.tags.set(tags)
```

In `_create_certificate`, replace the hardcoded status and add the type:

```python
        external_id=fetched.external_id,
        tenant=source.tenant,
        status=fetched.status or CertificateStatusChoices.STATUS_ACTIVE,
        certificate_type=fetched.certificate_type,
    )
```

and after `cert.save()` (before `auto_detect_ca`):

```python
    _apply_tags(cert, fetched, source)
```

Change `_update_certificate` to take the source and honour the same fields:

```python
def _update_certificate(local_cert_id: int, fetched: FetchedCertificate, source: Any) -> None:
    """Update an existing Certificate with new metadata.

    Args:
        local_cert_id: The pk of the local Certificate.
        fetched: The fetched certificate data.
        source: The ExternalSource, needed for the sync_tags opt-in.

    Raises:
        ValueError: If the fetched PEM contains a private key.
    """
```

Inside it, after `cert.algorithm = fetched.algorithm`, add:

```python
    if fetched.status:
        cert.status = fetched.status
    cert.certificate_type = fetched.certificate_type
```

and after `cert.save()`:

```python
    _apply_tags(cert, fetched, source)
```

Finally update the call site (around line 259):

```python
            _update_certificate(action.local_cert_id, action.fetched, source)
```

- [ ] **Step 4: Run the test and confirm it passes**

Run: the same container command as Step 2.
Expected: 5 passed.

- [ ] **Step 5: Run the existing sync-engine tests to prove no regression**

Run:

```bash
docker exec -w /opt/netbox/netbox netbox-ssl-netbox-1 \
  /opt/netbox/venv/bin/python -m pytest /tmp/plugin_tests/test_sync_engine.py -v
```

Expected: all pass. Any failure here means the signature change broke a caller — fix the caller, not the test.

- [ ] **Step 6: Commit**

```bash
git add netbox_ssl/utils/sync_engine.py tests/test_sync_engine_contract.py
git commit -m "feat: sync engine honours status, certificate_type and tags (#101)

Closes two pre-existing gaps: status was hardcoded to Active, so a
certificate already expired or disabled at the source still landed as
Active; and certificate_type was never set, so EKU detection added in
v1.4.0 never reached sync imports. Both now flow through the shared
contract, which means all four adapters benefit as they start populating
the fields.

_update_certificate gains a third parameter (source) so tag sync can
respect the per-source opt-in."
```

---

### Task 4: Adapter skeleton, auth schema, registration and dependency

**Files:**
- Create: `netbox_ssl/adapters/azure_kv.py`
- Modify: `netbox_ssl/adapters/__init__.py`, `pyproject.toml`
- Test: `tests/test_azure_kv_adapter.py` (create)

**Interfaces:**
- Consumes: `BaseAdapter`, `CredentialField` from `netbox_ssl.adapters.base`.
- Produces: `AzureKvAdapter` with `SUPPORTED_AUTH_METHODS = ("azure_managed_identity", "azure_explicit")`, `IMPLICIT_AUTH_METHODS = ("azure_managed_identity",)`, `REQUIRES_BASE_URL = True`, `REQUIRES_REGION = False`, and `credential_schema(auth_method)`. Consumed by Tasks 5–8.

- [ ] **Step 1: Write the failing test**

Create `tests/test_azure_kv_adapter.py`:

```python
"""Unit tests for AzureKvAdapter (#101). The Azure SDK is mocked throughout."""

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.unit

_project_root = Path(__file__).parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

_tests_dir = Path(__file__).parent
if str(_tests_dir) not in sys.path:
    sys.path.insert(0, str(_tests_dir))

try:
    _spec = importlib.util.find_spec("netbox")
    _NETBOX_AVAILABLE = _spec is not None and _spec.origin is not None
except (ValueError, ModuleNotFoundError):
    _NETBOX_AVAILABLE = False

if not _NETBOX_AVAILABLE and "netbox" not in sys.modules:
    sys.modules["netbox"] = MagicMock()
    sys.modules["netbox.plugins"] = MagicMock()


class TestAdapterShape:
    def test_adapter_class_exists(self):
        from netbox_ssl.adapters.azure_kv import AzureKvAdapter

        assert AzureKvAdapter.__name__ == "AzureKvAdapter"

    def test_declares_both_auth_methods_implicit_first(self):
        from netbox_ssl.adapters.azure_kv import AzureKvAdapter

        assert AzureKvAdapter.SUPPORTED_AUTH_METHODS == (
            "azure_managed_identity",
            "azure_explicit",
        )
        assert AzureKvAdapter.IMPLICIT_AUTH_METHODS == ("azure_managed_identity",)

    def test_requires_a_vault_url_not_a_region(self):
        from netbox_ssl.adapters.azure_kv import AzureKvAdapter

        assert AzureKvAdapter.REQUIRES_BASE_URL is True
        assert AzureKvAdapter.REQUIRES_REGION is False


class TestCredentialSchema:
    def test_managed_identity_needs_no_credentials(self):
        from netbox_ssl.adapters.azure_kv import AzureKvAdapter

        assert AzureKvAdapter.credential_schema("azure_managed_identity") == {}

    def test_explicit_declares_three_components(self):
        from netbox_ssl.adapters.azure_kv import AzureKvAdapter

        schema = AzureKvAdapter.credential_schema("azure_explicit")
        assert set(schema) == {"tenant_id", "client_id", "client_secret"}
        assert all(field.required for field in schema.values())

    def test_only_the_client_secret_is_marked_secret(self):
        from netbox_ssl.adapters.azure_kv import AzureKvAdapter

        schema = AzureKvAdapter.credential_schema("azure_explicit")
        assert schema["client_secret"].secret is True
        assert schema["tenant_id"].secret is False
        assert schema["client_id"].secret is False

    def test_unknown_auth_method_raises(self):
        from netbox_ssl.adapters.azure_kv import AzureKvAdapter

        with pytest.raises(ValueError, match="does not support auth_method"):
            AzureKvAdapter.credential_schema("bearer")


class TestRegistration:
    def test_registered_under_azure_kv(self):
        from netbox_ssl.adapters import get_adapter_class
        from netbox_ssl.adapters.azure_kv import AzureKvAdapter

        assert get_adapter_class("azure_kv") is AzureKvAdapter
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `python -m pytest tests/test_azure_kv_adapter.py -v -p no:django`
Expected: FAIL — `ModuleNotFoundError: No module named 'netbox_ssl.adapters.azure_kv'`.

- [ ] **Step 3: Install the SDK locally so the import resolves**

Run: `pip install 'azure-identity>=1.25,<2.0' 'azure-keyvault-certificates>=4.11,<5.0'`

- [ ] **Step 4: Create the adapter skeleton**

Create `netbox_ssl/adapters/azure_kv.py`:

```python
"""Read-only adapter for Azure Key Vault (#101).

Lists certificates in one vault and returns their public metadata. Like the AWS
ACM adapter, it uses a vendor SDK directly rather than BaseAdapter's HTTP
helpers, so the base class's response-size cap and redirect blocking do not
apply — §6.2 of the design compensates with vault-hostname validation.

Never constructs SecretClient or KeyClient. A certificate response carries `kid`
and `sid`, references to the key and to the secret holding the full PFX; both are
metadata and are never dereferenced. The documented minimum RBAC role,
`Key Vault Reader`, cannot follow them either.
"""

from __future__ import annotations

import logging

try:
    from azure.core.exceptions import ClientAuthenticationError, HttpResponseError, ResourceNotFoundError
    from azure.identity import ClientSecretCredential, DefaultAzureCredential
    from azure.keyvault.certificates import CertificateClient
except ImportError as exc:  # pragma: no cover - exercised by the registry fallback
    raise ImportError(
        "Azure Key Vault adapter requires the azure extras. "
        "Install with: pip install netbox-ssl[azure]"
    ) from exc

from .base import BaseAdapter, CredentialField, FetchedCertificate

logger = logging.getLogger("netbox_ssl.adapters")

# Accepted Key Vault hostname suffixes, per design §6.2. The SDK bypasses
# BaseAdapter._make_request, so this is the adapter's own SSRF guard.
VAULT_HOST_SUFFIXES: tuple[str, ...] = (
    ".vault.azure.net",           # global
    ".vault.azure.cn",            # China
    ".vault.usgovcloudapi.net",   # US Government
    ".vault.microsoftazure.de",   # Germany
)


class AzureKvAdapter(BaseAdapter):
    """Read-only adapter for Azure Key Vault certificates.

    Supports two auth methods:
    - azure_managed_identity: DefaultAzureCredential — resolves managed
      identity, workload identity (GitHub OIDC) and a local `az login`.
    - azure_explicit: operator-supplied tenant_id + client_id + client_secret.

    One ExternalSource = one vault, matching Azure's own model and the
    one-source-per-endpoint convention of the other adapters.
    """

    SUPPORTED_AUTH_METHODS: tuple[str, ...] = ("azure_managed_identity", "azure_explicit")
    IMPLICIT_AUTH_METHODS: tuple[str, ...] = ("azure_managed_identity",)
    REQUIRES_BASE_URL: bool = True
    REQUIRES_REGION: bool = False

    @classmethod
    def credential_schema(cls, auth_method: str) -> dict[str, CredentialField]:
        """Return the credential component schema for a given auth_method."""
        if auth_method == "azure_managed_identity":
            return {}
        if auth_method == "azure_explicit":
            return {
                "tenant_id": CredentialField(
                    required=True,
                    label="Tenant ID",
                    secret=False,
                    help_text="Entra ID (Azure AD) tenant GUID",
                ),
                "client_id": CredentialField(
                    required=True,
                    label="Client ID",
                    secret=False,
                    help_text="Application (client) ID of the service principal",
                ),
                "client_secret": CredentialField(
                    required=True,
                    label="Client Secret",
                    secret=True,
                    help_text="Service principal secret (env-var reference recommended)",
                ),
            }
        raise ValueError(
            f"AzureKvAdapter does not support auth_method '{auth_method}'. "
            f"Supported: {list(cls.SUPPORTED_AUTH_METHODS)}"
        )

    def __init__(self, source) -> None:
        super().__init__(source)
        self._client = None  # lazy: built on first use by _get_client()

    def test_connection(self) -> tuple[bool, str]:
        """Placeholder — implemented in Task 5."""
        raise NotImplementedError

    def fetch_certificates(self) -> list[FetchedCertificate]:
        """Placeholder — implemented in Task 6."""
        raise NotImplementedError

    def get_certificate_detail(self, external_id: str) -> FetchedCertificate | None:
        """Placeholder — implemented in Task 6."""
        raise NotImplementedError
```

- [ ] **Step 5: Register the adapter**

In `netbox_ssl/adapters/__init__.py`, inside `_build_registry()`, after the AWS block:

```python
    # Optional adapter — requires netbox-ssl[azure]
    try:
        from .azure_kv import AzureKvAdapter

        registry["azure_kv"] = AzureKvAdapter
    except ImportError as exc:
        logger.info(
            "Azure Key Vault adapter not registered (azure SDK not installed): %s. "
            "Install with: pip install netbox-ssl[azure]",
            exc,
        )
```

- [ ] **Step 6: Declare the optional dependency**

In `pyproject.toml`, under `[project.optional-dependencies]`, after the `aws` extra:

```toml
azure = [
    "azure-identity>=1.25,<2.0",
    "azure-keyvault-certificates>=4.11,<5.0",
]
```

and add both to the `dev` extra so CI can run the mocked tests:

```toml
    "azure-identity>=1.25,<2.0",
    "azure-keyvault-certificates>=4.11,<5.0",
```

- [ ] **Step 7: Run the tests and confirm they pass**

Run: `python -m pytest tests/test_azure_kv_adapter.py -v -p no:django`
Expected: 8 passed.

- [ ] **Step 8: Commit**

```bash
git add netbox_ssl/adapters/azure_kv.py netbox_ssl/adapters/__init__.py pyproject.toml tests/test_azure_kv_adapter.py
git commit -m "feat: Azure Key Vault adapter skeleton and registration (#101)

Auth schema for both methods, registry entry behind the same optional-
import guard AWS uses, and the azure extra. Fetch behaviour lands in the
next tasks."
```

---

### Task 5: `test_connection`, credentials and vault-hostname validation

**Files:**
- Modify: `netbox_ssl/adapters/azure_kv.py`
- Test: `tests/test_azure_kv_adapter.py` (append)

**Interfaces:**
- Consumes: `AzureKvAdapter` (Task 4).
- Produces: `_validate_vault_url(url) -> None` (raises `ValueError`), `_build_credential()`, `_get_client()`, `test_connection() -> tuple[bool, str]`. Consumed by Tasks 6–8.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_azure_kv_adapter.py`:

```python
def _source(**overrides):
    """A stub ExternalSource good enough for adapter unit tests."""
    source = MagicMock()
    source.base_url = overrides.get("base_url", "https://kv-nbssl-test-2609.vault.azure.net/")
    source.auth_method = overrides.get("auth_method", "azure_managed_identity")
    source.auth_credentials = overrides.get("auth_credentials", {})
    source.sync_tags = overrides.get("sync_tags", False)
    source.name = "azure-test"
    return source


class TestVaultUrlValidation:
    @pytest.mark.parametrize(
        "url",
        [
            "https://kv.vault.azure.net/",
            "https://kv.vault.azure.cn/",
            "https://kv.vault.usgovcloudapi.net/",
            "https://kv.vault.microsoftazure.de/",
        ],
    )
    def test_accepts_every_sovereign_cloud_suffix(self, url):
        from netbox_ssl.adapters.azure_kv import AzureKvAdapter

        AzureKvAdapter(_source(base_url=url))._validate_vault_url(url)

    @pytest.mark.parametrize(
        "url",
        [
            "https://evil.example.com/",
            "https://kv.vault.azure.net.evil.com/",
            "http://kv.vault.azure.net/",
        ],
    )
    def test_rejects_non_vault_hosts_and_plaintext(self, url):
        from netbox_ssl.adapters.azure_kv import AzureKvAdapter

        with pytest.raises(ValueError):
            AzureKvAdapter(_source(base_url=url))._validate_vault_url(url)


class TestTestConnection:
    def test_success_reports_the_certificate_count(self, monkeypatch):
        from netbox_ssl.adapters import azure_kv

        client = MagicMock()
        client.list_properties_of_certificates.return_value = iter(
            [MagicMock(name="a"), MagicMock(name="b")]
        )
        monkeypatch.setattr(azure_kv, "CertificateClient", lambda **kw: client)

        ok, message = azure_kv.AzureKvAdapter(_source()).test_connection()
        assert ok is True
        assert "2" in message

    def test_auth_failure_is_reported_without_leaking_the_credential(self, monkeypatch):
        from azure.core.exceptions import ClientAuthenticationError

        from netbox_ssl.adapters import azure_kv

        def _boom(**kwargs):
            raise ClientAuthenticationError("secret-value-should-never-surface")

        monkeypatch.setattr(azure_kv, "CertificateClient", _boom)

        ok, message = azure_kv.AzureKvAdapter(_source()).test_connection()
        assert ok is False
        assert "secret-value-should-never-surface" not in message
        assert "authentication" in message.lower()

    def test_permission_denied_names_the_required_role(self, monkeypatch):
        from azure.core.exceptions import HttpResponseError

        from netbox_ssl.adapters import azure_kv

        error = HttpResponseError("Forbidden")
        error.status_code = 403
        client = MagicMock()
        client.list_properties_of_certificates.side_effect = error
        monkeypatch.setattr(azure_kv, "CertificateClient", lambda **kw: client)

        ok, message = azure_kv.AzureKvAdapter(_source()).test_connection()
        assert ok is False
        assert "Key Vault Reader" in message
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `python -m pytest tests/test_azure_kv_adapter.py -v -p no:django -k "VaultUrl or TestConnection"`
Expected: FAIL — `AttributeError: '_validate_vault_url'` and `NotImplementedError`.

- [ ] **Step 3: Implement validation, credential building and the client**

In `netbox_ssl/adapters/azure_kv.py`, replace the `test_connection` placeholder with these four methods:

```python
    @staticmethod
    def _validate_vault_url(url: str) -> None:
        """Reject anything that is not an HTTPS Key Vault endpoint.

        The Azure SDK issues its own requests, so BaseAdapter's guards never
        see this URL. Matching on the host's suffix keeps the adapter from
        being aimed at an arbitrary server.

        Raises:
            ValueError: If the scheme is not https or the host is not a vault.
        """
        from urllib.parse import urlparse

        parsed = urlparse(url or "")
        if parsed.scheme != "https":
            raise ValueError(f"Key Vault URL must use https, got '{parsed.scheme or 'no scheme'}'")
        host = (parsed.hostname or "").lower()
        if not any(host.endswith(suffix) for suffix in VAULT_HOST_SUFFIXES):
            raise ValueError(
                f"'{host}' is not an Azure Key Vault hostname. "
                f"Expected one of: {', '.join(VAULT_HOST_SUFFIXES)}"
            )

    def _build_credential(self):
        """Build the Azure credential for this source's auth method.

        azure_managed_identity uses DefaultAzureCredential, which resolves a
        managed identity, a federated workload identity (GitHub OIDC) or a
        local `az login` — one code path for server, CI and laptop.
        """
        if self.source.auth_method == "azure_managed_identity":
            return DefaultAzureCredential()

        creds = self.resolve_credentials()
        return ClientSecretCredential(
            tenant_id=creds["tenant_id"],
            client_id=creds["client_id"],
            client_secret=creds["client_secret"],
        )

    def _get_client(self):
        """Lazily build and cache the CertificateClient.

        Only ever a CertificateClient: see the module docstring.
        """
        if self._client is None:
            self._validate_vault_url(self.source.base_url)
            self._client = CertificateClient(
                vault_url=self.source.base_url,
                credential=self._build_credential(),
            )
        return self._client

    def test_connection(self) -> tuple[bool, str]:
        """Probe the vault by listing certificate properties.

        Returns:
            (success, message). The message is safe to display: it never
            contains credential material.
        """
        try:
            count = sum(1 for _ in self._get_client().list_properties_of_certificates())
        except ClientAuthenticationError:
            logger.warning("Azure Key Vault authentication failed for source '%s'", self.source.name)
            return False, "Azure authentication failed. Check the credentials or the managed identity."
        except HttpResponseError as exc:
            if getattr(exc, "status_code", None) == 403:
                return False, (
                    "Access denied by Azure. The identity needs the 'Key Vault Reader' role "
                    "on the vault (or its resource group)."
                )
            logger.warning("Azure Key Vault error for source '%s': %s", self.source.name, exc.__class__.__name__)
            return False, "Azure Key Vault returned an error. Check the vault URL and try again."
        except ValueError as exc:
            return False, str(exc)
        except Exception:
            logger.exception("Unexpected error testing Azure Key Vault source '%s'", self.source.name)
            return False, "Unexpected error contacting Azure Key Vault."
        return True, f"Connected. {count} certificate(s) visible in the vault."
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `python -m pytest tests/test_azure_kv_adapter.py -v -p no:django`
Expected: all pass (8 from Task 4 + 10 new).

- [ ] **Step 5: Commit**

```bash
git add netbox_ssl/adapters/azure_kv.py tests/test_azure_kv_adapter.py
git commit -m "feat: Azure adapter connection test and vault URL validation (#101)

Hostname validation is the adapter's own SSRF guard: the Azure SDK
bypasses BaseAdapter._make_request, exactly as boto3 does, so the base
class's size cap and redirect blocking never see the request.

A 403 returns an actionable message naming Key Vault Reader; an auth
failure returns a generic one, and the underlying exception text is
never surfaced."
```

---

### Task 6: `fetch_certificates` — listing and mapping

**Files:**
- Modify: `netbox_ssl/adapters/azure_kv.py`
- Test: `tests/test_azure_kv_adapter.py` (append)

**Interfaces:**
- Consumes: `_get_client()` (Task 5); `CertificateParser.parse_der` from `netbox_ssl.utils.parser`.
- Produces: `fetch_certificates() -> list[FetchedCertificate]`, `get_certificate_detail(external_id)`, `_to_fetched(kv_cert) -> FetchedCertificate | None`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_azure_kv_adapter.py`:

```python
def _kv_cert(name="test-webserver", der=b"", enabled=True, tags=None, expires=None):
    """Build a stub KeyVaultCertificate."""
    from datetime import datetime, timedelta, timezone

    cert = MagicMock()
    cert.cer = der
    cert.name = name
    cert.properties.id = f"https://kv.vault.azure.net/certificates/{name}"
    cert.properties.enabled = enabled
    cert.properties.tags = tags or {}
    cert.properties.expires_on = expires or datetime.now(timezone.utc) + timedelta(days=365)
    return cert


class TestFetchCertificates:
    def _der(self, cn="www.netbox-ssl-demo.test"):
        from cert_factory import CertFactory
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        pem = CertFactory.create(cn=cn, extended_key_usage=["server"])
        return x509.load_pem_x509_certificate(pem.encode()).public_bytes(serialization.Encoding.DER)

    def test_maps_a_certificate_through_the_plugin_parser(self, monkeypatch):
        from netbox_ssl.adapters import azure_kv

        kv_cert = _kv_cert(der=self._der())
        client = MagicMock()
        client.list_properties_of_certificates.return_value = iter([kv_cert.properties])
        client.get_certificate.return_value = kv_cert
        monkeypatch.setattr(azure_kv, "CertificateClient", lambda **kw: client)

        results = azure_kv.AzureKvAdapter(_source()).fetch_certificates()

        assert len(results) == 1
        fetched = results[0]
        assert fetched.common_name == "www.netbox-ssl-demo.test"
        assert fetched.external_id == "https://kv.vault.azure.net/certificates/test-webserver"
        assert fetched.pem_content.startswith("-----BEGIN CERTIFICATE-----")
        assert ":" in fetched.fingerprint_sha256  # canonical colon-separated form
        assert fetched.certificate_type == "server"  # from EKU, via the parser

    def test_certificate_without_cer_is_skipped_not_fatal(self, monkeypatch):
        """A certificate still being issued has no public part yet."""
        from netbox_ssl.adapters import azure_kv

        pending = _kv_cert(name="pending", der=None)
        good = _kv_cert(name="good", der=self._der("api.netbox-ssl-demo.test"))
        client = MagicMock()
        client.list_properties_of_certificates.return_value = iter(
            [pending.properties, good.properties]
        )
        client.get_certificate.side_effect = [pending, good]
        monkeypatch.setattr(azure_kv, "CertificateClient", lambda **kw: client)

        results = azure_kv.AzureKvAdapter(_source()).fetch_certificates()

        assert [r.common_name for r in results] == ["api.netbox-ssl-demo.test"]

    def test_one_failing_certificate_does_not_abort_the_run(self, monkeypatch):
        from netbox_ssl.adapters import azure_kv

        good = _kv_cert(name="good", der=self._der("api.netbox-ssl-demo.test"))
        client = MagicMock()
        client.list_properties_of_certificates.return_value = iter(
            [MagicMock(name="broken"), good.properties]
        )
        client.get_certificate.side_effect = [RuntimeError("transient"), good]
        monkeypatch.setattr(azure_kv, "CertificateClient", lambda **kw: client)

        results = azure_kv.AzureKvAdapter(_source()).fetch_certificates()

        assert len(results) == 1
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `python -m pytest tests/test_azure_kv_adapter.py -v -p no:django -k FetchCertificates`
Expected: FAIL — `NotImplementedError`.

- [ ] **Step 3: Implement fetching and mapping**

Replace the `fetch_certificates` and `get_certificate_detail` placeholders:

```python
    def _to_fetched(self, kv_cert) -> FetchedCertificate | None:
        """Convert one KeyVaultCertificate into a FetchedCertificate.

        Everything X.509 knows comes from X.509: the DER bytes go through the
        plugin's own parser, which yields canonical values and keeps this
        adapter consistent with every other import path. Azure's own
        x509_thumbprint is deliberately unused — it is SHA-1.

        Returns:
            The mapped certificate, or None if it carries no public part yet.
        """
        from ..utils.parser import CertificateParser

        der = getattr(kv_cert, "cer", None)
        if not der:
            logger.info(
                "Skipping Azure certificate '%s': no public certificate yet (issuance pending)",
                getattr(kv_cert, "name", "?"),
            )
            return None

        parsed = CertificateParser.parse_der(bytes(der))
        props = kv_cert.properties

        return FetchedCertificate(
            external_id=str(props.id),
            common_name=parsed.common_name,
            serial_number=parsed.serial_number,
            fingerprint_sha256=parsed.fingerprint_sha256,
            issuer=parsed.issuer,
            valid_from=parsed.valid_from,
            valid_to=parsed.valid_to,
            sans=tuple(parsed.sans),
            key_size=parsed.key_size,
            algorithm=parsed.algorithm,
            pem_content=parsed.pem_content,
            issuer_chain=parsed.issuer_chain,
            certificate_type=parsed.certificate_type,
            # Task 7 replaces these two literals with the mappers.
            tags=(),
            status=None,
        )

    def fetch_certificates(self) -> list[FetchedCertificate]:
        """Fetch every certificate in the vault.

        A failure on one certificate is logged and skipped: one bad entry must
        never cost the operator the whole sync run.
        """
        client = self._get_client()
        results: list[FetchedCertificate] = []

        for props in client.list_properties_of_certificates():
            name = getattr(props, "name", None)
            try:
                kv_cert = client.get_certificate(name)
                fetched = self._to_fetched(kv_cert)
            except Exception:
                logger.exception("Skipping Azure certificate '%s': fetch failed", name)
                continue
            if fetched is not None:
                results.append(fetched)

        logger.info("Fetched %d certificate(s) from Azure Key Vault", len(results))
        return results

    def get_certificate_detail(self, external_id: str) -> FetchedCertificate | None:
        """Fetch one certificate by its vault URI.

        Args:
            external_id: The full vault-scoped certificate URI.

        Returns:
            The mapped certificate, or None if it is gone or has no public part.
        """
        name = external_id.rstrip("/").split("/")[-1]
        try:
            return self._to_fetched(self._get_client().get_certificate(name))
        except ResourceNotFoundError:
            return None
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `python -m pytest tests/test_azure_kv_adapter.py -v -p no:django -k FetchCertificates`
Expected: 3 passed. Tags and status are literals here; Tasks 7 and 8 wire in the mappers and the prohibited-field assertion, each with their own failing test first.

- [ ] **Step 5: Commit**

```bash
git add netbox_ssl/adapters/azure_kv.py tests/test_azure_kv_adapter.py
git commit -m "feat: Azure adapter fetches and maps certificates (#101)

Mapping is parse-first: the DER bytes go through CertificateParser, so
the adapter produces canonical values and inherits parser work such as
v1.4.0's EKU-based certificate_type instead of drifting from the other
import paths. Azure's x509_thumbprint is unused — it is SHA-1.

A certificate with no public part yet, or one that fails to fetch, is
skipped with a log line rather than aborting the run."
```

---

### Task 7: Status and tag mapping

**Files:**
- Modify: `netbox_ssl/adapters/azure_kv.py`
- Test: `tests/test_azure_kv_adapter.py` (append)

**Interfaces:**
- Consumes: `_to_fetched` (Task 6).
- Produces: `_map_status(props, valid_to) -> str`, `_map_tags(props) -> tuple[str, ...]`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_azure_kv_adapter.py`:

```python
class TestStatusMapping:
    def _fetch_one(self, monkeypatch, **cert_kwargs):
        from cert_factory import CertFactory
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        from netbox_ssl.adapters import azure_kv

        pem = CertFactory.create(cn="status.example.com", extended_key_usage=["server"])
        der = x509.load_pem_x509_certificate(pem.encode()).public_bytes(serialization.Encoding.DER)
        kv_cert = _kv_cert(der=der, **cert_kwargs)
        client = MagicMock()
        client.list_properties_of_certificates.return_value = iter([kv_cert.properties])
        client.get_certificate.return_value = kv_cert
        monkeypatch.setattr(azure_kv, "CertificateClient", lambda **kw: client)
        return azure_kv.AzureKvAdapter(_source()).fetch_certificates()[0]

    def test_disabled_certificate_maps_to_archived(self, monkeypatch):
        assert self._fetch_one(monkeypatch, enabled=False).status == "archived"

    def test_valid_enabled_certificate_maps_to_active(self, monkeypatch):
        assert self._fetch_one(monkeypatch, enabled=True).status == "active"

    def test_expired_certificate_maps_to_expired(self, monkeypatch):
        """Expiry is judged on the parsed X.509 validity, not Azure metadata."""
        from cert_factory import CertFactory
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        from netbox_ssl.adapters import azure_kv

        pem = CertFactory.create(cn="old.example.com", expired=True, extended_key_usage=["server"])
        der = x509.load_pem_x509_certificate(pem.encode()).public_bytes(serialization.Encoding.DER)
        kv_cert = _kv_cert(der=der, enabled=True)
        client = MagicMock()
        client.list_properties_of_certificates.return_value = iter([kv_cert.properties])
        client.get_certificate.return_value = kv_cert
        monkeypatch.setattr(azure_kv, "CertificateClient", lambda **kw: client)

        assert azure_kv.AzureKvAdapter(_source()).fetch_certificates()[0].status == "expired"

    def test_disabled_beats_expired(self, monkeypatch):
        """An operator disabling a certificate is a stronger signal than expiry."""
        assert self._fetch_one(monkeypatch, enabled=False).status == "archived"


class TestTagMapping:
    def _fetch_with_tags(self, monkeypatch, tags, sync_tags):
        from cert_factory import CertFactory
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        from netbox_ssl.adapters import azure_kv

        pem = CertFactory.create(cn="tagged.example.com", extended_key_usage=["server"])
        der = x509.load_pem_x509_certificate(pem.encode()).public_bytes(serialization.Encoding.DER)
        kv_cert = _kv_cert(der=der, tags=tags)
        client = MagicMock()
        client.list_properties_of_certificates.return_value = iter([kv_cert.properties])
        client.get_certificate.return_value = kv_cert
        monkeypatch.setattr(azure_kv, "CertificateClient", lambda **kw: client)
        return azure_kv.AzureKvAdapter(_source(sync_tags=sync_tags)).fetch_certificates()[0]

    def test_key_value_pairs_become_key_equals_value(self, monkeypatch):
        fetched = self._fetch_with_tags(monkeypatch, {"env": "prod", "owner": "team-a"}, True)
        assert set(fetched.tags) == {"env=prod", "owner=team-a"}

    def test_valueless_tag_keeps_only_the_key(self, monkeypatch):
        fetched = self._fetch_with_tags(monkeypatch, {"reviewed": ""}, True)
        assert fetched.tags == ("reviewed",)

    def test_tags_are_not_collected_when_sync_tags_is_off(self, monkeypatch):
        fetched = self._fetch_with_tags(monkeypatch, {"env": "prod"}, False)
        assert fetched.tags == ()

    def test_tag_order_is_deterministic(self, monkeypatch):
        fetched = self._fetch_with_tags(monkeypatch, {"z": "1", "a": "2"}, True)
        assert fetched.tags == ("a=2", "z=1")
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `python -m pytest tests/test_azure_kv_adapter.py -v -p no:django -k "StatusMapping or TagMapping"`
Expected: FAIL — `AttributeError: '_map_status'` (or the stubs return `None`/`()` where a value is expected).

- [ ] **Step 3: Implement the two mappers and call them**

Add both methods to `AzureKvAdapter`, then replace the two literals Task 6 left
in `_to_fetched`:

```python
            certificate_type=parsed.certificate_type,
            tags=self._map_tags(props),
            status=self._map_status(props, parsed.valid_to),
        )
```

The methods themselves:

```python
    @staticmethod
    def _map_status(props, valid_to) -> str:
        """Map Azure certificate state onto a plugin status.

        A disabled certificate outranks an expired one: disabling is an
        explicit operator action, while expiry is a fact about the clock.
        """
        from datetime import datetime, timezone

        from ..models import CertificateStatusChoices

        if getattr(props, "enabled", True) is False:
            return CertificateStatusChoices.STATUS_ARCHIVED
        if valid_to and valid_to < datetime.now(timezone.utc):
            return CertificateStatusChoices.STATUS_EXPIRED
        return CertificateStatusChoices.STATUS_ACTIVE

    def _map_tags(self, props) -> tuple[str, ...]:
        """Flatten Azure's key/value tags into NetBox tag names.

        `key`/`value` becomes `key=value`; a valueless tag keeps just the key.
        Sorted so a sync run produces the same order every time. Returns empty
        unless the source opted in.
        """
        if not getattr(self.source, "sync_tags", False):
            return ()
        tags = getattr(props, "tags", None) or {}
        return tuple(sorted(f"{key}={value}" if value else str(key) for key, value in tags.items()))
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `python -m pytest tests/test_azure_kv_adapter.py -v -p no:django`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add netbox_ssl/adapters/azure_kv.py tests/test_azure_kv_adapter.py
git commit -m "feat: Azure adapter status and tag mapping (#101)

Disabled outranks expired: disabling is an explicit operator action,
expiry is a fact about the clock. Expiry itself is judged on the parsed
X.509 validity rather than Azure metadata, so the two can never disagree.

Tags flatten to 'key=value', sorted for a stable sync diff, and are only
collected when the source opted in."
```

---

### Task 8: Security guards

**Files:**
- Modify: `netbox_ssl/adapters/azure_kv.py`
- Test: `tests/test_azure_kv_security.py` (create)

**Interfaces:**
- Consumes: `AzureKvAdapter` (Tasks 4–7).
- Produces: `_assert_no_prohibited_keys(obj) -> None` (raises `ValueError`).

- [ ] **Step 1: Write the failing test**

Create `tests/test_azure_kv_security.py`:

```python
"""Security invariants for the Azure Key Vault adapter (#101).

Layer 1 is Azure RBAC: `Key Vault Reader` grants certificates/read but not
secrets/getSecret, so the PFX is unreachable whatever the code does. These tests
cover the code-side layers, which exist so a future role change cannot silently
turn a metadata reader into a key exporter.
"""

import ast
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.unit

_project_root = Path(__file__).parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

# Importing the adapter pulls netbox_ssl/__init__.py, which imports
# netbox.plugins. NetBox is absent on the host lane, so mock it — the repo's
# established pattern, also used by test_credential_schema.py and test_adapters.py.
import importlib.util  # noqa: E402

try:
    _spec = importlib.util.find_spec("netbox")
    _NETBOX_AVAILABLE = _spec is not None and _spec.origin is not None
except (ValueError, ModuleNotFoundError):
    _NETBOX_AVAILABLE = False

if not _NETBOX_AVAILABLE and "netbox" not in sys.modules:
    sys.modules["netbox"] = MagicMock()
    sys.modules["netbox.plugins"] = MagicMock()

ADAPTER = Path(__file__).parent.parent / "netbox_ssl" / "adapters" / "azure_kv.py"


class TestAdapterNeverTouchesKeyMaterial:
    def test_module_never_imports_secret_or_key_clients(self):
        """A SecretClient is the only way to reach the PFX; it must not appear."""
        tree = ast.parse(ADAPTER.read_text())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)

        forbidden = {"SecretClient", "KeyClient"}
        assert not (imported & forbidden), (
            f"azure_kv.py imports {imported & forbidden}; a certificate's private key "
            "is reachable only through those clients"
        )

    def test_module_never_calls_key_or_secret_getters(self):
        source = ADAPTER.read_text()
        for forbidden in ("get_secret(", "get_key(", "backup_key(", "download_secret("):
            assert forbidden not in source, f"azure_kv.py calls {forbidden}"

    def test_module_never_dereferences_the_sid_or_kid_reference(self):
        """A certificate response carries sid/kid; they are metadata, never followed."""
        source = ADAPTER.read_text()
        for forbidden in (".sid", ".kid"):
            assert forbidden not in source, (
                f"azure_kv.py touches {forbidden}, which points at key/secret material"
            )


class TestProhibitedFieldAssertion:
    def test_response_carrying_key_material_fails_hard(self):
        from netbox_ssl.adapters.azure_kv import AzureKvAdapter

        source = MagicMock()
        source.base_url = "https://kv.vault.azure.net/"
        source.auth_method = "azure_managed_identity"
        adapter = AzureKvAdapter(source)

        poisoned = {"cer": b"x", "secret_value": "-----BEGIN PRIVATE KEY-----"}
        with pytest.raises(ValueError, match="prohibited"):
            adapter._assert_no_prohibited_keys(poisoned)

    def test_clean_response_passes(self):
        from netbox_ssl.adapters.azure_kv import AzureKvAdapter

        source = MagicMock()
        source.base_url = "https://kv.vault.azure.net/"
        source.auth_method = "azure_managed_identity"
        adapter = AzureKvAdapter(source)

        adapter._assert_no_prohibited_keys({"cer": b"x", "name": "ok"})
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `python -m pytest tests/test_azure_kv_security.py -v -p no:django`
Expected: FAIL on `_assert_no_prohibited_keys` not existing. The AST tests should already pass — if one fails, the adapter has a real problem; fix the adapter, never the test.

- [ ] **Step 3: Implement the assertion and call it**

Add the method below, then call it as the first statement of `_to_fetched`:

```python
        from ..utils.parser import CertificateParser

        self._assert_no_prohibited_keys(kv_cert)

        der = getattr(kv_cert, "cer", None)
```

The method itself:

```python
    @staticmethod
    def _assert_no_prohibited_keys(obj) -> None:
        """Fail hard if a response carries a field that could hold key material.

        Azure does not return key material from the certificates API today.
        This is a tripwire for the day it changes, or the day someone widens
        the RBAC role — see PROHIBITED_SYNC_FIELDS for the canonical list.

        Raises:
            ValueError: If any prohibited field name is present.
        """
        from .base import PROHIBITED_SYNC_FIELDS

        if isinstance(obj, dict):
            names = {str(key).lower() for key in obj}
        else:
            names = {name.lower() for name in dir(obj) if not name.startswith("_")}

        found = names & PROHIBITED_SYNC_FIELDS
        if found:
            raise ValueError(
                f"Azure Key Vault response contains prohibited field(s): {sorted(found)}. "
                "Refusing to process — this adapter must never handle key material."
            )
```

> **Note for the implementer:** `dir()` on a `MagicMock` returns a huge attribute
> set, so `_to_fetched`'s call to this assertion must run against the real
> object. If the Task 6 mock tests start failing with a spurious "prohibited
> field" error, give the stub `_kv_cert` a `spec=` so `dir()` is bounded — do not
> weaken the assertion.

- [ ] **Step 4: Run all adapter tests**

Run: `python -m pytest tests/test_azure_kv_security.py tests/test_azure_kv_adapter.py -v -p no:django`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add netbox_ssl/adapters/azure_kv.py tests/test_azure_kv_security.py
git commit -m "test: security invariants for the Azure adapter (#101)

AST guards assert the module never imports SecretClient or KeyClient,
never calls a key or secret getter, and never dereferences the sid/kid
references a certificate response carries. Plus the prohibited-field
tripwire AWS ACM uses.

These exist so a future RBAC change cannot silently turn a metadata
reader into a key exporter."
```

---

### Task 9: Expose `sync_tags` in the UI, API and GraphQL

**Files:**
- Modify: `netbox_ssl/forms/external_sources.py`, `netbox_ssl/api/serializers/external_sources.py`, `netbox_ssl/graphql/types.py`
- Test: `tests/test_azure_kv_model.py` (append)

**Interfaces:**
- Consumes: `ExternalSource.sync_tags` (Task 2).
- Produces: nothing new; makes the field operable.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_azure_kv_model.py`:

```python
class TestSyncTagsIsOperable:
    """A model field nobody can set is not a feature."""

    def _read(self, relative: str) -> str:
        return (Path(__file__).parent.parent / "netbox_ssl" / relative).read_text()

    def test_form_exposes_sync_tags(self):
        assert "sync_tags" in self._read("forms/external_sources.py")

    def test_serializer_exposes_sync_tags(self):
        assert "sync_tags" in self._read("api/serializers/external_sources.py")

    def test_graphql_exposes_sync_tags(self):
        assert "sync_tags" in self._read("graphql/types.py")
```

Add the import at the top of the file:

```python
from pathlib import Path
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `python -m pytest tests/test_azure_kv_model.py -v -p no:django -k SyncTags`
Expected: FAIL on all three.

- [ ] **Step 3: Add the field in all three places**

Each file already lists `verify_ssl`; insert `sync_tags` immediately after it.

`netbox_ssl/forms/external_sources.py` — **two** occurrences, around lines 40
and 76 (the fieldset and the `Meta.fields` tuple). Both need the addition:

```python
            "verify_ssl",
            "sync_tags",
```

`netbox_ssl/api/serializers/external_sources.py` — around line 60:

```python
            "verify_ssl",
            "sync_tags",
```

`netbox_ssl/graphql/types.py` — **two** occurrences. The explicit field list
around line 69:

```python
        "verify_ssl",
        "sync_tags",
```

and the type annotation around line 93:

```python
    verify_ssl: bool
    sync_tags: bool
```

> The GraphQL type **must** keep an explicit field list. `fields="__all__"` is
> forbidden by the project's security rules, and the field list and the
> annotations are two separate places — missing one gives a type that
> advertises a field it cannot resolve.

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `python -m pytest tests/test_azure_kv_model.py -v -p no:django`
Expected: 6 passed.

- [ ] **Step 5: Verify the OpenAPI schema still generates**

Run in the container:

```bash
docker exec netbox-ssl-netbox-1 python /opt/netbox/netbox/manage.py spectacular --validate --fail-on-warn > /dev/null && echo SCHEMA_OK
```

Expected: `SCHEMA_OK`.

- [ ] **Step 6: Commit**

```bash
git add netbox_ssl/forms/external_sources.py netbox_ssl/api/serializers/external_sources.py netbox_ssl/graphql/types.py tests/test_azure_kv_model.py
git commit -m "feat: expose sync_tags in form, API and GraphQL (#101)"
```

---

### Task 10: Live tests and the CI workflow

**Files:**
- Create: `tests/test_azure_kv_live.py`, `.github/workflows/azure-integration.yml`
- Modify: `pytest.ini`

**Interfaces:**
- Consumes: the whole adapter.
- Produces: the `azure_live` marker.

**Prerequisite:** `az login` locally, against the subscription in `azure-testresources-overdracht.md`.

- [ ] **Step 1: Register the marker**

In `pytest.ini`, under `markers`, add:

```
    azure_live: Live tests against the provisioned Azure Key Vault (maintainer-only; requires az login or CI OIDC)
```

- [ ] **Step 2: Write the live tests**

Create `tests/test_azure_kv_live.py`:

```python
"""Live tests against the provisioned Azure Key Vault.

Maintainer-only: the federated credential is scoped to refs/heads/main, so these
cannot run on a pull request. Locally they run after `az login`.

Vault and certificate names come from azure-testresources-overdracht.md.
"""

import os
from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.azure_live

VAULT_URL = os.environ.get("AZURE_TEST_VAULT_URL", "https://kv-nbssl-test-2609.vault.azure.net/")
EXPECTED_CERTS = {"test-webserver", "test-api-gateway", "test-bijna-verlopen"}


def _live_source():
    source = MagicMock()
    source.base_url = VAULT_URL
    source.auth_method = "azure_managed_identity"
    source.auth_credentials = {}
    source.sync_tags = True
    source.name = "azure-live-test"
    return source


@pytest.fixture(scope="module")
def adapter():
    pytest.importorskip("azure.keyvault.certificates")
    from netbox_ssl.adapters.azure_kv import AzureKvAdapter

    return AzureKvAdapter(_live_source())


def test_connection_succeeds(adapter):
    ok, message = adapter.test_connection()
    assert ok, message


def test_lists_the_three_provisioned_certificates(adapter):
    names = {c.external_id.rstrip("/").split("/")[-1] for c in adapter.fetch_certificates()}
    assert EXPECTED_CERTS.issubset(names), f"missing: {EXPECTED_CERTS - names}"


def test_public_certificate_is_readable_with_key_vault_reader(adapter):
    """Proves the documented minimum role is sufficient — the design's §2.1."""
    fetched = adapter.fetch_certificates()
    assert fetched, "no certificates returned"
    for cert in fetched:
        assert cert.pem_content.startswith("-----BEGIN CERTIFICATE-----")
        assert ":" in cert.fingerprint_sha256


def test_private_key_is_unreachable(adapter):
    """The privilege canary.

    Key Vault stores the PFX — certificate *and* private key — as a secret.
    `Key Vault Reader` grants secrets/readMetadata but not secrets/getSecret, so
    this must be refused. If someone widens the role to `Key Vault Certificate
    User`, this test fails loudly instead of the blast radius quietly growing.

    The adapter itself never constructs a SecretClient; this test does, to
    verify the platform-level guarantee rather than our own restraint.
    """
    from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
    from azure.identity import DefaultAzureCredential
    from azure.keyvault.secrets import SecretClient

    client = SecretClient(vault_url=VAULT_URL, credential=DefaultAzureCredential())
    with pytest.raises((HttpResponseError, ClientAuthenticationError)) as exc_info:
        client.get_secret("test-webserver")

    status = getattr(exc_info.value, "status_code", None)
    assert status == 403, (
        f"expected 403 Forbidden, got {status}. The identity may have been granted "
        "'Key Vault Certificate User', which allows private-key export."
    )
```

> `azure-keyvault-secrets` is needed only by this canary test. Add it to the
> `dev` extra, not to `azure` — production installs must not carry a secrets
> client at all.

- [ ] **Step 3: Run the live tests locally**

Run: `az login && python -m pytest tests/test_azure_kv_live.py -v -p no:django -m azure_live`
Expected: 4 passed. If `test_private_key_is_unreachable` fails with 200, stop and tell the maintainer — the role is wider than documented.

- [ ] **Step 4: Confirm the host lane still ignores them**

Run: `python -m pytest tests/ -m unit -q -p no:django`
Expected: passes, and the live tests are deselected rather than erroring on the marker.

- [ ] **Step 5: Add the workflow**

Create `.github/workflows/azure-integration.yml`:

```yaml
name: Azure Integration

# The federated credential is scoped to refs/heads/main, so this cannot run on a
# pull request — fork PRs have no path to Azure by design. During development the
# same checks run locally via `az login`; here they guard against drift.
on:
  workflow_dispatch:
  push:
    branches: [main]
    paths:
      - "netbox_ssl/adapters/azure_kv.py"
      - "tests/test_azure_kv_live.py"
      - ".github/workflows/azure-integration.yml"

permissions:
  id-token: write   # required for OIDC
  contents: read

jobs:
  integration-azure:
    name: Azure Key Vault (live)
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install
        run: pip install -e '.[azure,dev]'

      - uses: azure/login@v2
        with:
          client-id: ${{ vars.AZURE_CLIENT_ID }}
          tenant-id: ${{ vars.AZURE_TENANT_ID }}
          subscription-id: ${{ vars.AZURE_SUBSCRIPTION_ID }}

      - name: Live adapter tests
        run: python -m pytest tests/test_azure_kv_live.py -v -p no:django -m azure_live
```

- [ ] **Step 6: Set the repository variables**

These are identifiers, not secrets. Values are in `azure-testresources-overdracht.md`.

```bash
gh variable set AZURE_CLIENT_ID --body "<client-id from the handover doc>"
gh variable set AZURE_TENANT_ID --body "<tenant-id>"
gh variable set AZURE_SUBSCRIPTION_ID --body "<subscription-id>"
gh variable list
```

- [ ] **Step 7: Commit**

```bash
git add tests/test_azure_kv_live.py .github/workflows/azure-integration.yml pytest.ini pyproject.toml
git commit -m "test: live Azure Key Vault tests and OIDC workflow (#101)

Maintainer-only: the federated credential is scoped to refs/heads/main,
so these cannot run on the PR that introduces them. Local verification
uses the same code path via az login.

Includes a privilege canary asserting SecretClient returns 403 — it
verifies the platform guarantee rather than our own restraint, and fails
loudly if the role is ever widened to Key Vault Certificate User."
```

---

### Task 11: Documentation

**Files:**
- Create: `docs/how-to/azure-key-vault-sync.md`
- Modify: `mkdocs.yml`, `docs/reference/data-models.md`, `docs/reference/api.md`, `README.md`, `CHANGELOG.md`, `COMPATIBILITY.md`

- [ ] **Step 1: Run the documentation coverage guards to see what they demand**

Run: `python -m pytest tests/test_docs_coverage.py -v -p no:django`
Expected: FAIL — `sync_tags` and the new source type are undocumented. These guards were added in v1.4.0 exactly to catch this.

- [ ] **Step 2: Write the how-to**

Create `docs/how-to/azure-key-vault-sync.md` covering:

- **When to use this** — Azure-managed PKI, read-only inventory.
- **Step 1 — grant access.** The minimum role is **`Key Vault Reader`**, on the vault or its resource group. State plainly that `Key Vault Certificate User` is *not* required and should not be used: it grants `secrets/getSecret/action`, which permits downloading the PFX including the private key, and the plugin never needs it.
- **Step 2 — choose an auth method.** `Azure Managed Identity` when NetBox runs on Azure or with a federated workload identity (nothing to store); `Azure Service Principal` otherwise, with `tenant_id`, `client_id` and `client_secret` as `env:VAR_NAME` references.
- **Step 3 — create the source.** Vault URL as the base URL; one source per vault.
- **Step 4 — optional tag sync.** `sync_tags` is off by default; Azure `key`/`value` pairs become NetBox tags named `key=value`.
- **Step 5 — schedule.** Via the `ExternalSourceSync` script; link to the `SCRIPTS_ROOT` note in [Custom Scripts](../reference/scripts.md).
- **Status mapping** table: disabled → Archived, expired → Expired, otherwise Active.
- **What it never does** — no issuance, no renewal, no key material. Reference ADR-02.
- **Troubleshooting** — 403 names the role; a soft-deleted certificate disappears from the listing and is marked `source_removed`; a certificate still being issued has no public part and is skipped.

- [ ] **Step 3: Add it to the navigation**

In `mkdocs.yml`, add `- how-to/azure-key-vault-sync.md` to the How-to section, after `aws-acm-sync.md`.

- [ ] **Step 4: Update the reference docs**

- `docs/reference/data-models.md` — add `sync_tags` to the `ExternalSource` field table.
- `docs/reference/api.md` — note `azure_kv` as a `source_type` value and `sync_tags` on the external-sources collection.
- `README.md` — add Azure Key Vault to the External Sources feature paragraph.
- `COMPATIBILITY.md` — no version change; add a line noting the optional `azure` extra.

- [ ] **Step 5: Write the CHANGELOG entry**

Under `## [Unreleased]`, `### Added`:

```markdown
- **Azure Key Vault external source** ([#101](https://github.com/ctrl-alt-automate/netbox-ssl/issues/101)):
  read-only sync of certificate metadata from one Azure Key Vault, with managed
  identity / workload identity or an explicit service principal. Certificate
  fields are parsed from the vault's DER bytes by the plugin's own parser, so
  they match every other import path — including EKU-based certificate type.
  Optional tag sync (`sync_tags`, off by default) copies Azure tags onto
  imported certificates. Requires `pip install netbox-ssl[azure]`. The minimum
  Azure role is **`Key Vault Reader`**; `Key Vault Certificate User` is
  deliberately *not* required, because it also grants private-key export.
  Migration 0028 is additive.
- **Sync now records status, certificate type and tags**: `FetchedCertificate`
  gained three optional fields, closing two long-standing gaps — sync used to
  hardcode every imported certificate to Active, and never applied the EKU-based
  certificate type added in v1.4.0. All four adapters benefit as they populate
  them.
```

- [ ] **Step 6: Run the coverage guards and the full suite**

Run:

```bash
python -m pytest tests/test_docs_coverage.py -v -p no:django
python -m pytest tests/ -m unit -q -p no:django
ruff check netbox_ssl/ tests/ && ruff format --check netbox_ssl/ tests/
```

Expected: all green.

- [ ] **Step 7: Commit**

```bash
git add docs/ mkdocs.yml README.md CHANGELOG.md COMPATIBILITY.md
git commit -m "docs: Azure Key Vault how-to and reference updates (#101)

States Key Vault Reader as the minimum role and explains why Key Vault
Certificate User is deliberately not recommended: it grants
secrets/getSecret, which permits private-key export."
```

---

## Definition of Done

- [ ] All 11 tasks complete, each committed separately
- [ ] `python -m pytest tests/ -m unit -q -p no:django` green
- [ ] Container lane green, including `test_sync_engine.py` and `test_sync_engine_contract.py`
- [ ] `ruff check` and `ruff format --check` clean
- [ ] `makemigrations --check` reports no drift
- [ ] `spectacular --validate --fail-on-warn` clean
- [ ] Live tests pass against the provisioned vault, **including the privilege canary**
- [ ] `tests/test_docs_coverage.py` green
- [ ] PR to `dev` with `Closes #101` in the body
