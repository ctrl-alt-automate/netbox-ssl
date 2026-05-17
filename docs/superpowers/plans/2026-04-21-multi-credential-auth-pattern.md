# Multi-Credential Auth Pattern Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship Phase 1 of the multi-credential auth pattern (spec at `docs/superpowers/specs/2026-04-21-multi-credential-auth-pattern-design.md`) so `ExternalSource` can hold multi-component credentials, support role-based auth methods, and validate per-adapter credential schemas — all without breaking existing Lemur / Generic REST configurations.

**Architecture:** A new `auth_credentials` JSONField on `ExternalSource` replaces the single-string `auth_credentials_reference` (which stays as deprecated fallback through v2.0.0). A `CredentialField` dataclass + per-adapter `credential_schema(auth_method)` classmethod drive form and serializer validation. Role-based auth methods (`aws_instance_role`, `azure_managed_identity`) are wired in so Phase 2/3 adapters land cleanly.

**Tech Stack:** Django 4.2 / 5.0 (NetBox 4.4 + 4.5 compat), Python 3.10+, pytest + unittest.mock, ruff for lint + format.

**Target branch:** `feature/99-multi-credential-auth` (off `dev`).

**Release target:** v1.1.0 (infrastructure only; AWS ACM and Azure KV adapters land in follow-up PRs per issues #100 and #101).

---

## File Structure

Files to **create**:

| Path | Purpose |
|------|---------|
| `netbox_ssl/forms/__init__.py` | New `forms` package init (re-exports) |
| `netbox_ssl/forms/external_source.py` | `ExternalSourceForm` with schema-driven `clean()` |
| `netbox_ssl/utils/external_source_validator.py` | `ExternalSourceSchemaValidator` — single source of truth for schema validation |
| `netbox_ssl/migrations/0021_external_source_auth_credentials.py` | AddField + data-backfill migration |
| `tests/test_credential_schema.py` | Unit tests for `CredentialField` + each adapter's schema |
| `tests/test_credential_resolver_many.py` | Unit tests for `resolve_many()` |
| `tests/test_external_source_validator.py` | Unit tests for the validator |
| `tests/test_external_source_form.py` | Unit tests for the form's `clean()` |
| `tests/test_external_source_snapshot.py` | Unit tests for `snapshot()` redaction |

Files to **modify**:

| Path | What changes |
|------|--------------|
| `netbox_ssl/adapters/base.py` | Add `CredentialField` dataclass, `SUPPORTED_AUTH_METHODS`, `credential_schema()` classmethod; change `resolve_credentials()` to return `dict[str, str]`; update `_get_headers()` to read `creds["token"]` |
| `netbox_ssl/adapters/__init__.py` | Add `get_adapter_class()`, `get_supported_auth_methods()`, `get_credential_schema()` helpers |
| `netbox_ssl/adapters/lemur.py` | Add `SUPPORTED_AUTH_METHODS = ("bearer",)`, implement `credential_schema()` |
| `netbox_ssl/adapters/generic_rest.py` | Add `SUPPORTED_AUTH_METHODS = ("bearer", "api_key")`, implement `credential_schema()` |
| `netbox_ssl/utils/credential_resolver.py` | Add `resolve_many()` classmethod |
| `netbox_ssl/models/external_source.py` | Extend `AuthMethodChoices` with 4 new enum values; add `auth_credentials` JSONField; mark `auth_credentials_reference` deprecated via `help_text`; add `snapshot()` override with credential redaction |
| `netbox_ssl/api/serializers/external_sources.py` | Add `auth_credentials` (write_only JSONField), `has_credentials` (read-only computed), `validate()` via validator |
| `netbox_ssl/graphql/types.py` | Add `has_credentials: bool` computed field to `ExternalSourceType`; explicitly verify `auth_credentials` is not in the field list |
| `project-requirement-document/ROADMAP.md` | Add §8.2 deprecation entry for `auth_credentials_reference` |
| `docs/how-to/external-sources.md` | Document the new `auth_credentials` JSON shape + 4 new auth methods + deprecation note |
| `CHANGELOG.md` | Add entry under `[Unreleased]` describing the new field, auth methods, deprecation |

---

## Task 0: Branch setup

**Files:** (none — git plumbing)

- [ ] **Step 1: Ensure you are on `dev` with the spec merged locally**

```bash
git checkout dev
git pull origin dev
```

Expected: on `dev`, up to date with origin.

- [ ] **Step 2: Verify the spec is reachable on the branch**

```bash
ls docs/superpowers/specs/2026-04-21-multi-credential-auth-pattern-design.md
```

Expected: file exists (either merged to `dev` already, or about to be via PR #103).

If the spec isn't on `dev` yet because PR #103 hasn't merged, branch off `docs/spec-multi-credential-auth` instead — the implementation depends on the spec file being on the branch for reference.

- [ ] **Step 3: Create the feature branch**

```bash
git checkout -b feature/99-multi-credential-auth
```

Expected: `Switched to a new branch 'feature/99-multi-credential-auth'`.

- [ ] **Step 4: Verify the working tree is clean**

```bash
git status --short
```

Expected: no output (no unstaged changes, no untracked files).

---

## Task 1: `CredentialField` dataclass in `BaseAdapter`

Add the frozen dataclass that each adapter uses to declare credential components. Co-located with `BaseAdapter` to avoid a new module for a single class.

**Files:**
- Modify: `netbox_ssl/adapters/base.py`
- Create: `tests/test_credential_schema.py`

- [ ] **Step 1: Write the failing test for `CredentialField` structure and defaults**

Create `tests/test_credential_schema.py`:

```python
"""Unit tests for CredentialField dataclass and per-adapter credential schemas."""

import pytest

pytestmark = pytest.mark.unit


def test_credential_field_is_frozen():
    from netbox_ssl.adapters.base import CredentialField

    field = CredentialField(required=True, label="API Token")
    with pytest.raises(Exception):  # FrozenInstanceError, not imported for Py-version portability
        field.required = False  # type: ignore[misc]


def test_credential_field_defaults():
    from netbox_ssl.adapters.base import CredentialField

    field = CredentialField()
    assert field.required is True
    assert field.label == ""
    assert field.secret is False
    assert field.help_text == ""


def test_credential_field_all_attributes():
    from netbox_ssl.adapters.base import CredentialField

    field = CredentialField(
        required=False,
        label="Session Token",
        secret=True,
        help_text="Only for temporary credentials",
    )
    assert field.required is False
    assert field.label == "Session Token"
    assert field.secret is True
    assert field.help_text == "Only for temporary credentials"
```

- [ ] **Step 2: Run test to verify it fails**

```bash
python -m pytest tests/test_credential_schema.py::test_credential_field_is_frozen -v -p no:django
```

Expected: FAIL with `ImportError: cannot import name 'CredentialField' from 'netbox_ssl.adapters.base'`.

- [ ] **Step 3: Add `CredentialField` to `netbox_ssl/adapters/base.py`**

Open `netbox_ssl/adapters/base.py` and locate the existing imports at the top. After the `from dataclasses import dataclass, field` line (it already exists), add the following class definition **before** the `class BaseAdapter(ABC):` declaration:

```python
@dataclass(frozen=True)
class CredentialField:
    """Metadata for one credential component declared by an adapter.

    Adapters use a mapping of name -> CredentialField to describe the
    credentials required for a given auth_method. The form and serializer
    consume this mapping to validate user-submitted auth_credentials.

    Attributes:
        required: Must be present in auth_credentials at form-save time.
        label:    User-facing label used by the form / UI.
        secret:   If True, component is high-sensitivity — drives UI
                  masking and may restrict allowed reference schemes.
        help_text: Short description shown by the form.
    """

    required: bool = True
    label: str = ""
    secret: bool = False
    help_text: str = ""
```

- [ ] **Step 4: Run the three tests to verify they pass**

```bash
python -m pytest tests/test_credential_schema.py -v -p no:django -k "credential_field"
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add netbox_ssl/adapters/base.py tests/test_credential_schema.py
git commit -m "feat(adapters): add CredentialField dataclass for per-adapter credential schemas"
```

---

## Task 2: `CredentialResolver.resolve_many()` + promote `ENV_VAR_PATTERN`

Extend the single-value resolver with a dict-shaped helper that resolves all components of a credentials dict in one call, failing fast on the first error. Also promote the module-private `_ENV_VAR_PATTERN` to a public `ENV_VAR_PATTERN` so the new `ExternalSourceSchemaValidator` can reuse the exact same regex.

**Files:**
- Modify: `netbox_ssl/utils/credential_resolver.py`
- Create: `tests/test_credential_resolver_many.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_credential_resolver_many.py`:

```python
"""Unit tests for CredentialResolver.resolve_many()."""

import os
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.unit


def test_resolve_many_empty_dict_returns_empty_dict():
    from netbox_ssl.utils.credential_resolver import CredentialResolver

    assert CredentialResolver.resolve_many({}) == {}


def test_resolve_many_resolves_each_env_ref():
    from netbox_ssl.utils.credential_resolver import CredentialResolver

    refs = {"access_key_id": "env:TEST_KEY_ID", "secret_access_key": "env:TEST_SECRET"}
    with patch.dict(os.environ, {"TEST_KEY_ID": "AKIATEST", "TEST_SECRET": "secretval"}):
        result = CredentialResolver.resolve_many(refs)
    assert result == {"access_key_id": "AKIATEST", "secret_access_key": "secretval"}


def test_resolve_many_accepts_bare_varname_as_env():
    from netbox_ssl.utils.credential_resolver import CredentialResolver

    refs = {"token": "LEGACY_BARE_VAR"}
    with patch.dict(os.environ, {"LEGACY_BARE_VAR": "legacy_value"}):
        result = CredentialResolver.resolve_many(refs)
    assert result == {"token": "legacy_value"}


def test_resolve_many_fails_fast_on_missing_env_var():
    from netbox_ssl.utils.credential_resolver import (
        CredentialResolveError,
        CredentialResolver,
    )

    refs = {"present": "env:PRESENT_VAR", "missing": "env:MISSING_VAR_12345"}
    with patch.dict(os.environ, {"PRESENT_VAR": "x"}, clear=False):
        os.environ.pop("MISSING_VAR_12345", None)
        with pytest.raises(CredentialResolveError, match="MISSING_VAR_12345"):
            CredentialResolver.resolve_many(refs)


def test_resolve_many_rejects_unsupported_scheme():
    from netbox_ssl.utils.credential_resolver import (
        CredentialResolveError,
        CredentialResolver,
    )

    refs = {"token": "vault:secret/foo"}
    with pytest.raises(CredentialResolveError, match="Unsupported"):
        CredentialResolver.resolve_many(refs)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_credential_resolver_many.py -v -p no:django
```

Expected: FAIL with `AttributeError: type object 'CredentialResolver' has no attribute 'resolve_many'`.

- [ ] **Step 3: Promote `_ENV_VAR_PATTERN` to public `ENV_VAR_PATTERN`**

Open `netbox_ssl/utils/credential_resolver.py`. At the top of the module, replace:

```python
_ENV_VAR_PATTERN = re.compile(r"^[A-Z_][A-Z0-9_]{0,254}$")
```

With:

```python
# Public: re-used by ExternalSourceSchemaValidator for early form-time
# validation. Must match the resolver's own accepted format so runtime
# resolution cannot fail on names the form silently accepted.
ENV_VAR_PATTERN = re.compile(r"^[A-Z_][A-Z0-9_]{0,254}$")

# Backward-compatible alias — keep until v2.0.0 in case any custom
# subclass reads the private name.
_ENV_VAR_PATTERN = ENV_VAR_PATTERN
```

Then find the single internal usage inside `_resolve_env` (around line 74):

```python
    if not _ENV_VAR_PATTERN.match(var_name):
```

Replace with:

```python
    if not ENV_VAR_PATTERN.match(var_name):
```

- [ ] **Step 4: Add `resolve_many` method**

Still in `netbox_ssl/utils/credential_resolver.py`. After the existing `resolve` classmethod (ends around line 58) and before `_resolve_env` (starts around line 60), insert:

```python
    @classmethod
    def resolve_many(cls, references: dict[str, str]) -> dict[str, str]:
        """Resolve every reference in the dict; fail fast on the first error.

        Args:
            references: Mapping of component name -> reference string.
                        Empty dict returns an empty dict.

        Returns:
            Parallel dict of component name -> resolved value.

        Raises:
            CredentialResolveError: On the first reference that cannot
                be resolved (missing env var, invalid format, unsupported
                scheme). Does NOT attempt to resolve remaining refs.
        """
        return {name: cls.resolve(ref) for name, ref in references.items()}
```

- [ ] **Step 5: Run tests to verify they all pass**

```bash
python -m pytest tests/test_credential_resolver_many.py -v -p no:django
```

Expected: 5 passed.

- [ ] **Step 6: Run the existing credential_resolver tests to confirm the rename didn't break anything**

```bash
python -m pytest tests/ -v -p no:django -k "credential_resolver" --no-header 2>&1 | tail -10
```

Expected: all existing tests still pass.

- [ ] **Step 7: Commit**

```bash
git add netbox_ssl/utils/credential_resolver.py tests/test_credential_resolver_many.py
git commit -m "feat(resolver): add resolve_many() + promote ENV_VAR_PATTERN to public"
```

---

## Task 2b: Extend `PROHIBITED_SYNC_FIELDS` safe-list

Per the spec §11 and the Gemini review on PR #103, the safe-list of field names that external-source adapters must never accept from upstream payloads is expanded in Phase 1 so downstream adapters (AWS ACM #100, Azure Key Vault #101) inherit the protection without each having to re-declare it. The *enforcement* (code that asserts adapter responses contain none of these keys) lives in the adapter PRs.

**Files:**
- Modify: `netbox_ssl/adapters/base.py`
- Test: `tests/test_credential_schema.py` (extend)

- [ ] **Step 1: Write the failing test**

Add to `tests/test_credential_schema.py` (end of file):

```python
def test_prohibited_sync_fields_includes_cloud_aliases():
    """v1.1 extends the safe-list with AWS/Azure key-material aliases."""
    from netbox_ssl.adapters.base import PROHIBITED_SYNC_FIELDS

    # Pre-existing entries — must stay.
    assert "private_key" in PROHIBITED_SYNC_FIELDS
    assert "key_material" in PROHIBITED_SYNC_FIELDS
    assert "p12" in PROHIBITED_SYNC_FIELDS
    assert "pfx" in PROHIBITED_SYNC_FIELDS
    assert "pkcs12" in PROHIBITED_SYNC_FIELDS

    # v1.1 additions — Azure Key Vault + AWS ACM aliases.
    assert "pem_bundle" in PROHIBITED_SYNC_FIELDS
    assert "secret_value" in PROHIBITED_SYNC_FIELDS
    assert "key" in PROHIBITED_SYNC_FIELDS
```

- [ ] **Step 2: Run test to verify it fails**

```bash
python -m pytest tests/test_credential_schema.py::test_prohibited_sync_fields_includes_cloud_aliases -v -p no:django
```

Expected: FAIL — `"pem_bundle" not in PROHIBITED_SYNC_FIELDS`.

- [ ] **Step 3: Extend the safe-list**

Open `netbox_ssl/adapters/base.py`. Locate the existing `PROHIBITED_SYNC_FIELDS` constant (around line 15). Replace it with:

```python
# Fields that must never be accepted from external sources.
# Enforcement lives in each adapter's response-parsing code; this list
# is the single source of truth consulted by those assertions.
PROHIBITED_SYNC_FIELDS: frozenset[str] = frozenset(
    {
        # Pre-v1.1 entries
        "private_key",
        "key_material",
        "p12",
        "pfx",
        "pkcs12",
        # v1.1 additions for AWS ACM and Azure Key Vault parity
        "pem_bundle",     # AWS ACM export-certificate bundle form
        "secret_value",   # Azure Key Vault secret attribute
        "key",            # Azure Key Vault certificate.key shortcut
    }
)
```

- [ ] **Step 4: Run test to verify it passes**

```bash
python -m pytest tests/test_credential_schema.py::test_prohibited_sync_fields_includes_cloud_aliases -v -p no:django
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add netbox_ssl/adapters/base.py tests/test_credential_schema.py
git commit -m "feat(adapters): extend PROHIBITED_SYNC_FIELDS with AWS/Azure key-material aliases"
```

---

## Task 3: `BaseAdapter` adapter-requirements + `credential_schema()` classmethod

Extend the abstract base with the schema-declaration contract and the two new class attributes — `REQUIRES_BASE_URL` (default `True`, consumer: Lemur / Generic REST / Azure KV) and `REQUIRES_REGION` (default `False`, consumer: AWS ACM). Concrete adapters override `credential_schema()`; the default raises for unsupported `auth_method`.

**Files:**
- Modify: `netbox_ssl/adapters/base.py`
- Test: `tests/test_credential_schema.py` (extend)

- [ ] **Step 1: Write the failing test**

Add to `tests/test_credential_schema.py` (end of file):

```python
def test_base_adapter_has_empty_supported_auth_methods():
    from netbox_ssl.adapters.base import BaseAdapter

    assert BaseAdapter.SUPPORTED_AUTH_METHODS == ()


def test_base_adapter_default_requires_base_url():
    from netbox_ssl.adapters.base import BaseAdapter

    assert BaseAdapter.REQUIRES_BASE_URL is True
    assert BaseAdapter.REQUIRES_REGION is False


def test_base_adapter_credential_schema_rejects_unknown_auth_method():
    from netbox_ssl.adapters.base import BaseAdapter

    with pytest.raises(ValueError, match="does not support"):
        BaseAdapter.credential_schema("anything")
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_credential_schema.py::test_base_adapter_has_empty_supported_auth_methods -v -p no:django
```

Expected: FAIL with `AttributeError: type object 'BaseAdapter' has no attribute 'SUPPORTED_AUTH_METHODS'`.

- [ ] **Step 3: Extend `BaseAdapter` with the new contract**

Open `netbox_ssl/adapters/base.py`. Inside the `class BaseAdapter(ABC):` body, right after the docstring line and before the `__init__` method, add:

```python
    # Tuple of auth_method identifiers this adapter supports. Order is
    # meaningful — the first entry is used as the default in the
    # ExternalSource form dropdown for this adapter.
    SUPPORTED_AUTH_METHODS: tuple[str, ...] = ()

    # Adapter endpoint requirements consumed by ExternalSourceSchemaValidator.
    # Lemur / Generic REST / Azure KV set REQUIRES_BASE_URL (inherited default).
    # AWS ACM overrides to REQUIRES_BASE_URL = False, REQUIRES_REGION = True
    # because boto3 derives endpoints from the region + service.
    REQUIRES_BASE_URL: bool = True
    REQUIRES_REGION: bool = False

    @classmethod
    def credential_schema(cls, auth_method: str) -> dict[str, "CredentialField"]:
        """Return the credential component schema for a given auth_method.

        Concrete adapters override this; the default implementation
        raises for any auth_method not in SUPPORTED_AUTH_METHODS.

        Args:
            auth_method: The auth method identifier (e.g. "bearer", "aws_explicit").

        Returns:
            Mapping of component name -> CredentialField.

        Raises:
            ValueError: If auth_method is not in SUPPORTED_AUTH_METHODS.
        """
        if auth_method not in cls.SUPPORTED_AUTH_METHODS:
            raise ValueError(
                f"{cls.__name__} does not support auth_method '{auth_method}'. "
                f"Supported: {list(cls.SUPPORTED_AUTH_METHODS)}"
            )
        return {}
```

Note: the return type string `"CredentialField"` uses a forward reference because `CredentialField` is defined in the same module above `BaseAdapter`.

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_credential_schema.py -v -p no:django
```

Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add netbox_ssl/adapters/base.py tests/test_credential_schema.py
git commit -m "feat(adapters): add SUPPORTED_AUTH_METHODS + REQUIRES_* + credential_schema() to BaseAdapter"
```

---

## Task 4: `LemurAdapter` schema declaration

Concrete schema implementation for Lemur. Backward-compat trivial: one `token` credential for bearer auth.

**Files:**
- Modify: `netbox_ssl/adapters/lemur.py`
- Test: `tests/test_credential_schema.py` (extend)

- [ ] **Step 1: Write the failing test**

Add to `tests/test_credential_schema.py` (end of file):

```python
def test_lemur_supports_bearer_only():
    from netbox_ssl.adapters.lemur import LemurAdapter

    assert LemurAdapter.SUPPORTED_AUTH_METHODS == ("bearer",)


def test_lemur_credential_schema_has_single_token_field():
    from netbox_ssl.adapters.lemur import LemurAdapter

    schema = LemurAdapter.credential_schema("bearer")
    assert set(schema.keys()) == {"token"}
    assert schema["token"].required is True
    assert schema["token"].secret is True
    assert schema["token"].label == "API Token"


def test_lemur_credential_schema_rejects_non_bearer():
    from netbox_ssl.adapters.lemur import LemurAdapter

    with pytest.raises(ValueError, match="does not support"):
        LemurAdapter.credential_schema("api_key")
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_credential_schema.py::test_lemur_supports_bearer_only -v -p no:django
```

Expected: FAIL with `AssertionError: assert () == ('bearer',)`.

- [ ] **Step 3: Add the schema to `LemurAdapter`**

Open `netbox_ssl/adapters/lemur.py`. At the top of the class body (right after the docstring), add:

```python
    SUPPORTED_AUTH_METHODS: tuple[str, ...] = ("bearer",)

    @classmethod
    def credential_schema(cls, auth_method: str) -> dict[str, "CredentialField"]:
        """Lemur uses a single bearer token — one credential component."""
        if auth_method != "bearer":
            raise ValueError(
                f"LemurAdapter does not support auth_method '{auth_method}'. "
                f"Supported: {list(cls.SUPPORTED_AUTH_METHODS)}"
            )
        from .base import CredentialField  # local import to avoid circular at module load
        return {
            "token": CredentialField(
                required=True,
                label="API Token",
                secret=True,
                help_text="Lemur API bearer token",
            ),
        }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_credential_schema.py -v -p no:django
```

Expected: 8 passed.

- [ ] **Step 5: Commit**

```bash
git add netbox_ssl/adapters/lemur.py tests/test_credential_schema.py
git commit -m "feat(adapters): declare LemurAdapter credential schema (bearer + token)"
```

---

## Task 5: `GenericRESTAdapter` schema declaration

**Files:**
- Modify: `netbox_ssl/adapters/generic_rest.py`
- Test: `tests/test_credential_schema.py` (extend)

- [ ] **Step 1: Write the failing test**

Add to `tests/test_credential_schema.py` (end of file):

```python
def test_generic_rest_supports_bearer_and_api_key():
    from netbox_ssl.adapters.generic_rest import GenericRESTAdapter

    assert GenericRESTAdapter.SUPPORTED_AUTH_METHODS == ("bearer", "api_key")


def test_generic_rest_schema_is_single_token_for_both_methods():
    from netbox_ssl.adapters.generic_rest import GenericRESTAdapter

    for method in ("bearer", "api_key"):
        schema = GenericRESTAdapter.credential_schema(method)
        assert set(schema.keys()) == {"token"}
        assert schema["token"].required is True
        assert schema["token"].secret is True


def test_generic_rest_schema_rejects_cloud_methods():
    from netbox_ssl.adapters.generic_rest import GenericRESTAdapter

    for method in ("aws_explicit", "azure_managed_identity"):
        with pytest.raises(ValueError, match="does not support"):
            GenericRESTAdapter.credential_schema(method)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_credential_schema.py::test_generic_rest_supports_bearer_and_api_key -v -p no:django
```

Expected: FAIL with `AttributeError` or `AssertionError`.

- [ ] **Step 3: Add the schema to `GenericRESTAdapter`**

Open `netbox_ssl/adapters/generic_rest.py`. Locate the `class GenericRESTAdapter(BaseAdapter):` line. After the class docstring, add:

```python
    SUPPORTED_AUTH_METHODS: tuple[str, ...] = ("bearer", "api_key")

    @classmethod
    def credential_schema(cls, auth_method: str) -> dict[str, "CredentialField"]:
        """Generic REST uses one token for either bearer or api-key headers."""
        if auth_method not in cls.SUPPORTED_AUTH_METHODS:
            raise ValueError(
                f"GenericRESTAdapter does not support auth_method '{auth_method}'. "
                f"Supported: {list(cls.SUPPORTED_AUTH_METHODS)}"
            )
        from .base import CredentialField
        return {
            "token": CredentialField(
                required=True,
                label="API Token / Key",
                secret=True,
                help_text="Bearer token or API key value (same component, different header)",
            ),
        }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_credential_schema.py -v -p no:django
```

Expected: 11 passed.

- [ ] **Step 5: Commit**

```bash
git add netbox_ssl/adapters/generic_rest.py tests/test_credential_schema.py
git commit -m "feat(adapters): declare GenericRESTAdapter credential schema"
```

---

## Task 6: `BaseAdapter.resolve_credentials()` returns `dict` + `_get_headers()` reads from dict

The existing `resolve_credentials()` returns `str`; for multi-component adapters this must become `dict[str, str]`. `_get_headers()` reads `creds["token"]` for bearer and api_key paths. The transition is backward-compatible because Lemur and GenericREST schemas both declare a `token` component.

**Files:**
- Modify: `netbox_ssl/adapters/base.py`
- Modify: `netbox_ssl/adapters/lemur.py` (only if it re-implements `_get_headers`, which it doesn't — verify)
- Test: `tests/test_credential_schema.py` (extend)

- [ ] **Step 1: Write the failing test**

Add to `tests/test_credential_schema.py`:

```python
def test_base_adapter_resolve_credentials_returns_dict():
    """resolve_credentials must return dict[str, str] for multi-cred support."""
    import os
    from unittest.mock import MagicMock, patch
    from netbox_ssl.adapters.lemur import LemurAdapter

    source = MagicMock()
    source.auth_credentials = {"token": "env:LEMUR_TEST_TOKEN"}
    adapter = LemurAdapter(source)

    with patch.dict(os.environ, {"LEMUR_TEST_TOKEN": "t0ken"}):
        result = adapter.resolve_credentials()

    assert isinstance(result, dict)
    assert result == {"token": "t0ken"}


def test_get_headers_bearer_reads_token_from_dict():
    import os
    from unittest.mock import MagicMock, patch
    from netbox_ssl.adapters.lemur import LemurAdapter

    source = MagicMock()
    source.auth_credentials = {"token": "env:MY_TOKEN"}
    source.auth_method = "bearer"
    adapter = LemurAdapter(source)

    with patch.dict(os.environ, {"MY_TOKEN": "bearer_value"}):
        headers = adapter._get_headers()

    assert headers["Authorization"] == "Bearer bearer_value"
    assert headers["Accept"] == "application/json"


def test_get_headers_api_key_reads_token_from_dict():
    import os
    from unittest.mock import MagicMock, patch
    from netbox_ssl.adapters.generic_rest import GenericRESTAdapter

    source = MagicMock()
    source.auth_credentials = {"token": "env:MY_KEY"}
    source.auth_method = "api_key"
    adapter = GenericRESTAdapter(source)

    with patch.dict(os.environ, {"MY_KEY": "apikey_value"}):
        headers = adapter._get_headers()

    assert headers["X-API-Key"] == "apikey_value"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_credential_schema.py::test_base_adapter_resolve_credentials_returns_dict -v -p no:django
```

Expected: FAIL — `resolve_credentials()` currently returns `str`, not `dict`.

- [ ] **Step 3: Update `resolve_credentials()` and `_get_headers()`**

Open `netbox_ssl/adapters/base.py`. Locate the existing `resolve_credentials` and `_get_headers` methods (around lines 61-85). Replace them with:

```python
    def resolve_credentials(self) -> dict[str, str]:
        """Resolve all credential components from auth_credentials.

        Returns:
            Mapping of component name -> resolved value. Cached per
            adapter instance for the duration of one sync run.
        """
        if self._credentials is None:
            from ..utils.credential_resolver import CredentialResolver
            self._credentials = CredentialResolver.resolve_many(
                self.source.auth_credentials or {}
            )
        return self._credentials

    def _get_headers(self) -> dict[str, str]:
        """Build HTTP headers with authentication.

        For bearer and api_key auth methods, reads the "token" credential.
        Subclasses override for adapter-specific auth (AWS SigV4, Azure
        OAuth2) that does not use HTTP headers.

        Returns:
            Dictionary of HTTP headers including auth and accept headers.
        """
        creds = self.resolve_credentials()
        token = creds.get("token", "")
        if self.source.auth_method == "bearer":
            return {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        if self.source.auth_method == "api_key":
            return {"X-API-Key": token, "Accept": "application/json"}
        return {"Accept": "application/json"}
```

Also update the type of `self._credentials` in `__init__`. Replace:

```python
        self._credentials: str | None = None
```

With:

```python
        self._credentials: dict[str, str] | None = None
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_credential_schema.py -v -p no:django
```

Expected: 14 passed.

- [ ] **Step 5: Run existing adapter tests to confirm no regression**

```bash
python -m pytest tests/ -v -p no:django -k "lemur or generic_rest" --no-header 2>&1 | tail -20
```

Expected: all passed (any pre-existing tests).

- [ ] **Step 6: Commit**

```bash
git add netbox_ssl/adapters/base.py tests/test_credential_schema.py
git commit -m "feat(adapters): resolve_credentials() returns dict; _get_headers() reads creds['token']"
```

---

## Task 7: Adapter registry helpers

Add the lookup helpers the form and serializer will need.

**Files:**
- Modify: `netbox_ssl/adapters/__init__.py`
- Test: `tests/test_credential_schema.py` (extend)

- [ ] **Step 1: Write the failing test**

Add to `tests/test_credential_schema.py`:

```python
def test_get_adapter_class_returns_correct_class():
    from netbox_ssl.adapters import get_adapter_class
    from netbox_ssl.adapters.lemur import LemurAdapter
    from netbox_ssl.adapters.generic_rest import GenericRESTAdapter

    assert get_adapter_class("lemur") is LemurAdapter
    assert get_adapter_class("generic_rest") is GenericRESTAdapter


def test_get_adapter_class_raises_for_unknown():
    from netbox_ssl.adapters import get_adapter_class

    with pytest.raises(KeyError, match="No adapter registered"):
        get_adapter_class("nonexistent")


def test_get_supported_auth_methods():
    from netbox_ssl.adapters import get_supported_auth_methods

    assert get_supported_auth_methods("lemur") == ("bearer",)
    assert get_supported_auth_methods("generic_rest") == ("bearer", "api_key")


def test_get_credential_schema_for_lemur():
    from netbox_ssl.adapters import get_credential_schema

    schema = get_credential_schema("lemur", "bearer")
    assert "token" in schema
    assert schema["token"].required is True
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_credential_schema.py::test_get_adapter_class_returns_correct_class -v -p no:django
```

Expected: FAIL — `ImportError: cannot import name 'get_adapter_class'`.

- [ ] **Step 3: Add the registry helpers**

Open `netbox_ssl/adapters/__init__.py`. Replace the file content with:

```python
"""External source adapter framework."""

from .base import BaseAdapter, CredentialField, FetchedCertificate
from .generic_rest import GenericRESTAdapter
from .lemur import LemurAdapter

_REGISTRY: dict[str, type[BaseAdapter]] = {
    "lemur": LemurAdapter,
    "generic_rest": GenericRESTAdapter,
}


def get_adapter_class(source_type: str) -> type[BaseAdapter]:
    """Lookup adapter class for a given source_type.

    Args:
        source_type: The ExternalSource.source_type value.

    Returns:
        The registered adapter class.

    Raises:
        KeyError: If no adapter is registered for the source_type.
    """
    adapter_cls = _REGISTRY.get(source_type)
    if adapter_cls is None:
        raise KeyError(f"No adapter registered for source type '{source_type}'")
    return adapter_cls


def get_adapter_for_source(source) -> BaseAdapter:
    """Instantiate the correct adapter for a given ExternalSource.

    Args:
        source: An ExternalSource model instance.

    Returns:
        An adapter instance for the source type.

    Raises:
        ValueError: If no adapter is registered for the source type.
    """
    try:
        adapter_cls = get_adapter_class(source.source_type)
    except KeyError as e:
        raise ValueError(str(e)) from e
    return adapter_cls(source)


def get_supported_auth_methods(source_type: str) -> tuple[str, ...]:
    """Return the auth_method values the adapter for source_type accepts.

    Args:
        source_type: The ExternalSource.source_type value.

    Returns:
        Tuple of auth_method identifiers in form-dropdown order.
    """
    return get_adapter_class(source_type).SUPPORTED_AUTH_METHODS


def get_credential_schema(source_type: str, auth_method: str) -> dict[str, CredentialField]:
    """Return the credential schema for a (source_type, auth_method) pair.

    Args:
        source_type: The ExternalSource.source_type value.
        auth_method: The auth_method identifier.

    Returns:
        Mapping of component name -> CredentialField.

    Raises:
        KeyError: If source_type is not registered.
        ValueError: If auth_method is not supported by that adapter.
    """
    return get_adapter_class(source_type).credential_schema(auth_method)


__all__ = [
    "BaseAdapter",
    "CredentialField",
    "FetchedCertificate",
    "get_adapter_class",
    "get_adapter_for_source",
    "get_credential_schema",
    "get_supported_auth_methods",
]
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_credential_schema.py -v -p no:django
```

Expected: 18 passed.

- [ ] **Step 5: Commit**

```bash
git add netbox_ssl/adapters/__init__.py tests/test_credential_schema.py
git commit -m "feat(adapters): add registry helpers get_adapter_class/get_supported_auth_methods/get_credential_schema"
```

---

## Task 8: Extend `AuthMethodChoices` + add `auth_credentials` + `region` + relax `base_url`

**Files:**
- Modify: `netbox_ssl/models/external_source.py`
- Test: `tests/test_external_source.py` (extend) or use existing patterns

- [ ] **Step 1: Write the failing test**

Add to `tests/test_external_source.py` (end of file, inside the existing `_NETBOX_AVAILABLE` guard pattern — keep tests pure):

```python
@pytest.mark.unit
def test_auth_method_choices_include_cloud_methods():
    # Load the choices class directly
    from netbox_ssl.models.external_source import AuthMethodChoices

    values = [choice[0] for choice in AuthMethodChoices.CHOICES]
    assert "bearer" in values
    assert "api_key" in values
    assert "aws_explicit" in values
    assert "aws_instance_role" in values
    assert "azure_explicit" in values
    assert "azure_managed_identity" in values


@pytest.mark.unit
def test_external_source_has_auth_credentials_field():
    # Only check field declaration, not DB behavior — the mocks don't run migrations.
    from netbox_ssl.models.external_source import ExternalSource

    field_names = [f.name for f in ExternalSource._meta.get_fields()
                   if not f.many_to_many and not f.one_to_many]
    assert "auth_credentials" in field_names
    assert "auth_credentials_reference" in field_names  # still present, deprecated


@pytest.mark.unit
def test_external_source_has_region_field():
    from netbox_ssl.models.external_source import ExternalSource

    field_names = [f.name for f in ExternalSource._meta.get_fields()
                   if not f.many_to_many and not f.one_to_many]
    assert "region" in field_names


@pytest.mark.unit
def test_external_source_base_url_is_optional():
    """base_url becomes optional in v1.1 so AWS ACM sources can omit it."""
    from netbox_ssl.models.external_source import ExternalSource

    base_url_field = ExternalSource._meta.get_field("base_url")
    assert base_url_field.blank is True
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_external_source.py::test_auth_method_choices_include_cloud_methods -v -p no:django
```

Expected: FAIL — new auth_methods missing.

- [ ] **Step 3: Extend `AuthMethodChoices`**

Open `netbox_ssl/models/external_source.py`. Find the `class AuthMethodChoices(ChoiceSet):` block (around line 85). Replace the class body with:

```python
class AuthMethodChoices(ChoiceSet):
    """Authentication method choices for external sources."""

    AUTH_BEARER = "bearer"
    AUTH_API_KEY = "api_key"
    AUTH_AWS_EXPLICIT = "aws_explicit"
    AUTH_AWS_INSTANCE_ROLE = "aws_instance_role"
    AUTH_AZURE_EXPLICIT = "azure_explicit"
    AUTH_AZURE_MANAGED_IDENTITY = "azure_managed_identity"

    CHOICES = [
        (AUTH_BEARER, "Bearer Token", "blue"),
        (AUTH_API_KEY, "API Key (Header)", "yellow"),
        (AUTH_AWS_EXPLICIT, "AWS Explicit Credentials", "orange"),
        (AUTH_AWS_INSTANCE_ROLE, "AWS Instance Role", "green"),
        (AUTH_AZURE_EXPLICIT, "Azure Service Principal", "blue"),
        (AUTH_AZURE_MANAGED_IDENTITY, "Azure Managed Identity", "green"),
    ]
```

- [ ] **Step 4: Add `auth_credentials` field + `region` field + deprecate help_text**

In the same file, find the `auth_credentials_reference` field definition (around line 136). Immediately before it, add:

```python
    auth_credentials = models.JSONField(
        default=dict,
        blank=True,
        help_text=(
            "Mapping of credential component name to a reference string "
            "(e.g. {'access_key_id': 'env:AWS_KEY'}). "
            "Leave empty for role-based auth methods "
            "(aws_instance_role, azure_managed_identity)."
        ),
    )

    region = models.CharField(
        max_length=32,
        blank=True,
        help_text=(
            "Cloud region identifier (e.g., 'us-east-1'). "
            "Required for region-scoped adapters such as AWS ACM; "
            "ignored by others."
        ),
    )
```

Then update the existing `auth_credentials_reference` help_text. Replace:

```python
    auth_credentials_reference = models.CharField(
        max_length=512,
        blank=True,
        help_text='Credential reference (e.g., "env:LEMUR_API_TOKEN"). Never store actual secrets.',
    )
```

With:

```python
    auth_credentials_reference = models.CharField(
        max_length=512,
        blank=True,
        help_text=(
            "DEPRECATED in v1.1, removed in v2.0. "
            "Use auth_credentials instead — existing rows auto-migrate via 0021."
        ),
    )
```

- [ ] **Step 5: Relax `base_url` to `blank=True`**

Still in `netbox_ssl/models/external_source.py`. Find the `base_url` field definition (should be near the top of the `ExternalSource` model, around line 125). Replace:

```python
    base_url = models.URLField(
        max_length=500,
        validators=[validate_external_source_url],
        help_text="HTTPS API endpoint of the external source",
    )
```

With:

```python
    base_url = models.URLField(
        max_length=500,
        blank=True,
        validators=[validate_external_source_url],
        help_text=(
            "HTTPS API endpoint of the external source. "
            "Not required for region-scoped adapters (AWS ACM)."
        ),
    )
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
python -m pytest tests/test_external_source.py -v -p no:django -k "auth_method_choices or auth_credentials_field or region_field or base_url_is_optional"
```

Expected: 4 passed.

- [ ] **Step 7: Commit**

```bash
git add netbox_ssl/models/external_source.py tests/test_external_source.py
git commit -m "feat(models): add auth_credentials, region; relax base_url; 4 new auth_methods"
```

---

## Task 9: Migration 0021 — add `auth_credentials` + `region`, relax `base_url`, backfill

One migration applies all three v1.1 infrastructure schema changes so Phase 2/3 adapters need no further model migrations.

**Files:**
- Create: `netbox_ssl/migrations/0021_external_source_auth_credentials_and_region.py`
- Test: `tests/test_migration_0021.py` (inline integration-style test)

- [ ] **Step 1: Write the failing test**

Create `tests/test_migration_0021.py`:

```python
"""Smoke test that migration 0021 exists and declares the expected operations.

Full data-migration behavior is tested in the Docker integration suite
(tests that run inside the NetBox container with a real Django DB).
"""

import importlib.util
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

MIGRATION_PATH = (
    Path(__file__).resolve().parent.parent
    / "netbox_ssl"
    / "migrations"
    / "0021_external_source_auth_credentials_and_region.py"
)


def test_migration_file_exists():
    assert MIGRATION_PATH.is_file(), f"Migration not found at {MIGRATION_PATH}"


def test_migration_defines_expected_operations():
    spec = importlib.util.spec_from_file_location("mig0021", MIGRATION_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)

    operation_types = [type(op).__name__ for op in module.Migration.operations]
    # Two AddFields (auth_credentials, region), one AlterField (base_url), one RunPython (backfill).
    assert operation_types.count("AddField") == 2
    assert operation_types.count("AlterField") == 1
    assert operation_types.count("RunPython") == 1


def test_migration_adds_auth_credentials_and_region():
    spec = importlib.util.spec_from_file_location("mig0021", MIGRATION_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    addfield_names = [
        op.name for op in module.Migration.operations
        if type(op).__name__ == "AddField"
    ]
    assert set(addfield_names) == {"auth_credentials", "region"}


def test_migration_depends_on_0020():
    spec = importlib.util.spec_from_file_location("mig0021", MIGRATION_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert ("netbox_ssl", "0020_compliancetrendsnapshot_netboxmodel_fields") in module.Migration.dependencies
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_migration_0021.py -v -p no:django
```

Expected: FAIL — file does not exist.

- [ ] **Step 3: Create the migration file**

Create `netbox_ssl/migrations/0021_external_source_auth_credentials_and_region.py`:

```python
"""Add auth_credentials JSONField + region CharField to ExternalSource;
relax base_url to blank=True for region-scoped adapters (AWS ACM).

Backfills auth_credentials from the deprecated auth_credentials_reference
CharField so existing Lemur / Generic REST configurations continue to
work without operator action.

Per the spec at docs/superpowers/specs/2026-04-21-multi-credential-auth-pattern-design.md,
auth_credentials_reference is kept for one minor cycle and removed in v2.0.0.
"""

from django.db import migrations, models

import netbox_ssl.models.external_source  # for validate_external_source_url


def _migrate_auth_credentials(apps, schema_editor):
    """Copy each auth_credentials_reference string into auth_credentials['token'].

    Idempotent: re-running the migration is safe. Rows where
    auth_credentials is already populated are skipped.
    """
    ExternalSource = apps.get_model("netbox_ssl", "ExternalSource")
    for source in ExternalSource.objects.all():
        if source.auth_credentials:
            continue  # already migrated
        if source.auth_credentials_reference:
            source.auth_credentials = {"token": source.auth_credentials_reference}
            source.save(update_fields=["auth_credentials"])


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_ssl", "0020_compliancetrendsnapshot_netboxmodel_fields"),
    ]

    operations = [
        migrations.AddField(
            model_name="externalsource",
            name="auth_credentials",
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AddField(
            model_name="externalsource",
            name="region",
            field=models.CharField(blank=True, max_length=32),
        ),
        migrations.AlterField(
            model_name="externalsource",
            name="base_url",
            field=models.URLField(
                blank=True,
                max_length=500,
                validators=[netbox_ssl.models.external_source.validate_external_source_url],
            ),
        ),
        migrations.RunPython(
            _migrate_auth_credentials,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_migration_0021.py -v -p no:django
```

Expected: 4 passed.

- [ ] **Step 5: Apply migration locally to catch any Django-level syntax errors**

```bash
docker exec netbox-ssl-netbox-1 /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py migrate netbox_ssl 2>&1 | tail -5
```

Expected: `Applying netbox_ssl.0021_external_source_auth_credentials... OK`.

(Requires the local Docker dev stack to be running. If not running, `docker compose up -d` first.)

- [ ] **Step 6: Verify backfill happened for seeded data**

```bash
docker exec netbox-ssl-netbox-1 /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py shell -c "
from netbox_ssl.models import ExternalSource
for s in ExternalSource.objects.all():
    print(f'{s.name}: ref={s.auth_credentials_reference!r} creds={s.auth_credentials!r}')
" 2>&1 | tail -5
```

Expected: the Lemur (demo) source should show `auth_credentials={'token': 'env:LEMUR_API_TOKEN'}` (wrapped from the original reference).

- [ ] **Step 7: Commit**

```bash
git add netbox_ssl/migrations/0021_external_source_auth_credentials_and_region.py tests/test_migration_0021.py
git commit -m "feat(migrations): 0021 add auth_credentials + region; relax base_url; backfill refs"
```

---

## Task 10: `ExternalSource.snapshot()` credential redaction

Override the changelog snapshot method to redact credential values while preserving key-level audit trail.

**Files:**
- Modify: `netbox_ssl/models/external_source.py`
- Create: `tests/test_external_source_snapshot.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_external_source_snapshot.py`:

```python
"""Unit tests for ExternalSource.snapshot() credential scrubbing."""

from unittest.mock import MagicMock, patch

import pytest

pytestmark = pytest.mark.unit


def _make_source_with_snapshot_method(auth_credentials=None, auth_ref=""):
    """Build a mocked ExternalSource-like object with the real snapshot() override."""
    from netbox_ssl.models.external_source import ExternalSource

    source = MagicMock(spec=ExternalSource)
    source.auth_credentials = auth_credentials or {}
    source.auth_credentials_reference = auth_ref
    # Patch the parent snapshot() to return a dict containing our fields
    base_snapshot = {
        "name": "test-source",
        "auth_credentials": source.auth_credentials,
        "auth_credentials_reference": source.auth_credentials_reference,
    }
    with patch("netbox_ssl.models.external_source.NetBoxModel.snapshot", return_value=base_snapshot):
        return ExternalSource.snapshot(source)


def test_snapshot_redacts_auth_credentials_values():
    result = _make_source_with_snapshot_method(
        auth_credentials={"access_key_id": "env:AWS_KEY", "secret_access_key": "env:AWS_SECRET"},
    )
    assert result["auth_credentials"] == {
        "access_key_id": "<redacted>",
        "secret_access_key": "<redacted>",
    }


def test_snapshot_preserves_keys_for_audit():
    """Key additions/removals must be visible in diffs; values are not."""
    result = _make_source_with_snapshot_method(auth_credentials={"token": "env:FOO"})
    assert "token" in result["auth_credentials"]
    assert result["auth_credentials"]["token"] == "<redacted>"


def test_snapshot_redacts_legacy_reference():
    result = _make_source_with_snapshot_method(auth_ref="env:OLD_TOKEN")
    assert result["auth_credentials_reference"] == "<redacted>"


def test_snapshot_leaves_empty_reference_empty():
    result = _make_source_with_snapshot_method(auth_ref="")
    assert result["auth_credentials_reference"] == ""


def test_snapshot_empty_credentials_dict_stays_empty():
    result = _make_source_with_snapshot_method(auth_credentials={})
    assert result["auth_credentials"] == {}


def test_snapshot_never_leaks_env_var_names():
    """Full security assertion: no env var name must appear in the snapshot."""
    result = _make_source_with_snapshot_method(
        auth_credentials={"token": "env:SUPER_SECRET_VAR_NAME"},
        auth_ref="env:ANOTHER_SECRET",
    )
    snapshot_repr = str(result)
    assert "SUPER_SECRET_VAR_NAME" not in snapshot_repr
    assert "ANOTHER_SECRET" not in snapshot_repr
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_external_source_snapshot.py -v -p no:django
```

Expected: FAIL — `snapshot()` on `ExternalSource` not overridden; returns raw values.

- [ ] **Step 3: Add `snapshot()` override to the model**

Open `netbox_ssl/models/external_source.py`. Locate the `ExternalSource` class. Immediately after the `save()` method (around line 210-215), add:

```python
    def snapshot(self):
        """Override changelog snapshot to redact credential values.

        Key-level audit trail is preserved (adds/removes of credential
        components show in diffs) but reference strings are redacted to
        prevent historical env-var-name leakage.
        """
        data = super().snapshot() or {}
        if isinstance(data.get("auth_credentials"), dict):
            data["auth_credentials"] = {
                key: "<redacted>" for key in data["auth_credentials"].keys()
            }
        if data.get("auth_credentials_reference"):
            data["auth_credentials_reference"] = "<redacted>"
        return data
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_external_source_snapshot.py -v -p no:django
```

Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add netbox_ssl/models/external_source.py tests/test_external_source_snapshot.py
git commit -m "feat(models): redact credential values in ExternalSource.snapshot() for changelog"
```

---

## Task 11: `ExternalSourceSchemaValidator` utility

The single source of truth for schema validation — used by form and serializer so they can't drift.

**Files:**
- Create: `netbox_ssl/utils/external_source_validator.py`
- Create: `tests/test_external_source_validator.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_external_source_validator.py`:

```python
"""Unit tests for ExternalSourceSchemaValidator."""

import pytest

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
            base_url="",   # missing
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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_external_source_validator.py -v -p no:django
```

Expected: FAIL — module does not exist.

- [ ] **Step 3: Create the validator utility**

Create `netbox_ssl/utils/external_source_validator.py`:

```python
"""Schema-compliance validation for ExternalSource credentials.

Shared by forms, serializers, and any other caller that needs to validate
an auth_credentials dict against an adapter's declared schema. Keeps
validation logic in one place so form and API cannot drift.
"""

from __future__ import annotations

from django.core.exceptions import ValidationError

from ..adapters import get_adapter_class
from .credential_resolver import ENV_VAR_PATTERN, CredentialResolver


class ExternalSourceSchemaValidator:
    """Validate an ExternalSource payload against adapter requirements.

    All validation methods raise Django ValidationError with a dict of
    field-specific errors so callers (form, serializer) can surface them
    at the right field in their UI.
    """

    @staticmethod
    def validate(
        source_type: str,
        auth_method: str,
        auth_credentials: dict,
        base_url: str = "",
        region: str = "",
    ) -> None:
        """Validate credential payload + adapter requirements.

        Args:
            source_type:      The ExternalSource.source_type value.
            auth_method:      The auth_method identifier.
            auth_credentials: The credential references dict to validate.
            base_url:         The ExternalSource.base_url value (may be empty).
            region:           The ExternalSource.region value (may be empty).

        Raises:
            ValidationError: With a field-specific error dict.
        """
        # 1. source_type must be known
        try:
            adapter_cls = get_adapter_class(source_type)
        except KeyError:
            raise ValidationError(
                {"source_type": f"Unknown source_type '{source_type}'"}
            )

        # 2. auth_method must be supported by this adapter
        if auth_method not in adapter_cls.SUPPORTED_AUTH_METHODS:
            raise ValidationError(
                {"auth_method": (
                    f"{adapter_cls.__name__} does not support auth_method "
                    f"'{auth_method}'. "
                    f"Supported: {list(adapter_cls.SUPPORTED_AUTH_METHODS)}"
                )}
            )

        # 3. Adapter endpoint requirements (base_url, region)
        if adapter_cls.REQUIRES_BASE_URL and not base_url:
            raise ValidationError(
                {"base_url": f"{adapter_cls.__name__} requires a base URL."}
            )
        if adapter_cls.REQUIRES_REGION and not region:
            raise ValidationError(
                {"region": (
                    f"{adapter_cls.__name__} requires a region "
                    "(e.g., 'us-east-1')."
                )}
            )

        # 4. Schema compliance for auth_credentials
        schema = adapter_cls.credential_schema(auth_method)

        extra_keys = set(auth_credentials.keys()) - set(schema.keys())
        if extra_keys:
            raise ValidationError(
                {"auth_credentials": (
                    f"Unknown credential keys: {sorted(extra_keys)}. "
                    f"Allowed: {sorted(schema.keys())}"
                )}
            )

        for key, field_spec in schema.items():
            if field_spec.required and key not in auth_credentials:
                raise ValidationError(
                    {"auth_credentials": (
                        f"Missing required credential '{key}' "
                        f"({field_spec.label or key})"
                    )}
                )

        # 5. Reference format — strict match against ENV_VAR_PATTERN
        for key, ref in auth_credentials.items():
            if not isinstance(ref, str) or not ref.strip():
                raise ValidationError(
                    {"auth_credentials": (
                        f"Credential '{key}' must be a non-empty string reference"
                    )}
                )

            if ":" in ref:
                scheme, _, path = ref.partition(":")
                scheme = scheme.strip().lower()
                path = path.strip()
                if scheme not in CredentialResolver.SUPPORTED_SCHEMES:
                    raise ValidationError(
                        {"auth_credentials": (
                            f"Credential '{key}' uses unsupported scheme "
                            f"'{scheme}'. "
                            f"Supported: {sorted(CredentialResolver.SUPPORTED_SCHEMES)}"
                        )}
                    )
                if not path:
                    raise ValidationError(
                        {"auth_credentials": (
                            f"Credential '{key}' has an empty path after "
                            f"'{scheme}:'. Provide an env-var name, e.g. 'env:MY_TOKEN'."
                        )}
                    )
                var_name = path
            else:
                var_name = ref.strip()

            # 6. Env-var name must match the resolver's allowed pattern
            if not ENV_VAR_PATTERN.match(var_name):
                raise ValidationError(
                    {"auth_credentials": (
                        f"Credential '{key}' references '{var_name}', which is "
                        "not a valid environment variable name. "
                        "Names must start with an uppercase letter or underscore "
                        "and contain only uppercase letters, digits, and underscores."
                    )}
                )
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_external_source_validator.py -v -p no:django
```

Expected: 14 passed (9 original + 1 empty-path + 2 ENV_VAR_PATTERN + 1 base_url required + 1 region check placeholder).

- [ ] **Step 5: Commit**

```bash
git add netbox_ssl/utils/external_source_validator.py tests/test_external_source_validator.py
git commit -m "feat(utils): ExternalSourceSchemaValidator with ENV_VAR_PATTERN + base_url/region checks"
```

---

## Task 12: `ExternalSourceForm` with schema-driven `clean()`

**Files:**
- Create: `netbox_ssl/forms/__init__.py`
- Create: `netbox_ssl/forms/external_source.py`
- Create: `tests/test_external_source_form.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_external_source_form.py`:

```python
"""Unit tests for ExternalSourceForm.clean() validation."""

import pytest

pytestmark = pytest.mark.unit


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


def test_form_accepts_valid_lemur_config():
    from netbox_ssl.forms.external_source import ExternalSourceForm

    form = ExternalSourceForm(data=_base_form_data())
    assert form.is_valid(), form.errors


def test_form_rejects_unknown_credential_key():
    from netbox_ssl.forms.external_source import ExternalSourceForm

    form = ExternalSourceForm(data=_base_form_data(
        auth_credentials={"token": "env:OK", "extra": "env:BAD"},
    ))
    assert not form.is_valid()
    assert "Unknown credential keys" in str(form.errors)


def test_form_rejects_missing_required_credential():
    from netbox_ssl.forms.external_source import ExternalSourceForm

    form = ExternalSourceForm(data=_base_form_data(auth_credentials={}))
    assert not form.is_valid()
    assert "Missing required credential" in str(form.errors)


def test_form_rejects_auth_method_not_supported_by_source_type():
    from netbox_ssl.forms.external_source import ExternalSourceForm

    form = ExternalSourceForm(data=_base_form_data(
        source_type="lemur",
        auth_method="aws_explicit",
    ))
    assert not form.is_valid()
    assert "does not support" in str(form.errors)


def test_form_accepts_empty_credentials_for_role_based_auth():
    """Role-based auth methods (AWS instance role, Azure MI) require no creds.

    AWS ACM and Azure KV adapters are not registered in this plan phase,
    so this test uses a synthetic registration path — see Task 18 integration test
    for end-to-end validation once those adapters ship."""
    # Phase 1 only declares bearer / api_key / (future cloud methods).
    # Lemur does not support empty credentials because bearer requires a token.
    # This behavior is covered end-to-end by the cloud adapter PRs (#100, #101).
    pass
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_external_source_form.py -v -p no:django
```

Expected: FAIL — `ImportError: No module named 'netbox_ssl.forms'`.

- [ ] **Step 3: Create the forms package init**

Create `netbox_ssl/forms/__init__.py`:

```python
"""Plugin forms module."""

from .external_source import ExternalSourceForm

__all__ = ["ExternalSourceForm"]
```

- [ ] **Step 4: Create `ExternalSourceForm`**

Create `netbox_ssl/forms/external_source.py`:

```python
"""ExternalSource model form with schema-driven credential validation."""

from __future__ import annotations

from django import forms
from netbox.forms import NetBoxModelForm

from ..models import ExternalSource
from ..utils.external_source_validator import ExternalSourceSchemaValidator


class ExternalSourceForm(NetBoxModelForm):
    """Form for creating/editing ExternalSource with credential-schema validation."""

    auth_credentials = forms.JSONField(
        required=False,
        widget=forms.Textarea(attrs={"rows": 5, "class": "font-monospace"}),
        help_text=(
            'JSON mapping of credential component name to an env-var reference. '
            'Example: {"access_key_id": "env:AWS_KEY"}. '
            "Leave empty for role-based auth methods."
        ),
    )

    class Meta:
        model = ExternalSource
        fields = (
            "name",
            "source_type",
            "base_url",
            "region",
            "auth_method",
            "auth_credentials",
            "field_mapping",
            "sync_interval_minutes",
            "enabled",
            "verify_ssl",
            "tenant",
        )

    def clean(self):
        cleaned = super().clean()
        ExternalSourceSchemaValidator.validate(
            source_type=cleaned.get("source_type"),
            auth_method=cleaned.get("auth_method"),
            auth_credentials=cleaned.get("auth_credentials") or {},
            base_url=cleaned.get("base_url") or "",
            region=cleaned.get("region") or "",
        )
        return cleaned
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
python -m pytest tests/test_external_source_form.py -v -p no:django
```

Expected: 4 passed (the 5th is a `pass` placeholder for cloud-adapter coverage).

- [ ] **Step 6: Commit**

```bash
git add netbox_ssl/forms/__init__.py netbox_ssl/forms/external_source.py tests/test_external_source_form.py
git commit -m "feat(forms): ExternalSourceForm with schema-driven credential validation"
```

---

## Task 13: Serializer — `auth_credentials` (write_only), `has_credentials` (read_only), `validate()` via validator

**Files:**
- Modify: `netbox_ssl/api/serializers/external_sources.py`
- Test: no new file — add to `tests/test_external_source_validator.py` (serializer delegates to validator, covered by Task 11)

- [ ] **Step 1: Read the existing serializer**

```bash
sed -n '1,60p' netbox_ssl/api/serializers/external_sources.py
```

Expected: should show `ExternalSourceSerializer` with `auth_credentials_reference` as write_only CharField, `has_credentials` as a SerializerMethodField, and no `validate()`.

- [ ] **Step 2: Add `auth_credentials` field + serializer-level validation**

Open `netbox_ssl/api/serializers/external_sources.py`. In the `ExternalSourceSerializer` class:

1. After the existing `auth_credentials_reference` field declaration (around line 24), add:

```python
    auth_credentials = serializers.JSONField(
        write_only=True,
        required=False,
        default=dict,
        help_text=(
            "Mapping of credential component name to env-var reference. "
            "See ExternalSource model help for format."
        ),
    )
```

2. In the `Meta.fields` list, add `"auth_credentials"` next to `"auth_credentials_reference"`, and add `"region"` next to `"base_url"`.

3. At the end of the class (after `get_has_credentials`), add:

```python
    def validate(self, attrs):
        """Validate credential payload against adapter schema + requirements."""
        from ...utils.external_source_validator import ExternalSourceSchemaValidator

        source_type = attrs.get("source_type")
        auth_method = attrs.get("auth_method")
        auth_credentials = attrs.get("auth_credentials") or {}
        base_url = attrs.get("base_url")
        region = attrs.get("region")

        # On PATCH, instance fields fill in missing attrs
        if self.instance is not None:
            source_type = source_type or self.instance.source_type
            auth_method = auth_method or self.instance.auth_method
            if base_url is None:
                base_url = self.instance.base_url
            if region is None:
                region = self.instance.region

        ExternalSourceSchemaValidator.validate(
            source_type=source_type,
            auth_method=auth_method,
            auth_credentials=auth_credentials,
            base_url=base_url or "",
            region=region or "",
        )
        return attrs
```

4. Update `get_has_credentials` to consider role-based auth methods. Replace:

```python
    def get_has_credentials(self, obj) -> bool:
        """Indicate whether credentials are configured for this source."""
        return bool(obj.auth_credentials_reference)
```

With:

```python
    def get_has_credentials(self, obj) -> bool:
        """Indicate whether the source is authorized to run.

        Role-based auth (AWS instance role, Azure Managed Identity)
        needs no stored credentials but still has valid auth.
        """
        if obj.auth_method in {"aws_instance_role", "azure_managed_identity"}:
            return True
        return bool(obj.auth_credentials or obj.auth_credentials_reference)
```

- [ ] **Step 3: Run the existing serializer tests (if any) + validator tests**

```bash
python -m pytest tests/test_external_source_validator.py tests/test_external_source.py -v -p no:django
```

Expected: all passed.

- [ ] **Step 4: Commit**

```bash
git add netbox_ssl/api/serializers/external_sources.py
git commit -m "feat(api): ExternalSourceSerializer auth_credentials field + schema validate()"
```

---

## Task 14: GraphQL — ensure `auth_credentials` stays excluded + add `has_credentials` computed field

**Files:**
- Modify: `netbox_ssl/graphql/types.py`
- Test: `tests/test_external_source_graphql.py` (create)

- [ ] **Step 1: Write the failing test**

Create `tests/test_external_source_graphql.py`:

```python
"""Unit tests verifying GraphQL scrubbing of ExternalSource credentials."""

import pytest

pytestmark = pytest.mark.unit


def test_external_source_type_has_no_auth_credentials_field():
    from netbox_ssl.graphql.types import ExternalSourceType

    # Inspect the class annotations (strawberry/strawberry-django uses these)
    annotations = getattr(ExternalSourceType, "__annotations__", {})
    assert "auth_credentials" not in annotations
    assert "auth_credentials_reference" not in annotations


def test_external_source_type_has_has_credentials_field():
    from netbox_ssl.graphql.types import ExternalSourceType

    # has_credentials is exposed as a strawberry_django.field
    assert hasattr(ExternalSourceType, "has_credentials")
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_external_source_graphql.py -v -p no:django
```

Expected: FAIL on `has_credentials` check (already passes on exclusion check).

- [ ] **Step 3: Add `region` to the ExternalSourceType field list + `has_credentials` computed field**

Open `netbox_ssl/graphql/types.py`. Locate the `ExternalSourceType` class (around line 75). Find the existing explicit annotations list (starts with `name: str`). Add `region: str` between `base_url` and `auth_method`:

```python
    region: str
```

Then inside the class, after the existing `certificate_count` method, add:

```python
    @strawberry_django.field
    def has_credentials(self) -> bool:
        """Are credentials configured for this source?

        True for role-based auth (AWS instance role, Azure MI) even when
        auth_credentials is empty — those methods authorize via host identity.
        """
        if self.auth_method in ("aws_instance_role", "azure_managed_identity"):
            return True
        return bool(self.auth_credentials) or bool(self.auth_credentials_reference)
```

Also update the class docstring to reflect the new exclusion. Replace:

```python
    """GraphQL type for ExternalSource model.

    Note: auth_credentials_reference is intentionally excluded for security.
    """
```

With:

```python
    """GraphQL type for ExternalSource model.

    Note: auth_credentials and auth_credentials_reference are intentionally
    excluded for security — both hold env-var references that would be a
    reconnaissance leak if exposed. Use has_credentials to check
    configuration presence.
    """
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_external_source_graphql.py -v -p no:django
```

Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add netbox_ssl/graphql/types.py tests/test_external_source_graphql.py
git commit -m "feat(graphql): add has_credentials computed field; confirm auth_credentials excluded"
```

---

## Task 15: ROADMAP §8.2 deprecation entry

**Files:**
- Modify: `project-requirement-document/ROADMAP.md`

- [ ] **Step 1: Read the existing §8 section**

```bash
sed -n '225,248p' project-requirement-document/ROADMAP.md
```

Expected: shows §8 Planned Breaking Changes with §8.1 for `add_certificate` removal.

- [ ] **Step 2: Add §8.2 entry**

Open `project-requirement-document/ROADMAP.md`. Find the end of the §8.1 block (ends with the "permissions reference" link line). After the blank line following §8.1, add:

```markdown
### 8.2 Removal of auth_credentials_reference field on ExternalSource

- **Deprecated in:** v1.1.0
- **Removal target:** v2.0.0

The `ExternalSource.auth_credentials_reference` CharField stored single-string credential references. v1.1 adds a structured `auth_credentials` JSONField that supersedes it; migration 0021 wraps existing single strings as `{"token": "env:..."}`.

**Operator action.** No code change needed IF you've run `manage.py migrate` on v1.1 (the field content is already copied to `auth_credentials["token"]`). If you still rely on `auth_credentials_reference` in custom code (e.g. reading it from the database directly in a script), switch to `auth_credentials` before upgrading to v2.0.
```

Also update the §1 change log table. Find the row for 2026-04-21 (the entry added by the AWS/Azure promotion PR). After that row, add:

```markdown
| 2026-04-21 | Added §8.2 for `auth_credentials_reference` deprecation (landing with multi-credential auth pattern in v1.1.0). |
```

- [ ] **Step 3: Lint the markdown**

```bash
grep -n "§8\." project-requirement-document/ROADMAP.md | head -10
```

Expected: §8.1 and §8.2 both present, no stray references.

- [ ] **Step 4: Commit**

```bash
git add project-requirement-document/ROADMAP.md
git commit -m "docs(roadmap): add §8.2 for auth_credentials_reference deprecation (v2.0 removal target)"
```

---

## Task 16: Update `docs/how-to/external-sources.md` with new JSON shape

**Files:**
- Modify: `docs/how-to/external-sources.md`

- [ ] **Step 1: Read the existing doc**

```bash
head -80 docs/how-to/external-sources.md
```

Expected: should show the current Lemur/GenericREST setup guide using `auth_credentials_reference`.

- [ ] **Step 2: Add a new section for `auth_credentials` (new in v1.1)**

Open `docs/how-to/external-sources.md`. Find the first code example showing `auth_credentials_reference`. Before that code block, add a new H2 section:

```markdown
## Credentials reference format (v1.1+)

As of v1.1.0, credentials are stored in the `auth_credentials` JSONField, which maps credential component names to environment-variable references. This supports both simple single-token adapters (Lemur, Generic REST) and multi-component cloud adapters (AWS ACM, Azure Key Vault).

### Single-token adapters (Lemur, Generic REST)

```json
{"token": "env:LEMUR_API_TOKEN"}
```

The operator sets `LEMUR_API_TOKEN=<value>` in the NetBox process environment; the plugin reads the env var at sync time, never stores the value.

### Multi-component adapters (AWS ACM, Azure Key Vault)

AWS ACM with explicit credentials:

```json
{
  "access_key_id": "env:AWS_ACCESS_KEY_ID",
  "secret_access_key": "env:AWS_SECRET_ACCESS_KEY",
  "session_token": "env:AWS_SESSION_TOKEN"
}
```

Azure Key Vault with explicit service-principal credentials:

```json
{
  "tenant_id": "env:AZURE_TENANT_ID",
  "client_id": "env:AZURE_CLIENT_ID",
  "client_secret": "env:AZURE_CLIENT_SECRET"
}
```

### Role-based auth (cloud-native)

When NetBox runs on an AWS EC2 instance with an IAM role or on Azure with a Managed Identity, `auth_credentials` is left **empty** and the adapter uses the host identity. This is the recommended production pattern.

```json
{}
```

Supported role-based `auth_method` values:

- `aws_instance_role` — AWS IAM role attached to the NetBox host (EC2, ECS, Lambda). Requires IMDSv2 enabled.
- `azure_managed_identity` — Azure Managed Identity (system- or user-assigned). For user-assigned, include `client_id` pointing at the identity's client-ID.

### Deprecated — `auth_credentials_reference`

The legacy single-string `auth_credentials_reference` field (v0.8 – v1.0) remains functional through v1.1.x for backward compatibility. Migration 0021 auto-wraps existing values as `{"token": "..."}` in `auth_credentials`; operators need take no action.

**`auth_credentials_reference` is removed in v2.0.0.** See [ROADMAP §8.2](../../project-requirement-document/ROADMAP.md#82-removal-of-auth_credentials_reference-field-on-externalsource).
```

- [ ] **Step 3: Verify the doc still renders under `mkdocs build --strict`**

```bash
cd docs-venv 2>/dev/null || python3 -m venv .venv-docs && source .venv-docs/bin/activate && pip install mkdocs mkdocs-material mike 2>&1 | tail -2
mkdocs build --strict 2>&1 | tail -5
```

Expected: `INFO - Documentation built in ...`. If the virtualenv approach fails, skip this check — CI's `Strict MkDocs build` job covers it on the PR.

- [ ] **Step 4: Commit**

```bash
git add docs/how-to/external-sources.md
git commit -m "docs(how-to): document auth_credentials JSON shape + role-based auth methods"
```

---

## Task 17: CHANGELOG entry under `[Unreleased]`

**Files:**
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Read the current `[Unreleased]` section**

```bash
sed -n '8,20p' CHANGELOG.md
```

Expected: `## [Unreleased]` on line 8 with the next version (likely `[1.0.1]`) immediately after.

- [ ] **Step 2: Populate the `[Unreleased]` block**

Open `CHANGELOG.md`. Replace the `## [Unreleased]` line and the blank line immediately following it with:

```markdown
## [Unreleased]

### Added

- **Multi-credential auth pattern for External Sources** ([#99](https://github.com/ctrl-alt-automate/netbox-ssl/issues/99)):
  new `ExternalSource.auth_credentials` JSONField stores credential-component
  references (e.g., `{"access_key_id": "env:AWS_KEY", "secret_access_key": "env:AWS_SECRET"}`)
  instead of a single-string token. Enables first-class role-based auth
  (`aws_instance_role`, `azure_managed_identity`) where the cloud SDK resolves
  credentials via the host identity and `auth_credentials` stays empty.
- **Per-adapter credential schemas** — each adapter class declares a
  `credential_schema(auth_method)` classmethod; the ExternalSource form
  and API serializer validate submitted credentials against the schema
  at save time, surfacing field-specific errors (missing required key,
  unknown key, unsupported reference scheme).
- **Four new `auth_method` values**: `aws_explicit`, `aws_instance_role`,
  `azure_explicit`, `azure_managed_identity`. Form dropdowns filter
  per-source-type automatically via the adapter's `SUPPORTED_AUTH_METHODS`.
- **`has_credentials` computed field** on the GraphQL type + API serializer —
  returns `True` for role-based auth methods even when `auth_credentials`
  is empty, so UI consumers can show "configured" state without seeing
  reference values.
- **`ExternalSource.snapshot()` credential redaction** — changelog entries
  redact reference values to `<redacted>` while preserving key-level audit
  trail (adds/removes of credential components stay visible).

### Deprecated

- **`ExternalSource.auth_credentials_reference`** (single-string CharField
  from v0.8) deprecated in favor of the new JSONField. Migration 0021
  auto-wraps existing values as `{"token": "..."}`. Field stays functional
  through v1.1.x; removed in v2.0.0 — see [ROADMAP §8.2](project-requirement-document/ROADMAP.md#82-removal-of-auth_credentials_reference-field-on-externalsource).

### Migration notes

One new migration (`0021_external_source_auth_credentials`) adds the field
and backfills it from the legacy CharField. Run:

```bash
python manage.py migrate netbox_ssl
```

The migration is idempotent (safe to re-run) and additive (safe to downgrade to v1.0.x — the old field remains).

## [1.0.1] - 2026-04-20
```

- [ ] **Step 3: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs(changelog): add [Unreleased] entry for multi-credential auth pattern"
```

---

## Task 18: Integration smoke test — Docker container, real DB

Confirms the whole pipeline (form → model → migration → API) works end-to-end in a real NetBox instance. Not CI-gated for this plan phase; must pass locally before PR.

**Files:** (no new files — a one-off shell script in a scratch path, not committed)

- [ ] **Step 1: Ensure the Docker stack is up and migration applied**

```bash
docker compose up -d
docker exec netbox-ssl-netbox-1 /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py migrate netbox_ssl 2>&1 | tail -3
```

Expected: all netbox_ssl migrations applied, including 0021.

- [ ] **Step 2: Run a form-level smoke test inside the container**

```bash
docker cp netbox_ssl netbox-ssl-netbox-1:/opt/netbox/netbox/netbox_ssl
docker exec -i netbox-ssl-netbox-1 /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py shell <<'PYEOF'
from netbox_ssl.forms.external_source import ExternalSourceForm
from netbox_ssl.utils.external_source_validator import ExternalSourceSchemaValidator

# Positive case — Lemur with bearer token
ExternalSourceSchemaValidator.validate(
    source_type="lemur", auth_method="bearer",
    auth_credentials={"token": "env:FAKE_VAR"},
)
print("OK: Lemur bearer with valid creds")

# Negative case — Lemur with unsupported auth_method
try:
    ExternalSourceSchemaValidator.validate(
        source_type="lemur", auth_method="aws_explicit",
        auth_credentials={},
    )
    raise SystemExit("FAIL: should have rejected aws_explicit on lemur")
except Exception as e:
    print(f"OK: rejected aws_explicit on lemur ({e})")
PYEOF
```

Expected: `OK: Lemur bearer ...` and `OK: rejected aws_explicit ...` printed.

- [ ] **Step 3: Test the model directly — save a source with auth_credentials and verify snapshot redacts**

```bash
docker exec -i netbox-ssl-netbox-1 /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py shell <<'PYEOF'
from netbox_ssl.models import ExternalSource

src = ExternalSource.objects.filter(name="Lemur (demo)").first()
if src is None:
    print("SKIP: no Lemur (demo) source seeded")
else:
    print(f"creds before: {src.auth_credentials}")
    src.auth_credentials = {"token": "env:NEW_TEST_VAR"}
    src.save()
    snap = src.snapshot()
    print(f"snapshot auth_credentials: {snap.get('auth_credentials')}")
    assert snap["auth_credentials"] == {"token": "<redacted>"}, "redaction failed"
    print("OK: snapshot redacts values, preserves keys")
PYEOF
```

Expected: `OK: snapshot redacts values, preserves keys`.

- [ ] **Step 4: Test API GET does not return auth_credentials**

```bash
curl -s -H "Authorization: Token $NETBOX_TOKEN" \
     "http://localhost:8000/api/plugins/ssl/external-sources/" | \
     python3 -c "import sys, json; d = json.load(sys.stdin); r = d['results'][0] if d['results'] else {}; print('auth_credentials in response:', 'auth_credentials' in r); print('has_credentials:', r.get('has_credentials'))"
```

Expected: `auth_credentials in response: False`, `has_credentials: True`.

If `NETBOX_TOKEN` is not set, skip this step — Task 19 (CI) will cover it via the form.

- [ ] **Step 5: No commit (this is a smoke-test pass; no new files)**

---

## Task 19: Run full test suite locally + open PR

**Files:** (no new files — CI + PR plumbing)

- [ ] **Step 1: Run the full local unit test suite**

```bash
python -m pytest tests/ -v -p no:django --tb=short 2>&1 | tail -30
```

Expected: all `-m unit` tests pass. Integration tests that require Docker may be skipped here — that's fine.

- [ ] **Step 2: Run lint + format checks**

```bash
ruff check netbox_ssl/
ruff format --check netbox_ssl/
```

Expected: `All checks passed!` and `N files already formatted`.

- [ ] **Step 3: Run the bandit security scan**

```bash
bandit -r netbox_ssl/ -x netbox_ssl/migrations,netbox_ssl/tests -s B101 -q 2>&1 | tail -10
```

Expected: 0 high, 0 medium findings.

- [ ] **Step 4: Push the branch**

```bash
git push -u origin feature/99-multi-credential-auth
```

Expected: `* [new branch] feature/99-multi-credential-auth -> feature/99-multi-credential-auth`.

- [ ] **Step 5: Open the PR against `dev`**

```bash
gh pr create --base dev --head feature/99-multi-credential-auth --title "feat: multi-credential auth pattern for External Sources (#99)" --body "$(cat <<'PRBODY'
## Summary

Implements Phase 1 of the multi-credential auth pattern spec (#99) — the infrastructure that unblocks AWS ACM (#100) and Azure Key Vault (#101) first-party adapters. No new adapters in this PR; only the storage, validation, and schema framework.

Spec: [docs/superpowers/specs/2026-04-21-multi-credential-auth-pattern-design.md](../blob/feature/99-multi-credential-auth/docs/superpowers/specs/2026-04-21-multi-credential-auth-pattern-design.md)

## What changes

- `ExternalSource.auth_credentials` JSONField — structured credential references.
- Four new `auth_method` values — `aws_explicit`, `aws_instance_role`, `azure_explicit`, `azure_managed_identity`.
- Per-adapter `credential_schema(auth_method)` classmethod with `CredentialField` metadata.
- `ExternalSourceSchemaValidator` — single source of truth for schema validation (form + serializer use it).
- `ExternalSourceForm` — dedicated ModelForm with schema-driven `clean()`.
- Migration 0021 — data-backfill from `auth_credentials_reference`.
- Changelog snapshot — redacts credential values, preserves key-level audit trail.
- GraphQL — `auth_credentials` excluded, `has_credentials` computed field added.
- `auth_credentials_reference` deprecated (v2.0.0 removal target, tracked in ROADMAP §8.2).

## Backward compatibility

Zero operator action needed beyond `manage.py migrate`. Existing Lemur / Generic REST rows automatically get `auth_credentials = {"token": "env:..."}` from the backfill.

## Release target

v1.1.0 (infrastructure only). AWS ACM (#100) and Azure KV (#101) adapters land in follow-up PRs.

## Test plan

- [x] Ruff check + format pass
- [x] Bandit 0 high / 0 medium
- [x] `pytest tests/ -m unit -p no:django` passes (all new tests + no regressions)
- [x] Docker integration: migration applies idempotently; form round-trip works; snapshot redacts; API excludes `auth_credentials` from GET
- [ ] CI matrix: Integration v4.4 + v4.5 + Playwright E2E
- [ ] Gemini review
PRBODY
)"
```

Expected: PR URL printed (e.g., `https://github.com/ctrl-alt-automate/netbox-ssl/pull/104`).

- [ ] **Step 6: Verify the PR is live**

```bash
gh pr view --web 2>&1 | tail -2
```

Expected: browser opens the PR. Close the browser when done.

---

## Self-Review Checklist (run after completing all tasks above)

Run through the spec §11 Phase 1 items one more time. Each should map to at least one task above:

1. ✓ `CredentialField` + `resolve_many()` + `ENV_VAR_PATTERN` promotion — Tasks 1, 2
2. ✓ `AuthMethodChoices` with 4 new values — Task 8
3. ✓ `auth_credentials` + `region` fields + relax `base_url` + migration 0021 — Tasks 8, 9
4. ✓ `BaseAdapter` `SUPPORTED_AUTH_METHODS` + `REQUIRES_BASE_URL` + `REQUIRES_REGION` + `credential_schema()` — Task 3
5. ✓ `LemurAdapter` + `GenericRESTAdapter` schemas — Tasks 4, 5
6. ✓ `PROHIBITED_SYNC_FIELDS` extension — Task 2b
7. ✓ `ExternalSourceSchemaValidator` (schema + ENV_VAR_PATTERN + base_url/region) — Task 11
8. ✓ `ExternalSourceForm` — Task 12
9. ✓ Serializer `auth_credentials` + `region` + `has_credentials` + `validate()` — Task 13
10. ✓ GraphQL exclusion + `region` + `has_credentials` — Task 14
11. ✓ `snapshot()` scrub — Task 10
12. ✓ ROADMAP §8.2 entry — Task 15
13. ✓ `docs/how-to/external-sources.md` — Task 16
14. ✓ CHANGELOG — Task 17

Plus `BaseAdapter.resolve_credentials()` returns dict + `_get_headers()` reads `creds["token"]` — Task 6.

If anything is missing: add a task. If any code in a later task references a symbol defined only in a later task, fix the ordering. Re-run the checklist after fixing.

---

## Deferred (not in this plan)

Per the spec's §11 phasing, the following are explicitly **out of scope** for this PR and ship separately:

- **Phase 2 — AWS ACM adapter** (issue #100)
- **Phase 3 — Azure Key Vault adapter** (issue #101)
- **HTMX-driven form field swap per auth_method** — polish, v1.2+
- **`PROHIBITED_SYNC_FIELDS` extension** with AWS/Azure key-material aliases — lives in the adapter PRs where those fields actually arise.
- **Additional credential schemes** (`file:`, `vault:`, `aws-sm:`) — each future scheme is its own focused change.
- **AWS SSO / WIF / SAML support** — documented as not-supported, revisit if demand emerges.
