# AWS ACM Adapter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a read-only AWS Certificate Manager adapter as the first multi-credential downstream consumer of the Phase 1 infrastructure (PR #104), so operators with ACM-managed certs get automatic inventory in NetBox without rekeying.

**Architecture:** New `AwsAcmAdapter` class in `netbox_ssl/adapters/aws_acm.py`. Uses boto3 directly (not `requests`) — bypasses `BaseAdapter._make_request()`. Reuses Phase 1 multi-cred infra: `BaseAdapter.resolve_credentials()` returns `dict[str, str]` which feeds `boto3.client(**kwargs)`. Supports `aws_explicit` (access_key_id + secret_access_key + optional session_token) and `aws_instance_role` (boto3 default credential chain). Single AWS region per ExternalSource. Lazy-registered in adapter registry so plugin still works without `[aws]` extras installed.

**Tech Stack:** Python 3.10+, boto3 1.34+ (sync), botocore 1.34+, moto 5+ (`mock_aws` decorator) for tests, Django 4.2/5.0 (NetBox 4.4+4.5 compat), pytest + unittest.mock, ruff.

**Target branch:** `feature/100-aws-acm-adapter` (already created, parented on `dev` HEAD `196c1b4`, contains spec commit `41e0fd7`).

**Release target:** v1.1.0 (bundled with #101 Azure Key Vault adapter; no interim release).

**Spec reference:** `docs/superpowers/specs/2026-04-22-aws-acm-adapter-design.md` (committed as `41e0fd7` on this branch).

---

## File Structure

Files to **create**:

| Path | Purpose |
|------|---------|
| `netbox_ssl/adapters/aws_acm.py` | `AwsAcmAdapter` class — read-only AWS ACM adapter |
| `tests/test_aws_acm_adapter.py` | Unit tests using `moto.mock_aws` decorator |
| `docs/how-to/aws-acm-sync.md` | Operator guide: IAM policy, env vars, sync usage |

Files to **modify**:

| Path | What changes |
|------|--------------|
| `pyproject.toml` | Add `[project.optional-dependencies] aws = [boto3, botocore]` and `moto[acm]+boto3` to `dev` extras |
| `netbox_ssl/models/external_source.py` | Add `TYPE_AWS_ACM = "aws_acm"` + `(TYPE_AWS_ACM, "AWS Certificate Manager", "orange")` to `ExternalSourceTypeChoices` |
| `netbox_ssl/adapters/__init__.py` | Replace static `_REGISTRY` with `_build_registry()` factory that lazy-imports `AwsAcmAdapter` |
| `tests/test_credential_schema.py` | Append registry-helper tests for `aws_acm` source_type + credential schemas |
| `CHANGELOG.md` | Add AWS ACM adapter entry under existing `[Unreleased]` block |
| `.github/workflows/ci.yml` | Add `boto3 moto` to unit-tests `pip install`; add `boto3 'moto[acm]>=5.0,<6.0'` to integration-tests container install |

---

## Task 0: Branch verification

**Files:** (none — git plumbing)

- [ ] **Step 1: Verify on the correct branch with spec committed**

```bash
git status
git log --oneline -3
```

Expected: on `feature/100-aws-acm-adapter`, working tree clean, top commit is the spec doc (`docs(specs): AWS ACM adapter design (issue #100)`), parent is the `dev` merge commit.

- [ ] **Step 2: Verify the spec is on this branch**

```bash
ls docs/superpowers/specs/2026-04-22-aws-acm-adapter-design.md
```

Expected: file exists.

- [ ] **Step 3: Verify Phase 1 multi-cred infra is in place**

```bash
grep -n "IMPLICIT_AUTH_METHODS" netbox_ssl/adapters/base.py | head -2
grep -n "auth_credentials" netbox_ssl/models/external_source.py | head -3
```

Expected: `IMPLICIT_AUTH_METHODS: tuple[str, ...] = ()` defined in BaseAdapter; `auth_credentials` field present in ExternalSource model.

- [ ] **Step 4: Verify dev shell is loaded with boto3 + moto available**

```bash
python -c "import boto3, moto; print(f'boto3={boto3.__version__} moto={moto.__version__}')"
```

Expected: prints versions. If not, run `direnv allow && eval "$(direnv export bash)"` and retry.

- [ ] **Step 5: Run baseline test suite to confirm clean starting state**

```bash
python -m pytest tests/ -p no:django 2>&1 | tail -3
```

Expected: 910 passed, 142 skipped (or similar — no failures).

---

## Task 1: Add `boto3` + `moto` to `pyproject.toml`

Pure dependency change. No tests required for this change itself, but verify the install works.

**Files:**
- Modify: `pyproject.toml`

- [ ] **Step 1: Add `aws` optional extras and update `dev` extras**

Open `pyproject.toml`. Find the `[project.optional-dependencies]` block (around line 31). Replace:

```toml
[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "pytest-cov>=5.0",
    "ruff>=0.4.0",
    "bandit>=1.7.0",
    "playwright>=1.40",
    "locust>=2.20",
    "pip-audit>=2.7",
]
```

With:

```toml
[project.optional-dependencies]
aws = [
    "boto3>=1.34,<2.0",
    "botocore>=1.34,<2.0",
]
dev = [
    "pytest>=8.0",
    "pytest-cov>=5.0",
    "ruff>=0.4.0",
    "bandit>=1.7.0",
    "playwright>=1.40",
    "locust>=2.20",
    "pip-audit>=2.7",
    "boto3>=1.34,<2.0",
    "moto[acm]>=5.0,<6.0",
]
```

(`docs` extras stay unchanged.)

- [ ] **Step 2: Verify pyproject.toml parses correctly**

```bash
python -c "import tomllib; d = tomllib.load(open('pyproject.toml','rb')); print(sorted(d['project']['optional-dependencies'].keys()))"
```

Expected: `['aws', 'dev', 'docs']`.

- [ ] **Step 3: Confirm boto3 + moto are importable** (already true via flake.nix, but sanity-check)

```bash
python -c "import boto3, moto; from moto import mock_aws; print('imports OK')"
```

Expected: `imports OK`.

- [ ] **Step 4: Commit**

```bash
git add pyproject.toml
git commit -m "build(pyproject): add [aws] extras for boto3; add moto to dev extras"
```

---

## Task 2: Add `TYPE_AWS_ACM` to `ExternalSourceTypeChoices`

Pure model change — extends an enum. No DB migration needed because `source_type` field's `max_length=30` already accommodates `"aws_acm"` (7 chars).

**Files:**
- Modify: `netbox_ssl/models/external_source.py`
- Test: extend `tests/test_external_source.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_external_source.py` (end of file):

```python
@pytest.mark.unit
def test_external_source_type_choices_include_aws_acm():
    from netbox_ssl.models.external_source import ExternalSourceTypeChoices

    values = [choice[0] for choice in ExternalSourceTypeChoices.CHOICES]
    assert "aws_acm" in values
    # Existing types must remain
    assert "lemur" in values
    assert "generic_rest" in values
    # Sanity check: TYPE_AWS_ACM constant exists
    assert ExternalSourceTypeChoices.TYPE_AWS_ACM == "aws_acm"
```

- [ ] **Step 2: Run test to verify it fails**

```bash
python -m pytest tests/test_external_source.py::test_external_source_type_choices_include_aws_acm -v -p no:django
```

Expected: FAIL with `AttributeError: type object 'ExternalSourceTypeChoices' has no attribute 'TYPE_AWS_ACM'` (or `AssertionError` if attribute exists by coincidence).

- [ ] **Step 3: Extend `ExternalSourceTypeChoices`**

Open `netbox_ssl/models/external_source.py`. Find `class ExternalSourceTypeChoices(ChoiceSet):` (around line 73). Replace its body with:

```python
class ExternalSourceTypeChoices(ChoiceSet):
    """Type choices for external sources."""

    TYPE_LEMUR = "lemur"
    TYPE_GENERIC_REST = "generic_rest"
    TYPE_AWS_ACM = "aws_acm"

    CHOICES = [
        (TYPE_LEMUR, "Lemur", "purple"),
        (TYPE_GENERIC_REST, "Generic REST API", "blue"),
        (TYPE_AWS_ACM, "AWS Certificate Manager", "orange"),
    ]
```

- [ ] **Step 4: Run test to verify it passes**

```bash
python -m pytest tests/test_external_source.py::test_external_source_type_choices_include_aws_acm -v -p no:django
```

Expected: 1 passed.

- [ ] **Step 5: Run the rest of `test_external_source.py` to confirm no regression**

```bash
python -m pytest tests/test_external_source.py -v -p no:django 2>&1 | tail -5
```

Expected: all pre-existing tests still pass + the new one (24 passed locally; 3 skipped).

- [ ] **Step 6: ruff checks**

```bash
ruff format --check netbox_ssl/models/external_source.py tests/test_external_source.py
ruff check netbox_ssl/models/external_source.py tests/test_external_source.py
```

Expected: both pass.

- [ ] **Step 7: Commit**

```bash
git add netbox_ssl/models/external_source.py tests/test_external_source.py
git commit -m "feat(models): add TYPE_AWS_ACM to ExternalSourceTypeChoices"
```

---

## Task 3: `aws_acm.py` skeleton — imports, class shell, class attributes

Create the new adapter file with imports (including the boto3 ImportError fail-fast), the class declaration, and only the four class attributes from the spec. All methods will be added in subsequent tasks.

**Files:**
- Create: `netbox_ssl/adapters/aws_acm.py`
- Create: `tests/test_aws_acm_adapter.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_aws_acm_adapter.py`:

```python
"""Unit tests for AwsAcmAdapter."""

import pytest

pytestmark = pytest.mark.unit


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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_aws_acm_adapter.py -v -p no:django
```

Expected: 6 failures with `ModuleNotFoundError: No module named 'netbox_ssl.adapters.aws_acm'`.

- [ ] **Step 3: Create `netbox_ssl/adapters/aws_acm.py`**

```python
"""AWS Certificate Manager (ACM) adapter — read-only ingestion of cert metadata.

Requires the `[aws]` optional extras: `pip install netbox-ssl[aws]`.

Architecturally diverges from Lemur/GenericREST: uses boto3 directly instead of
`requests` via `BaseAdapter._make_request()`. Reuses Phase 1 multi-credential
infrastructure for credential resolution, schema validation, and snapshot
redaction.

Design spec: docs/superpowers/specs/2026-04-22-aws-acm-adapter-design.md
"""

from __future__ import annotations

import logging

try:
    import boto3
    import botocore.exceptions
except ImportError as exc:  # pragma: no cover — covered by lazy registry test
    raise ImportError(
        "AWS ACM adapter requires boto3. "
        "Install with: pip install netbox-ssl[aws]"
    ) from exc

from .base import BaseAdapter, CredentialField, FetchedCertificate

logger = logging.getLogger("netbox_ssl.adapters.aws_acm")


class AwsAcmAdapter(BaseAdapter):
    """Read-only adapter for AWS Certificate Manager.

    Supports two auth methods:
    - aws_explicit:        operator-supplied access_key_id + secret_access_key (+ optional session_token)
    - aws_instance_role:   boto3 default credential chain (EC2 IMDSv2, ECS task role, Lambda exec role)

    One ExternalSource = one AWS region. Multi-region operators create one
    source per region (matches Lemur/GenericREST one-source-per-endpoint).
    """

    SUPPORTED_AUTH_METHODS: tuple[str, ...] = ("aws_explicit", "aws_instance_role")
    IMPLICIT_AUTH_METHODS: tuple[str, ...] = ("aws_instance_role",)
    REQUIRES_BASE_URL: bool = False
    REQUIRES_REGION: bool = True

    def __init__(self, source) -> None:
        super().__init__(source)
        self._client = None  # lazy: built on first use by _get_client()

    def test_connection(self) -> tuple[bool, str]:
        """Test connectivity to the ACM API. Implemented in Task 14."""
        raise NotImplementedError("Implemented in Task 14")

    def fetch_certificates(self) -> list[FetchedCertificate]:
        """Fetch all certificates. Implemented in Task 12."""
        raise NotImplementedError("Implemented in Task 12")

    def get_certificate_detail(self, external_id: str) -> FetchedCertificate | None:
        """Fetch a single certificate by ARN. Implemented in Task 13."""
        raise NotImplementedError("Implemented in Task 13")
```

(The abstract methods get NotImplementedError stubs so the class is instantiable for the class-attribute tests. Each subsequent task replaces one stub with a real implementation.)

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_aws_acm_adapter.py -v -p no:django
```

Expected: 6 passed.

- [ ] **Step 5: ruff checks**

```bash
ruff format --check netbox_ssl/adapters/aws_acm.py tests/test_aws_acm_adapter.py
ruff check netbox_ssl/adapters/aws_acm.py tests/test_aws_acm_adapter.py
```

Expected: both pass.

- [ ] **Step 6: Commit**

```bash
git add netbox_ssl/adapters/aws_acm.py tests/test_aws_acm_adapter.py
git commit -m "feat(adapters): AwsAcmAdapter skeleton — class attrs + boto3 import guard"
```

---

## Task 4: `credential_schema()` classmethod

Implement schema declaration for both supported auth methods.

**Files:**
- Modify: `netbox_ssl/adapters/aws_acm.py`
- Test: extend `tests/test_aws_acm_adapter.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_aws_acm_adapter.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_aws_acm_adapter.py -v -p no:django -k "credential_schema"
```

Expected: 4 failures with `AttributeError: type object 'AwsAcmAdapter' has no attribute 'credential_schema'`.

- [ ] **Step 3: Add `credential_schema()` classmethod**

Open `netbox_ssl/adapters/aws_acm.py`. Inside the `class AwsAcmAdapter(BaseAdapter):` body, after the four class attribute lines and BEFORE the `def __init__(self, source) -> None:` line, insert:

```python
    @classmethod
    def credential_schema(cls, auth_method: str) -> dict[str, CredentialField]:
        """Return the credential component schema for a given auth_method.

        - aws_explicit:      access_key_id + secret_access_key + optional session_token
        - aws_instance_role: empty dict (boto3 default credential chain handles it)
        """
        if auth_method == "aws_explicit":
            return {
                "access_key_id": CredentialField(
                    required=True,
                    label="Access Key ID",
                    secret=True,
                    help_text="AWS access key ID for the IAM user/role",
                ),
                "secret_access_key": CredentialField(
                    required=True,
                    label="Secret Access Key",
                    secret=True,
                    help_text="AWS secret access key (env-var ref recommended)",
                ),
                "session_token": CredentialField(
                    required=False,
                    label="Session Token",
                    secret=True,
                    help_text="Optional STS session token for temporary credentials",
                ),
            }
        if auth_method == "aws_instance_role":
            return {}
        raise ValueError(
            f"AwsAcmAdapter does not support auth_method '{auth_method}'. "
            f"Supported: {list(cls.SUPPORTED_AUTH_METHODS)}"
        )
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_aws_acm_adapter.py -v -p no:django
```

Expected: 10 passed (6 from Task 3 + 4 new).

- [ ] **Step 5: ruff checks**

```bash
ruff format --check netbox_ssl/adapters/aws_acm.py tests/test_aws_acm_adapter.py
ruff check netbox_ssl/adapters/aws_acm.py tests/test_aws_acm_adapter.py
```

Expected: both pass.

- [ ] **Step 6: Commit**

```bash
git add netbox_ssl/adapters/aws_acm.py tests/test_aws_acm_adapter.py
git commit -m "feat(adapters): AwsAcmAdapter credential_schema (aws_explicit + aws_instance_role)"
```

---

## Task 5: `_map_acm_status()` static method

Map ACM `Status` strings to plugin status. Returns `None` for statuses we skip (FAILED, INACTIVE, VALIDATION_TIMED_OUT).

**Files:**
- Modify: `netbox_ssl/adapters/aws_acm.py`
- Test: extend `tests/test_aws_acm_adapter.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_aws_acm_adapter.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_aws_acm_adapter.py -v -p no:django -k "map_acm_status"
```

Expected: 8 failures with `AttributeError: type object 'AwsAcmAdapter' has no attribute '_map_acm_status'`.

- [ ] **Step 3: Add the status map and `_map_acm_status()` method**

Open `netbox_ssl/adapters/aws_acm.py`. After the `credential_schema` classmethod and BEFORE `def __init__`, insert:

```python
    # ACM Status string → plugin Certificate.status value.
    # Statuses NOT in this map are skipped during fetch (returns None).
    # FAILED / INACTIVE / VALIDATION_TIMED_OUT have no useful inventory value
    # (no valid PEM, no usable cert) — skip per spec §4.
    _STATUS_MAP: dict[str, str] = {
        "ISSUED": "active",
        "EXPIRED": "expired",
        "REVOKED": "revoked",
        "PENDING_VALIDATION": "pending",
    }

    @staticmethod
    def _map_acm_status(acm_status: str) -> str | None:
        """Map an ACM Status to a plugin Certificate.status, or None to skip.

        Args:
            acm_status: The Status field from ACM DescribeCertificate response.

        Returns:
            Plugin status string (active/expired/revoked/pending) or None.
        """
        return AwsAcmAdapter._STATUS_MAP.get(acm_status)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_aws_acm_adapter.py -v -p no:django
```

Expected: 18 passed (10 from previous tasks + 8 new).

- [ ] **Step 5: ruff checks**

```bash
ruff format --check netbox_ssl/adapters/aws_acm.py
ruff check netbox_ssl/adapters/aws_acm.py
```

Expected: both pass.

- [ ] **Step 6: Commit**

```bash
git add netbox_ssl/adapters/aws_acm.py tests/test_aws_acm_adapter.py
git commit -m "feat(adapters): AwsAcmAdapter _map_acm_status (ISSUED/EXPIRED/REVOKED/PENDING + skip)"
```

---

## Task 6: `_build_client_kwargs()` method

Bridge from `BaseAdapter.resolve_credentials()` (returns `dict[str, str]`) to boto3 client constructor kwargs.

**Files:**
- Modify: `netbox_ssl/adapters/aws_acm.py`
- Test: extend `tests/test_aws_acm_adapter.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_aws_acm_adapter.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_aws_acm_adapter.py -v -p no:django -k "build_client_kwargs"
```

Expected: 3 failures with `AttributeError: 'AwsAcmAdapter' object has no attribute '_build_client_kwargs'`.

- [ ] **Step 3: Add `_build_client_kwargs()` method**

Open `netbox_ssl/adapters/aws_acm.py`. After `_map_acm_status` and BEFORE `def __init__`... actually `_map_acm_status` is `@staticmethod` and lives near the top of the class. Place `_build_client_kwargs` AFTER `__init__` (it's an instance method). Insert it right after `def __init__(self, source) -> None: ...` block:

```python
    def _build_client_kwargs(self) -> dict[str, str]:
        """Build boto3 client kwargs from source credentials + region.

        For aws_explicit: includes aws_access_key_id, aws_secret_access_key,
        and optionally aws_session_token (resolved via Phase 1 multi-cred
        infrastructure).

        For aws_instance_role: omits all credential kwargs so boto3 falls
        back to its default credential chain (EC2 IMDSv2, ECS task role,
        Lambda execution role).

        Returns:
            Mapping suitable for `boto3.client('acm', **kwargs)`.
        """
        kwargs: dict[str, str] = {"region_name": self.source.region}
        if self.source.auth_method == "aws_explicit":
            creds = self.resolve_credentials()  # dict[str, str]
            kwargs["aws_access_key_id"] = creds["access_key_id"]
            kwargs["aws_secret_access_key"] = creds["secret_access_key"]
            if "session_token" in creds:
                kwargs["aws_session_token"] = creds["session_token"]
        # aws_instance_role: no credential kwargs — boto3 default chain handles it
        return kwargs
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_aws_acm_adapter.py -v -p no:django
```

Expected: 21 passed (18 + 3 new).

- [ ] **Step 5: ruff checks**

```bash
ruff format --check netbox_ssl/adapters/aws_acm.py
ruff check netbox_ssl/adapters/aws_acm.py
```

Expected: both pass.

- [ ] **Step 6: Commit**

```bash
git add netbox_ssl/adapters/aws_acm.py tests/test_aws_acm_adapter.py
git commit -m "feat(adapters): AwsAcmAdapter _build_client_kwargs (bridge to boto3)"
```

---

## Task 7: `_get_client()` lazy boto3 client builder

Build the boto3 client lazily (on first call) and cache it on `self._client`.

**Files:**
- Modify: `netbox_ssl/adapters/aws_acm.py`
- Test: extend `tests/test_aws_acm_adapter.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_aws_acm_adapter.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_aws_acm_adapter.py -v -p no:django -k "get_client"
```

Expected: 2 failures with `AttributeError: 'AwsAcmAdapter' object has no attribute '_get_client'`.

- [ ] **Step 3: Add `_get_client()` method**

Open `netbox_ssl/adapters/aws_acm.py`. After `_build_client_kwargs()`, insert:

```python
    def _get_client(self):
        """Lazily build and cache the boto3 ACM client.

        First call constructs the client using kwargs from
        `_build_client_kwargs()`. Subsequent calls return the cached client.

        Returns:
            A boto3 ACM client instance.
        """
        if self._client is None:
            kwargs = self._build_client_kwargs()
            self._client = boto3.client("acm", **kwargs)
        return self._client
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_aws_acm_adapter.py -v -p no:django
```

Expected: 23 passed (21 + 2 new).

- [ ] **Step 5: ruff checks**

```bash
ruff format --check netbox_ssl/adapters/aws_acm.py
ruff check netbox_ssl/adapters/aws_acm.py
```

Expected: both pass.

- [ ] **Step 6: Commit**

```bash
git add netbox_ssl/adapters/aws_acm.py tests/test_aws_acm_adapter.py
git commit -m "feat(adapters): AwsAcmAdapter _get_client (lazy boto3 client + cache)"
```

---

## Task 8: `_assert_no_prohibited_keys()` defensive safety check

Belt-and-suspenders check: ACM responses should never contain private-key-material keys, but assert it anyway.

**Files:**
- Modify: `netbox_ssl/adapters/aws_acm.py`
- Test: extend `tests/test_aws_acm_adapter.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_aws_acm_adapter.py`:

```python
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

    dirty_response = {"PrivateKey": "..."}  # mixed case
    with pytest.raises(ValueError, match="failed safety check"):
        AwsAcmAdapter._assert_no_prohibited_keys(dirty_response)


def test_assert_no_prohibited_keys_pem_bundle_aws_alias_raises():
    """v1.1 PROHIBITED_SYNC_FIELDS includes pem_bundle (AWS ACM alias)."""
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    dirty_response = {"pem_bundle": "..."}
    with pytest.raises(ValueError, match="failed safety check"):
        AwsAcmAdapter._assert_no_prohibited_keys(dirty_response)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_aws_acm_adapter.py -v -p no:django -k "prohibited"
```

Expected: 4 failures with `AttributeError: type object 'AwsAcmAdapter' has no attribute '_assert_no_prohibited_keys'`.

- [ ] **Step 3: Add the import + method**

Open `netbox_ssl/adapters/aws_acm.py`. Update the import line at the top:

Replace:

```python
from .base import BaseAdapter, CredentialField, FetchedCertificate
```

With:

```python
from .base import PROHIBITED_SYNC_FIELDS, BaseAdapter, CredentialField, FetchedCertificate
```

Then, after `_get_client()`, insert:

```python
    @staticmethod
    def _assert_no_prohibited_keys(response: dict) -> None:
        """Defensive guard — ACM responses must never contain private key material.

        ACM's read-only API (Describe/List/GetCertificate) does not expose
        private keys. This check enforces that invariant: if a hypothetical
        future ACM API change starts returning sensitive fields, the adapter
        fails hard rather than silently leaking them into NetBox.

        Args:
            response: A dict from boto3 (e.g. DescribeCertificate response body).

        Raises:
            ValueError: If any response key matches PROHIBITED_SYNC_FIELDS
                        (case-insensitive comparison).
        """
        keys_lower = {k.lower() for k in response.keys()}
        forbidden = keys_lower & PROHIBITED_SYNC_FIELDS
        if forbidden:
            logger.error("ACM response contained prohibited keys: %s", forbidden)
            raise ValueError("Adapter response failed safety check")
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_aws_acm_adapter.py -v -p no:django
```

Expected: 27 passed (23 + 4 new).

- [ ] **Step 5: ruff checks**

```bash
ruff format --check netbox_ssl/adapters/aws_acm.py
ruff check netbox_ssl/adapters/aws_acm.py
```

Expected: both pass.

- [ ] **Step 6: Commit**

```bash
git add netbox_ssl/adapters/aws_acm.py tests/test_aws_acm_adapter.py
git commit -m "feat(adapters): AwsAcmAdapter _assert_no_prohibited_keys defensive check"
```

---

## Task 9: `_parse_acm_certificate()` static method

Pure function: takes ACM Describe + Get responses, returns `FetchedCertificate` or `None`. Heaviest single method — handles status filter, IMPORTED vs AMAZON_ISSUED differences, KeyAlgorithm parsing, fingerprint computation.

**Files:**
- Modify: `netbox_ssl/adapters/aws_acm.py`
- Test: extend `tests/test_aws_acm_adapter.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_aws_acm_adapter.py`:

```python
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
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter
    from cert_factory import CertFactory

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
    assert len(cert.fingerprint_sha256) == 64  # SHA256 hex


def test_parse_acm_certificate_imported_no_chain():
    """IMPORTED certs may have empty CertificateChain — handle gracefully."""
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter
    from cert_factory import CertFactory

    pem = CertFactory.create(cn="imported.example.com")
    describe = _make_describe_response(Type="IMPORTED")
    get = _make_get_response(pem=pem, chain="")  # no chain

    cert = AwsAcmAdapter._parse_acm_certificate(describe, get)

    assert cert is not None
    assert cert.issuer_chain == ""


def test_parse_acm_certificate_skips_failed_status():
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter
    from cert_factory import CertFactory

    pem = CertFactory.create(cn="failed.example.com")
    describe = _make_describe_response(Status="FAILED")
    get = _make_get_response(pem=pem)

    assert AwsAcmAdapter._parse_acm_certificate(describe, get) is None


def test_parse_acm_certificate_skips_inactive_status():
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter
    from cert_factory import CertFactory

    pem = CertFactory.create(cn="inactive.example.com")
    describe = _make_describe_response(Status="INACTIVE")
    get = _make_get_response(pem=pem)

    assert AwsAcmAdapter._parse_acm_certificate(describe, get) is None


def test_parse_acm_certificate_ecdsa_algorithm():
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter
    from cert_factory import CertFactory

    pem = CertFactory.create(cn="ecdsa.example.com")
    describe = _make_describe_response(KeyAlgorithm="EC_prime256v1")
    get = _make_get_response(pem=pem)

    cert = AwsAcmAdapter._parse_acm_certificate(describe, get)

    assert cert is not None
    assert cert.algorithm == "ecdsa"
    assert cert.key_size is None  # ECDSA doesn't carry a parseable size in KeyAlgorithm


def test_parse_acm_certificate_rsa_4096():
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter
    from cert_factory import CertFactory

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
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter
    from cert_factory import CertFactory

    pem = CertFactory.create(cn="minimal.example.com")
    # describe response with only the essentials
    from datetime import datetime, timezone
    describe = {"Certificate": {
        "CertificateArn": "arn:aws:acm:eu-west-1:000:certificate/min",
        "DomainName": "minimal.example.com",
        "NotBefore": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "NotAfter": datetime(2027, 1, 1, tzinfo=timezone.utc),
        "Status": "ISSUED",
        "KeyAlgorithm": "RSA_2048",
        # No SANs, no Issuer, no Serial
    }}
    get = _make_get_response(pem=pem)

    cert = AwsAcmAdapter._parse_acm_certificate(describe, get)

    assert cert is not None
    assert cert.sans == ()
    assert cert.issuer == ""
    assert cert.serial_number == ""
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_aws_acm_adapter.py -v -p no:django -k "parse_acm_certificate"
```

Expected: 8 failures with `AttributeError: type object 'AwsAcmAdapter' has no attribute '_parse_acm_certificate'`.

- [ ] **Step 3: Add `_parse_acm_certificate()` method**

Open `netbox_ssl/adapters/aws_acm.py`. After `_assert_no_prohibited_keys()`, insert:

```python
    @staticmethod
    def _parse_acm_certificate(describe_response: dict, get_response: dict) -> FetchedCertificate | None:
        """Parse paired DescribeCertificate + GetCertificate responses into FetchedCertificate.

        Returns None if:
        - The cert's Status maps to None (skip — FAILED/INACTIVE/VALIDATION_TIMED_OUT)
        - The PEM in get_response is unparseable
        - Required fields are missing/invalid

        Args:
            describe_response: Body of boto3 ACM describe_certificate() call.
                               Has shape {"Certificate": {...}}.
            get_response:      Body of boto3 ACM get_certificate() call.
                               Has shape {"Certificate": "<PEM>", "CertificateChain": "<PEM>"}.

        Returns:
            FetchedCertificate or None to skip.
        """
        try:
            cert_meta = describe_response["Certificate"]

            # Status filter — skip non-mappable statuses
            status = cert_meta.get("Status", "")
            if AwsAcmAdapter._map_acm_status(status) is None:
                return None

            # KeyAlgorithm parsing: "RSA_2048" → ("rsa", 2048); "EC_prime256v1" → ("ecdsa", None)
            key_alg_raw = cert_meta.get("KeyAlgorithm", "").upper()
            algorithm = "unknown"
            key_size: int | None = None
            if key_alg_raw.startswith("RSA"):
                algorithm = "rsa"
                # "RSA_2048" → 2048
                _, _, size_str = key_alg_raw.partition("_")
                if size_str.isdigit():
                    key_size = int(size_str)
            elif key_alg_raw.startswith("EC"):
                algorithm = "ecdsa"

            # PEM + fingerprint
            pem = get_response.get("Certificate", "")
            if not pem:
                logger.warning("ACM cert %s has no PEM in GetCertificate response — skipping",
                               cert_meta.get("CertificateArn", "<unknown>"))
                return None

            from cryptography import x509
            from cryptography.hazmat.primitives import hashes
            try:
                x509_cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))
                fingerprint = x509_cert.fingerprint(hashes.SHA256()).hex()
            except (ValueError, TypeError) as e:
                logger.warning("ACM cert %s has invalid PEM: %s — skipping",
                               cert_meta.get("CertificateArn", "<unknown>"), e)
                return None

            sans_raw = cert_meta.get("SubjectAlternativeNames", [])
            sans = tuple(str(s) for s in sans_raw if s)

            return FetchedCertificate(
                external_id=str(cert_meta["CertificateArn"]),
                common_name=str(cert_meta.get("DomainName", "")),
                serial_number=str(cert_meta.get("Serial", "")),
                fingerprint_sha256=fingerprint,
                issuer=str(cert_meta.get("Issuer", "")),
                valid_from=cert_meta["NotBefore"],
                valid_to=cert_meta["NotAfter"],
                sans=sans,
                key_size=key_size,
                algorithm=algorithm,
                pem_content=pem,
                issuer_chain=str(get_response.get("CertificateChain", "")),
            )
        except (KeyError, TypeError) as e:
            logger.warning("Failed to parse ACM certificate: %s", e)
            return None
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_aws_acm_adapter.py -v -p no:django
```

Expected: 35 passed (27 + 8 new).

- [ ] **Step 5: ruff checks**

```bash
ruff format --check netbox_ssl/adapters/aws_acm.py
ruff check netbox_ssl/adapters/aws_acm.py
```

Expected: both pass.

- [ ] **Step 6: Commit**

```bash
git add netbox_ssl/adapters/aws_acm.py tests/test_aws_acm_adapter.py
git commit -m "feat(adapters): AwsAcmAdapter _parse_acm_certificate (mapping + filter + fingerprint)"
```

---

## Task 10: `_list_certificate_arns()` paginator wrapper

Iterate over all certificate ARNs in the source's region using boto3's built-in paginator.

**Files:**
- Modify: `netbox_ssl/adapters/aws_acm.py`
- Test: extend `tests/test_aws_acm_adapter.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_aws_acm_adapter.py`:

```python
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
    import boto3
    from unittest.mock import MagicMock
    from moto import mock_aws
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter
    from cert_factory import CertFactory

    @mock_aws
    def run():
        client = boto3.client("acm", region_name="eu-west-1")
        pem = CertFactory.create(cn="single.example.com")
        # Use any non-empty private key — moto only validates basic shape
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        key_pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_aws_acm_adapter.py -v -p no:django -k "list_certificate_arns"
```

Expected: 2 failures with `AttributeError: 'AwsAcmAdapter' object has no attribute '_list_certificate_arns'`.

- [ ] **Step 3: Add the import + method**

Open `netbox_ssl/adapters/aws_acm.py`. Add at the top of the file (after existing imports):

```python
from collections.abc import Iterator
```

Then, after `_parse_acm_certificate()`, insert:

```python
    def _list_certificate_arns(self) -> Iterator[str]:
        """Yield every certificate ARN in the source's region via boto3 paginator.

        boto3 handles NextToken automatically. Returns an empty iterator
        for accounts with no certs in this region.

        Yields:
            Certificate ARN strings.
        """
        paginator = self._get_client().get_paginator("list_certificates")
        for page in paginator.paginate(PaginationConfig={"PageSize": 1000}):
            for summary in page.get("CertificateSummaryList", []):
                arn = summary.get("CertificateArn")
                if arn:
                    yield arn
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_aws_acm_adapter.py -v -p no:django
```

Expected: 37 passed (35 + 2 new).

- [ ] **Step 5: ruff checks**

```bash
ruff format --check netbox_ssl/adapters/aws_acm.py
ruff check netbox_ssl/adapters/aws_acm.py
```

Expected: both pass.

- [ ] **Step 6: Commit**

```bash
git add netbox_ssl/adapters/aws_acm.py tests/test_aws_acm_adapter.py
git commit -m "feat(adapters): AwsAcmAdapter _list_certificate_arns (paginator wrapper)"
```

---

## Task 11: `_describe_and_get()` per-cert helper

Combines DescribeCertificate + GetCertificate calls for a single ARN, runs the safety check, and parses the result. Returns `None` on per-cert failure (caller skips).

**Files:**
- Modify: `netbox_ssl/adapters/aws_acm.py`
- Test: extend `tests/test_aws_acm_adapter.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_aws_acm_adapter.py`:

```python
def test_describe_and_get_happy_path():
    import boto3
    from unittest.mock import MagicMock
    from moto import mock_aws
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter
    from cert_factory import CertFactory
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    @mock_aws
    def run():
        client = boto3.client("acm", region_name="eu-west-1")
        pem = CertFactory.create(cn="happy.example.com")
        key_pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        arn = client.import_certificate(
            Certificate=pem.encode(), PrivateKey=key_pem.encode()
        )["CertificateArn"]

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
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter
    from botocore.exceptions import ClientError

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
    from unittest.mock import MagicMock, patch
    from datetime import datetime, timezone
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter
    from botocore.exceptions import ClientError

    source = MagicMock()
    source.region = "eu-west-1"
    source.auth_method = "aws_instance_role"
    source.auth_credentials = {}
    adapter = AwsAcmAdapter(source)

    mock_client = MagicMock()
    mock_client.describe_certificate.return_value = {"Certificate": {
        "CertificateArn": "arn:test", "DomainName": "x.example.com", "Status": "ISSUED",
        "NotBefore": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "NotAfter": datetime(2027, 1, 1, tzinfo=timezone.utc),
        "KeyAlgorithm": "RSA_2048",
    }}
    mock_client.get_certificate.side_effect = ClientError(
        error_response={"Error": {"Code": "AccessDeniedException", "Message": "no perm"}},
        operation_name="GetCertificate",
    )
    with patch.object(adapter, "_get_client", return_value=mock_client):
        result = adapter._describe_and_get("arn:test")

    assert result is None


def test_describe_and_get_returns_none_for_filtered_status():
    """Status FAILED → describe still called, but parser returns None."""
    from unittest.mock import MagicMock, patch
    from datetime import datetime, timezone
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    source = MagicMock()
    source.region = "eu-west-1"
    source.auth_method = "aws_instance_role"
    source.auth_credentials = {}
    adapter = AwsAcmAdapter(source)

    mock_client = MagicMock()
    mock_client.describe_certificate.return_value = {"Certificate": {
        "CertificateArn": "arn:failed", "DomainName": "f.example.com", "Status": "FAILED",
        "NotBefore": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "NotAfter": datetime(2027, 1, 1, tzinfo=timezone.utc),
        "KeyAlgorithm": "RSA_2048",
    }}
    # get_certificate should NOT be called since status filter trips first
    with patch.object(adapter, "_get_client", return_value=mock_client):
        result = adapter._describe_and_get("arn:failed")

    assert result is None
    mock_client.get_certificate.assert_not_called()
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_aws_acm_adapter.py -v -p no:django -k "describe_and_get"
```

Expected: 4 failures with `AttributeError: 'AwsAcmAdapter' object has no attribute '_describe_and_get'`.

- [ ] **Step 3: Add `_describe_and_get()` method**

Open `netbox_ssl/adapters/aws_acm.py`. After `_list_certificate_arns()`, insert:

```python
    def _describe_and_get(self, arn: str) -> FetchedCertificate | None:
        """Fetch metadata + PEM for one cert ARN, parse, and return.

        Performs early status-filter optimization: if DescribeCertificate's
        Status maps to None (skip), GetCertificate is NOT called — saves an
        API round-trip per filtered cert.

        Args:
            arn: The certificate ARN.

        Returns:
            FetchedCertificate, or None if:
            - DescribeCertificate or GetCertificate raises ClientError
            - Status maps to skip
            - Parser returns None
        """
        client = self._get_client()
        try:
            describe = client.describe_certificate(CertificateArn=arn)
        except botocore.exceptions.ClientError as e:
            logger.warning("DescribeCertificate failed for %s: %s — skipping", arn, e)
            return None

        # Early status filter — skip GetCertificate for non-mappable statuses
        cert_meta = describe.get("Certificate", {})
        status = cert_meta.get("Status", "")
        if self._map_acm_status(status) is None:
            return None

        try:
            get = client.get_certificate(CertificateArn=arn)
        except botocore.exceptions.ClientError as e:
            logger.warning("GetCertificate failed for %s: %s — skipping", arn, e)
            return None

        try:
            self._assert_no_prohibited_keys(describe)
            self._assert_no_prohibited_keys(get)
        except ValueError as e:
            logger.error("Safety check failed for %s: %s — skipping", arn, e)
            return None

        return self._parse_acm_certificate(describe, get)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_aws_acm_adapter.py -v -p no:django
```

Expected: 41 passed (37 + 4 new).

- [ ] **Step 5: ruff checks**

```bash
ruff format --check netbox_ssl/adapters/aws_acm.py
ruff check netbox_ssl/adapters/aws_acm.py
```

Expected: both pass.

- [ ] **Step 6: Commit**

```bash
git add netbox_ssl/adapters/aws_acm.py tests/test_aws_acm_adapter.py
git commit -m "feat(adapters): AwsAcmAdapter _describe_and_get (per-cert fetch + parse + safety)"
```

---

## Task 12: `fetch_certificates()` orchestration

Public method that the sync engine calls. Iterates all ARNs, calls `_describe_and_get()`, filters Nones, returns the list.

**Files:**
- Modify: `netbox_ssl/adapters/aws_acm.py`
- Test: extend `tests/test_aws_acm_adapter.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_aws_acm_adapter.py`:

```python
def _import_test_cert(client, cn: str) -> str:
    """Helper: import a test cert into mocked ACM, return ARN."""
    from cert_factory import CertFactory
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    pem = CertFactory.create(cn=cn)
    key_pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return client.import_certificate(
        Certificate=pem.encode(), PrivateKey=key_pem.encode()
    )["CertificateArn"]


def test_fetch_certificates_empty_account_returns_empty_list():
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
        return adapter.fetch_certificates()

    assert run() == []


def test_fetch_certificates_returns_imported_certs():
    import boto3
    from unittest.mock import MagicMock
    from moto import mock_aws
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    @mock_aws
    def run():
        client = boto3.client("acm", region_name="eu-west-1")
        _import_test_cert(client, "first.example.com")
        _import_test_cert(client, "second.example.com")

        source = MagicMock()
        source.region = "eu-west-1"
        source.auth_method = "aws_instance_role"
        source.auth_credentials = {}
        adapter = AwsAcmAdapter(source)
        return adapter.fetch_certificates()

    certs = run()
    cns = sorted(c.common_name for c in certs)
    assert cns == ["first.example.com", "second.example.com"]


def test_fetch_certificates_isolated_per_region():
    """ExternalSource configured for eu-west-1 only sees eu-west-1 certs."""
    import boto3
    from unittest.mock import MagicMock
    from moto import mock_aws
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    @mock_aws
    def run():
        eu_client = boto3.client("acm", region_name="eu-west-1")
        us_client = boto3.client("acm", region_name="us-east-1")
        _import_test_cert(eu_client, "europe.example.com")
        _import_test_cert(us_client, "america.example.com")

        source = MagicMock()
        source.region = "eu-west-1"
        source.auth_method = "aws_instance_role"
        source.auth_credentials = {}
        adapter = AwsAcmAdapter(source)
        return adapter.fetch_certificates()

    certs = run()
    cns = [c.common_name for c in certs]
    assert cns == ["europe.example.com"]


def test_fetch_certificates_skips_failed_per_cert_errors():
    """If one cert raises during fetch, others still succeed."""
    import boto3
    from unittest.mock import MagicMock, patch
    from moto import mock_aws
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter
    from botocore.exceptions import ClientError

    @mock_aws
    def run():
        client = boto3.client("acm", region_name="eu-west-1")
        good_arn = _import_test_cert(client, "good.example.com")
        bad_arn = _import_test_cert(client, "bad.example.com")

        source = MagicMock()
        source.region = "eu-west-1"
        source.auth_method = "aws_instance_role"
        source.auth_credentials = {}
        adapter = AwsAcmAdapter(source)

        # Wrap _describe_and_get to fail for one specific ARN
        original = adapter._describe_and_get
        def wrapped(arn):
            if arn == bad_arn:
                raise ClientError(
                    error_response={"Error": {"Code": "InternalServerError", "Message": "boom"}},
                    operation_name="DescribeCertificate",
                )
            return original(arn)

        with patch.object(adapter, "_describe_and_get", side_effect=wrapped):
            return adapter.fetch_certificates()

    certs = run()
    # Good cert returned; bad cert silently skipped (not raised through fetch)
    cns = [c.common_name for c in certs]
    assert cns == ["good.example.com"]
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_aws_acm_adapter.py -v -p no:django -k "fetch_certificates"
```

Expected: 4 failures with `NotImplementedError: Implemented in Task 12`.

- [ ] **Step 3: Replace the `fetch_certificates()` stub with the real implementation**

Open `netbox_ssl/adapters/aws_acm.py`. Find:

```python
    def fetch_certificates(self) -> list[FetchedCertificate]:
        """Fetch all certificates. Implemented in Task 12."""
        raise NotImplementedError("Implemented in Task 12")
```

Replace with:

```python
    def fetch_certificates(self) -> list[FetchedCertificate]:
        """Fetch all certificates from the configured ACM region.

        Iterates ARNs via ListCertificates paginator, then calls
        DescribeCertificate + GetCertificate for each. Skips certs that:
        - Have a non-mappable status (FAILED/INACTIVE/VALIDATION_TIMED_OUT)
        - Fail per-cert API calls (logged, not raised)
        - Have unparseable PEM

        Returns:
            List of FetchedCertificate. Empty list on connection failure.
        """
        certificates: list[FetchedCertificate] = []
        skipped = 0
        try:
            arns = list(self._list_certificate_arns())
        except botocore.exceptions.ClientError as e:
            logger.error("ListCertificates failed for source '%s': %s", self.source.name, e)
            return []
        except botocore.exceptions.NoCredentialsError as e:
            logger.error("No AWS credentials available for source '%s': %s", self.source.name, e)
            return []
        except botocore.exceptions.EndpointConnectionError as e:
            logger.error("Cannot reach ACM in region '%s' for source '%s': %s",
                         self.source.region, self.source.name, e)
            return []

        for arn in arns:
            try:
                cert = self._describe_and_get(arn)
            except botocore.exceptions.ClientError as e:
                logger.warning("Per-cert error for %s: %s — skipping", arn, e)
                skipped += 1
                continue
            if cert is None:
                skipped += 1
                continue
            certificates.append(cert)

        logger.info("ACM source '%s' (region=%s): fetched %d, skipped %d",
                    self.source.name, self.source.region, len(certificates), skipped)
        return certificates
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_aws_acm_adapter.py -v -p no:django
```

Expected: 45 passed (41 + 4 new).

- [ ] **Step 5: ruff checks**

```bash
ruff format --check netbox_ssl/adapters/aws_acm.py
ruff check netbox_ssl/adapters/aws_acm.py
```

Expected: both pass.

- [ ] **Step 6: Commit**

```bash
git add netbox_ssl/adapters/aws_acm.py tests/test_aws_acm_adapter.py
git commit -m "feat(adapters): AwsAcmAdapter fetch_certificates (orchestrate + skip-on-error)"
```

---

## Task 13: `get_certificate_detail()` single-cert lookup

For on-demand refresh of a single cert by ARN.

**Files:**
- Modify: `netbox_ssl/adapters/aws_acm.py`
- Test: extend `tests/test_aws_acm_adapter.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_aws_acm_adapter.py`:

```python
def test_get_certificate_detail_found():
    import boto3
    from unittest.mock import MagicMock
    from moto import mock_aws
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    @mock_aws
    def run():
        client = boto3.client("acm", region_name="eu-west-1")
        arn = _import_test_cert(client, "lookup.example.com")

        source = MagicMock()
        source.region = "eu-west-1"
        source.auth_method = "aws_instance_role"
        source.auth_credentials = {}
        adapter = AwsAcmAdapter(source)
        return adapter.get_certificate_detail(arn)

    cert = run()
    assert cert is not None
    assert cert.common_name == "lookup.example.com"


def test_get_certificate_detail_not_found_returns_none():
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
        return adapter.get_certificate_detail(
            "arn:aws:acm:eu-west-1:000000000000:certificate/00000000-0000-0000-0000-000000000000"
        )

    assert run() is None
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_aws_acm_adapter.py -v -p no:django -k "get_certificate_detail"
```

Expected: 2 failures with `NotImplementedError: Implemented in Task 13`.

- [ ] **Step 3: Replace the `get_certificate_detail()` stub**

Open `netbox_ssl/adapters/aws_acm.py`. Find:

```python
    def get_certificate_detail(self, external_id: str) -> FetchedCertificate | None:
        """Fetch a single certificate by ARN. Implemented in Task 13."""
        raise NotImplementedError("Implemented in Task 13")
```

Replace with:

```python
    def get_certificate_detail(self, external_id: str) -> FetchedCertificate | None:
        """Fetch a single certificate by its ARN.

        Used for on-demand refresh of a known cert (e.g., admin clicks
        "Refresh from source" in the UI).

        Args:
            external_id: The certificate ARN.

        Returns:
            FetchedCertificate, or None if not found / inaccessible.
        """
        return self._describe_and_get(external_id)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_aws_acm_adapter.py -v -p no:django
```

Expected: 47 passed (45 + 2 new).

- [ ] **Step 5: ruff checks**

```bash
ruff format --check netbox_ssl/adapters/aws_acm.py
ruff check netbox_ssl/adapters/aws_acm.py
```

Expected: both pass.

- [ ] **Step 6: Commit**

```bash
git add netbox_ssl/adapters/aws_acm.py tests/test_aws_acm_adapter.py
git commit -m "feat(adapters): AwsAcmAdapter get_certificate_detail (single-cert lookup)"
```

---

## Task 14: `test_connection()` with error mapping

Performs a cheap permissions-check call (`ListCertificates(MaxItems=1)`) and translates AWS exceptions into user-friendly messages without leaking credentials.

**Files:**
- Modify: `netbox_ssl/adapters/aws_acm.py`
- Test: extend `tests/test_aws_acm_adapter.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_aws_acm_adapter.py`:

```python
def test_test_connection_success_with_empty_account():
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
        return adapter.test_connection()

    success, message = run()
    assert success is True
    assert "successful" in message.lower()


def test_test_connection_returns_generic_message_on_access_denied():
    """AccessDenied → False with generic message; full error logged internally."""
    from unittest.mock import MagicMock, patch
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter
    from botocore.exceptions import ClientError

    source = MagicMock()
    source.region = "eu-west-1"
    source.auth_method = "aws_instance_role"
    source.auth_credentials = {}
    adapter = AwsAcmAdapter(source)

    mock_client = MagicMock()
    mock_client.list_certificates.side_effect = ClientError(
        error_response={"Error": {"Code": "AccessDeniedException", "Message": "no perm"}},
        operation_name="ListCertificates",
    )
    with patch.object(adapter, "_get_client", return_value=mock_client):
        success, message = adapter.test_connection()

    assert success is False
    assert "Insufficient permissions" in message
    # Generic — never echoes raw AWS message
    assert "no perm" not in message


def test_test_connection_returns_generic_message_on_invalid_credentials():
    from unittest.mock import MagicMock, patch
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter
    from botocore.exceptions import ClientError

    source = MagicMock()
    source.region = "eu-west-1"
    source.auth_method = "aws_explicit"
    source.auth_credentials = {"access_key_id": "env:X", "secret_access_key": "env:Y"}
    adapter = AwsAcmAdapter(source)

    mock_client = MagicMock()
    mock_client.list_certificates.side_effect = ClientError(
        error_response={"Error": {"Code": "InvalidClientTokenId", "Message": "bad key"}},
        operation_name="ListCertificates",
    )
    with patch.object(adapter, "_get_client", return_value=mock_client):
        success, message = adapter.test_connection()

    assert success is False
    assert "AWS authentication failed" in message


def test_test_connection_no_credentials_error():
    from unittest.mock import MagicMock, patch
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter
    from botocore.exceptions import NoCredentialsError

    source = MagicMock()
    source.region = "eu-west-1"
    source.auth_method = "aws_instance_role"
    source.auth_credentials = {}
    adapter = AwsAcmAdapter(source)

    with patch.object(adapter, "_get_client", side_effect=NoCredentialsError):
        success, message = adapter.test_connection()

    assert success is False
    assert "No AWS credentials" in message


def test_test_connection_endpoint_connection_error():
    from unittest.mock import MagicMock, patch
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter
    from botocore.exceptions import EndpointConnectionError

    source = MagicMock()
    source.region = "fake-region-99"
    source.auth_method = "aws_instance_role"
    source.auth_credentials = {}
    adapter = AwsAcmAdapter(source)

    with patch.object(adapter, "_get_client", side_effect=EndpointConnectionError(endpoint_url="https://acm.fake-region-99.amazonaws.com")):
        success, message = adapter.test_connection()

    assert success is False
    assert "Cannot reach ACM" in message
    assert "fake-region-99" in message
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_aws_acm_adapter.py -v -p no:django -k "test_connection"
```

Expected: 5 failures with `NotImplementedError: Implemented in Task 14`.

- [ ] **Step 3: Replace the `test_connection()` stub**

Open `netbox_ssl/adapters/aws_acm.py`. Find:

```python
    def test_connection(self) -> tuple[bool, str]:
        """Test connectivity to the ACM API. Implemented in Task 14."""
        raise NotImplementedError("Implemented in Task 14")
```

Replace with:

```python
    def test_connection(self) -> tuple[bool, str]:
        """Test connectivity + permissions by calling ListCertificates(MaxItems=1).

        Returns generic user-facing messages; full AWS error details are
        logged internally (never echoed in response — could leak account
        identifiers, region info, etc.).

        Returns:
            (True, "Connection successful") on success,
            (False, "<generic explanation>") on any failure.
        """
        try:
            client = self._get_client()
            client.list_certificates(MaxItems=1)
            return True, "Connection successful"
        except botocore.exceptions.NoCredentialsError as e:
            logger.warning("ACM source '%s': no credentials: %s", self.source.name, e)
            return False, (
                "No AWS credentials available — "
                "check that the host has an IAM role attached"
            )
        except botocore.exceptions.PartialCredentialsError as e:
            logger.warning("ACM source '%s': partial credentials: %s", self.source.name, e)
            return False, (
                "Incomplete AWS credentials — "
                "verify access_key_id and secret_access_key are both set"
            )
        except botocore.exceptions.EndpointConnectionError as e:
            logger.warning("ACM source '%s': endpoint unreachable: %s", self.source.name, e)
            return False, (
                f"Cannot reach ACM in region '{self.source.region}' — "
                "verify region name and network connectivity"
            )
        except botocore.exceptions.ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            logger.warning("ACM source '%s': ClientError %s: %s",
                           self.source.name, code, e)
            if code in ("InvalidClientTokenId", "SignatureDoesNotMatch"):
                return False, "AWS authentication failed — verify access key is valid and active"
            if code == "UnrecognizedClientException":
                return False, "AWS credentials rejected — IAM user may have been deleted"
            if code == "AccessDeniedException":
                return False, (
                    "Insufficient permissions for ACM — adapter needs "
                    "acm:ListCertificates, acm:DescribeCertificate, acm:GetCertificate"
                )
            if code == "RequestExpired":
                return False, "Request signature expired — check system clock"
            return False, f"Connection failed: {code or 'unknown error'}"
        except Exception as e:
            logger.error("ACM source '%s': unexpected error: %s", self.source.name, e)
            return False, "Connection test failed due to an unexpected error"
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_aws_acm_adapter.py -v -p no:django
```

Expected: 52 passed (47 + 5 new).

- [ ] **Step 5: ruff checks**

```bash
ruff format --check netbox_ssl/adapters/aws_acm.py
ruff check netbox_ssl/adapters/aws_acm.py
```

Expected: both pass.

- [ ] **Step 6: Commit**

```bash
git add netbox_ssl/adapters/aws_acm.py tests/test_aws_acm_adapter.py
git commit -m "feat(adapters): AwsAcmAdapter test_connection (error mapping + generic messages)"
```

---

## Task 15: Lazy registry registration in `adapters/__init__.py`

Replace the static `_REGISTRY` dict with a `_build_registry()` factory that wraps the AWS adapter import in try/except so the plugin still works without `[aws]` extras.

**Files:**
- Modify: `netbox_ssl/adapters/__init__.py`
- Test: extend `tests/test_credential_schema.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_credential_schema.py`:

```python
def test_get_adapter_class_returns_aws_acm():
    """When boto3 is available, aws_acm is registered."""
    from netbox_ssl.adapters import get_adapter_class
    from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

    assert get_adapter_class("aws_acm") is AwsAcmAdapter


def test_get_supported_auth_methods_for_aws_acm():
    from netbox_ssl.adapters import get_supported_auth_methods

    assert get_supported_auth_methods("aws_acm") == ("aws_explicit", "aws_instance_role")


def test_get_credential_schema_for_aws_acm_explicit():
    from netbox_ssl.adapters import get_credential_schema

    schema = get_credential_schema("aws_acm", "aws_explicit")
    assert "access_key_id" in schema
    assert "secret_access_key" in schema
    assert "session_token" in schema
    assert schema["session_token"].required is False


def test_get_credential_schema_for_aws_acm_instance_role():
    from netbox_ssl.adapters import get_credential_schema

    assert get_credential_schema("aws_acm", "aws_instance_role") == {}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_credential_schema.py -v -p no:django -k "aws_acm"
```

Expected: 4 failures with `KeyError: "No adapter registered for source type 'aws_acm'"`.

- [ ] **Step 3: Replace `netbox_ssl/adapters/__init__.py` content**

Open `netbox_ssl/adapters/__init__.py`. Replace the entire file content with:

```python
"""External source adapter framework."""

import logging

from .base import BaseAdapter, CredentialField, FetchedCertificate
from .generic_rest import GenericRESTAdapter
from .lemur import LemurAdapter

logger = logging.getLogger("netbox_ssl.adapters")


def _build_registry() -> dict[str, type[BaseAdapter]]:
    """Build the adapter registry, lazy-importing optional adapters.

    Adapters with optional dependencies (e.g., aws_acm requires the [aws]
    extras for boto3) are wrapped in try/except so a missing extra does
    not break the entire plugin — the adapter is simply unavailable.
    """
    registry: dict[str, type[BaseAdapter]] = {
        "lemur": LemurAdapter,
        "generic_rest": GenericRESTAdapter,
    }
    # Optional adapter — requires netbox-ssl[aws]
    try:
        from .aws_acm import AwsAcmAdapter
        registry["aws_acm"] = AwsAcmAdapter
    except ImportError as exc:
        logger.info(
            "AWS ACM adapter not registered (boto3 not installed): %s. "
            "Install with: pip install netbox-ssl[aws]",
            exc,
        )
    return registry


_REGISTRY: dict[str, type[BaseAdapter]] = _build_registry()


def get_adapter_class(source_type: str) -> type[BaseAdapter]:
    """Lookup adapter class for a given source_type.

    Args:
        source_type: The ExternalSource.source_type value.

    Returns:
        The registered adapter class.

    Raises:
        KeyError: If no adapter is registered for the source_type
                  (either unknown source_type, or optional extras missing).
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

Expected: 24 passed (20 from Phase 1 + 4 new).

- [ ] **Step 5: Run the full adapter test suite for regression**

```bash
python -m pytest tests/test_aws_acm_adapter.py tests/test_credential_schema.py tests/test_adapters.py -v -p no:django 2>&1 | tail -5
```

Expected: all pass.

- [ ] **Step 6: ruff checks**

```bash
ruff format --check netbox_ssl/adapters/__init__.py
ruff check netbox_ssl/adapters/__init__.py
```

Expected: both pass.

- [ ] **Step 7: Commit**

```bash
git add netbox_ssl/adapters/__init__.py tests/test_credential_schema.py
git commit -m "feat(adapters): lazy-register aws_acm in registry (gracefully missing without [aws])"
```

---

## Task 16: Documentation — `docs/how-to/aws-acm-sync.md`

Operator guide: minimum IAM policy, env-var setup, ExternalSource configuration via UI + API.

**Files:**
- Create: `docs/how-to/aws-acm-sync.md`

- [ ] **Step 1: Create the doc**

Create `docs/how-to/aws-acm-sync.md`:

```markdown
# Sync certificates from AWS ACM

The AWS Certificate Manager (ACM) adapter ingests certificate metadata from
ACM into NetBox SSL as a read-only External Source. The adapter ships in
the optional `[aws]` extras — install it with:

```bash
pip install netbox-ssl[aws]
```

## Minimum IAM policy

The adapter needs three read-only ACM permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "acm:ListCertificates",
        "acm:DescribeCertificate",
        "acm:GetCertificate"
      ],
      "Resource": "*"
    }
  ]
}
```

Attach this policy to the IAM user (for `aws_explicit` auth) or instance
role (for `aws_instance_role` auth) that NetBox uses.

## Authentication options

### Option A — Explicit credentials (`aws_explicit`)

For NetBox installations outside AWS or where you prefer rotating keys
yourself.

1. Create an IAM user with the policy above.
2. Generate an access key for the user.
3. Set environment variables in the NetBox process:

```bash
export NETBOX_AWS_ACCESS_KEY_ID="AKIA..."
export NETBOX_AWS_SECRET_ACCESS_KEY="..."
# Optional, for STS temporary credentials:
export NETBOX_AWS_SESSION_TOKEN="..."
```

4. In the External Source form (or via API), set:

```json
{
  "name": "AWS ACM (eu-west-1)",
  "source_type": "aws_acm",
  "region": "eu-west-1",
  "auth_method": "aws_explicit",
  "auth_credentials": {
    "access_key_id": "env:NETBOX_AWS_ACCESS_KEY_ID",
    "secret_access_key": "env:NETBOX_AWS_SECRET_ACCESS_KEY",
    "session_token": "env:NETBOX_AWS_SESSION_TOKEN"
  }
}
```

The `env:VAR_NAME` references are resolved at sync time — secrets are never
written to the NetBox database.

### Option B — Instance role (`aws_instance_role`)

For NetBox running on AWS infrastructure (EC2 with IAM role, ECS task with
task role, Lambda with execution role). Requires IMDSv2 enabled on EC2.

1. Attach an IAM role with the policy above to the NetBox compute resource.
2. In the External Source form, set:

```json
{
  "name": "AWS ACM (eu-west-1)",
  "source_type": "aws_acm",
  "region": "eu-west-1",
  "auth_method": "aws_instance_role",
  "auth_credentials": {}
}
```

The boto3 default credential chain discovers the instance role
automatically — no env vars needed.

## What gets imported

The adapter imports the following per certificate:

- `external_id` — full ACM ARN
- `common_name` — `DomainName`
- `sans` — `SubjectAlternativeNames`
- `valid_from` / `valid_to` — `NotBefore` / `NotAfter`
- `status` — mapped from ACM `Status` (see below)
- `issuer` — `Issuer`
- `serial_number` — `Serial`
- `algorithm` / `key_size` — parsed from `KeyAlgorithm`
- `pem_content` — public PEM from `GetCertificate`
- `issuer_chain` — chain PEM from `GetCertificate`
- `fingerprint_sha256` — computed from `pem_content`

### Status mapping

| ACM Status | NetBox SSL Status | Behaviour |
|---|---|---|
| `ISSUED` | `active` | Imported |
| `EXPIRED` | `expired` | Imported |
| `REVOKED` | `revoked` | Imported |
| `PENDING_VALIDATION` | `pending` | Imported |
| `FAILED` | — | **Skipped** (no usable cert) |
| `INACTIVE` | — | **Skipped** (disabled by AWS) |
| `VALIDATION_TIMED_OUT` | — | **Skipped** (no usable cert) |

Skipped certs are not visible in NetBox. To see them, check the AWS console.

## Multi-region setups

One External Source corresponds to one AWS region. For a multi-region ACM
footprint, create one External Source per region (e.g., one for `eu-west-1`,
one for `us-east-1`). Each runs its own sync schedule and IAM context.

## What is NOT supported

- ACM Private CA (`acm-pca`) — different service, separate adapter
- DNS validation record manipulation
- Cross-account `sts:AssumeRole` chains beyond direct credentials
- ACM write operations (request, renew, import, delete)
- `export-certificate` (passphrase-encrypted private keys) — never called

## Troubleshooting

### "Connection failed: AccessDeniedException"

The IAM user/role lacks one of the three required ACM permissions. Verify
the policy attached to the principal includes `acm:ListCertificates`,
`acm:DescribeCertificate`, and `acm:GetCertificate`.

### "Cannot reach ACM in region 'XXX'"

Either the region name is wrong, or NetBox cannot make outbound HTTPS
connections to `acm.<region>.amazonaws.com`. Check region spelling and
network egress rules.

### "No AWS credentials available"

You configured `aws_instance_role` but NetBox is not running on an AWS
compute resource with an IAM role. Either move to AWS (and attach a role)
or switch to `aws_explicit` with stored credentials.

### Sync completes but 0 certs found

Check the configured region — ACM is region-scoped. A cert in `us-east-1`
is invisible to a source configured for `eu-west-1`.
```

- [ ] **Step 2: Verify mkdocs build still passes** (optional — CI catches it on PR)

```bash
# If you have mkdocs in your dev env:
mkdocs build --strict 2>&1 | tail -3
```

Expected: no warnings/errors. Skip if mkdocs not installed locally.

- [ ] **Step 3: Commit**

```bash
git add docs/how-to/aws-acm-sync.md
git commit -m "docs(how-to): operator guide for AWS ACM sync (IAM policy, auth, status mapping)"
```

---

## Task 17: CHANGELOG entry

Add the AWS ACM bullet under the existing `[Unreleased]` block (which already has the multi-credential auth entries from Phase 1).

**Files:**
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Read the current `[Unreleased]` section to find the right insertion point**

```bash
sed -n '8,40p' CHANGELOG.md
```

Expected: shows `## [Unreleased]` with `### Added` containing the multi-credential auth bullets from Phase 1.

- [ ] **Step 2: Insert the AWS ACM bullet at the END of the `### Added` block**

Open `CHANGELOG.md`. Find the `### Added` block under `## [Unreleased]`. The last existing bullet is the snapshot redaction one (ends with "stay visible)."). After that bullet (and BEFORE the `### Deprecated` heading), insert:

```markdown
- **AWS ACM read-only adapter** ([#100](https://github.com/ctrl-alt-automate/netbox-ssl/issues/100)):
  ingest certificate metadata from AWS Certificate Manager. Supports
  `aws_explicit` (access key + secret + optional session token) and
  `aws_instance_role` (boto3 default credential chain) auth methods. One
  ExternalSource per AWS region. Read-only: never writes to ACM, never
  fetches private key material. Requires the `[aws]` optional extras:
  `pip install netbox-ssl[aws]`. See
  [docs/how-to/aws-acm-sync.md](docs/how-to/aws-acm-sync.md) for the
  minimum IAM policy and configuration walkthrough.
```

- [ ] **Step 3: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs(changelog): add AWS ACM adapter entry to [Unreleased]"
```

---

## Task 18: CI workflow updates

Add `boto3` and `moto` to the unit-test install line, add the new test file to the unit-test pytest invocation, and add `boto3 'moto[acm]>=5.0,<6.0'` to the integration-test container install.

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Find and update the unit-tests `Install dependencies` step**

Open `.github/workflows/ci.yml`. Find the step that runs `pip install pytest cryptography django requests` (under the unit-tests job). Replace the run line:

From:

```yaml
- name: Install dependencies
  run: |
    pip install pytest cryptography django requests
```

To:

```yaml
- name: Install dependencies
  run: |
    pip install pytest cryptography django requests boto3 'moto[acm]>=5.0,<6.0'
```

- [ ] **Step 2: Update the unit-tests pytest invocation to include the new test file**

In the same workflow, find the `Run unit tests` step. Replace:

```yaml
- name: Run unit tests
  run: |
    python -m pytest tests/test_parser.py tests/test_models.py tests/test_events.py tests/test_expiry_scan.py -v -p no:django
```

With:

```yaml
- name: Run unit tests
  run: |
    python -m pytest tests/test_parser.py tests/test_models.py tests/test_events.py \
                     tests/test_expiry_scan.py tests/test_aws_acm_adapter.py \
                     -v -p no:django
```

- [ ] **Step 3: Update the integration-tests container install step**

Find the step `Install pytest in NetBox container`. Replace:

```yaml
- name: Install pytest in NetBox container
  run: |
    docker compose exec -T netbox bash -c "curl -sS https://bootstrap.pypa.io/get-pip.py | /opt/netbox/venv/bin/python"
    docker compose exec -T netbox /opt/netbox/venv/bin/pip install pytest
```

With:

```yaml
- name: Install pytest in NetBox container
  run: |
    docker compose exec -T netbox bash -c "curl -sS https://bootstrap.pypa.io/get-pip.py | /opt/netbox/venv/bin/python"
    docker compose exec -T netbox /opt/netbox/venv/bin/pip install pytest boto3 'moto[acm]>=5.0,<6.0'
```

- [ ] **Step 4: Verify YAML still parses**

```bash
python -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))" && echo "YAML OK"
```

Expected: `YAML OK`.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: install boto3 + moto[acm] for AWS ACM adapter tests"
```

---

## Task 19: Integration smoke test — Docker, real AWS

Confirms the whole pipeline (form → validator → adapter → AWS) works end-to-end against a real NetBox container with the configured `netbox-ssl` AWS profile. Not CI-gated; must pass locally before PR.

**Files:** (no new files — one-off shell snippets, not committed)

- [ ] **Step 1: Ensure Docker stack is up and migrations applied**

```bash
docker compose up -d
docker exec netbox-ssl-netbox-1 /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py migrate netbox_ssl 2>&1 | tail -3
```

Expected: all `netbox_ssl` migrations applied (no new migration in this PR — should be a no-op).

- [ ] **Step 2: Install `[aws]` extras in the running container**

```bash
docker exec netbox-ssl-netbox-1 /opt/netbox/venv/bin/pip install 'boto3>=1.34,<2.0' 'botocore>=1.34,<2.0' 2>&1 | tail -3
```

Expected: successful install (or "already satisfied").

- [ ] **Step 3: Restart NetBox to pick up the new adapter**

```bash
docker compose restart netbox netbox-worker 2>&1 | tail -3
```

Wait ~10-15 seconds for restart.

- [ ] **Step 4: Verify the AWS ACM adapter is registered in the running plugin**

```bash
docker exec -i netbox-ssl-netbox-1 /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py shell <<'PYEOF'
from netbox_ssl.adapters import get_adapter_class, get_supported_auth_methods
print("AWS ACM class:", get_adapter_class("aws_acm").__name__)
print("AWS ACM auth methods:", get_supported_auth_methods("aws_acm"))
PYEOF
```

Expected: `AWS ACM class: AwsAcmAdapter` and `('aws_explicit', 'aws_instance_role')`.

- [ ] **Step 5: Build an adapter instance with real AWS credentials and run `test_connection`**

Get the access key id / secret from the host's `~/.aws/credentials` for profile `netbox-ssl`:

```bash
AKID=$(aws --profile netbox-ssl configure get aws_access_key_id)
SECRET=$(aws --profile netbox-ssl configure get aws_secret_access_key)
```

Then run inside the container, passing the values as env vars:

```bash
docker exec -i \
  -e NETBOX_AWS_AKID="$AKID" \
  -e NETBOX_AWS_SECRET="$SECRET" \
  netbox-ssl-netbox-1 /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py shell <<'PYEOF'
from unittest.mock import MagicMock
from netbox_ssl.adapters.aws_acm import AwsAcmAdapter

source = MagicMock()
source.name = "smoke-test"
source.region = "eu-west-1"
source.auth_method = "aws_explicit"
source.auth_credentials = {
    "access_key_id": "env:NETBOX_AWS_AKID",
    "secret_access_key": "env:NETBOX_AWS_SECRET",
}

adapter = AwsAcmAdapter(source)
ok, msg = adapter.test_connection()
print(f"test_connection -> {ok}: {msg}")

certs = adapter.fetch_certificates()
print(f"fetch_certificates -> {len(certs)} cert(s)")
for c in certs[:3]:
    print(f"  {c.common_name} ({c.external_id})")
PYEOF
```

Expected: `test_connection -> True: Connection successful` and `fetch_certificates -> 0 cert(s)` (fresh account) or N certs if you've uploaded test certs.

- [ ] **Step 6: (No commit — smoke test does not produce committed artifacts)**

If everything above passed, the integration is verified. Move to Task 20.

If something failed, debug and re-run before continuing. Do NOT proceed to PR with a broken smoke test.

---

## Task 20: Run full test suite locally + lint + open PR

**Files:** (no new files — CI + PR plumbing)

- [ ] **Step 1: Run the full local unit test suite**

```bash
python -m pytest tests/ -v -p no:django --tb=short 2>&1 | tail -10
```

Expected: all `-m unit` tests pass, no regressions vs the baseline (910 from Phase 1 + ~52 new from this PR ≈ 962 passed, 142 skipped). Some integration tests may skip locally — that's fine.

- [ ] **Step 2: Run lint + format checks**

```bash
ruff check netbox_ssl/
ruff format --check netbox_ssl/
```

Expected: `All checks passed!` and `N files already formatted`.

- [ ] **Step 3: Run bandit security scan**

```bash
bandit -r netbox_ssl/ -x netbox_ssl/migrations,netbox_ssl/tests -s B101 -q 2>&1 | tail -10
```

Expected: 0 high, 0 medium findings. (Skip if bandit not installed locally — CI covers it.)

- [ ] **Step 4: Push the branch**

```bash
git push -u origin feature/100-aws-acm-adapter
```

Expected: `* [new branch] feature/100-aws-acm-adapter -> feature/100-aws-acm-adapter`.

- [ ] **Step 5: Open the PR against `dev`**

```bash
gh pr create --base dev --head feature/100-aws-acm-adapter \
  --title "feat: AWS ACM read-only External Source adapter (#100)" \
  --body "$(cat <<'PRBODY'
## Summary

Implements the AWS Certificate Manager adapter (issue #100) — first downstream consumer of the Phase 1 multi-credential auth pattern (PR #104). Operators with ACM-managed certificates get automatic inventory in NetBox without rekeying.

Spec: [docs/superpowers/specs/2026-04-22-aws-acm-adapter-design.md](../blob/feature/100-aws-acm-adapter/docs/superpowers/specs/2026-04-22-aws-acm-adapter-design.md)

## What ships

- `AwsAcmAdapter` with `aws_explicit` + `aws_instance_role` auth methods
- Read-only: `ListCertificates`, `DescribeCertificate`, `GetCertificate` — never writes to ACM, never fetches private key material
- Status mapping: `ISSUED → active`, `EXPIRED → expired`, `REVOKED → revoked`, `PENDING_VALIDATION → pending`. Skips `FAILED`, `INACTIVE`, `VALIDATION_TIMED_OUT`.
- Eager PEM fetch (for fingerprint-based dedup across sources)
- Single-region per ExternalSource (matches Lemur/GenericREST one-source-per-endpoint)
- `[aws]` optional extras for `boto3` — base install stays lean
- Lazy adapter registration: plugin works without `[aws]` extras (adapter just unavailable)
- moto-based unit tests (no real AWS calls in CI) + Docker integration smoke test
- `ExternalSourceTypeChoices.TYPE_AWS_ACM = "aws_acm"` enum value
- Documentation: `docs/how-to/aws-acm-sync.md` with minimum IAM policy

## Backward compatibility

Zero impact for operators not using AWS ACM. The `[aws]` extras are opt-in. No model migrations required (`source_type` field's `max_length=30` already accommodates `"aws_acm"`).

## Release target

v1.1.0 (bundled with #101 Azure Key Vault adapter — no interim release).

## Test plan

- [x] Ruff check + format pass on all plugin files
- [x] `pytest tests/ -p no:django` — 962 passed, 142 skipped, 0 failed (910 baseline + ~52 new)
- [x] Docker integration: `test_connection()` returns success against real AWS profile `netbox-ssl` (region eu-west-1)
- [x] Adapter registered in running NetBox via `get_adapter_class("aws_acm")`
- [ ] CI matrix: Integration v4.4 + v4.5 + Playwright E2E
- [ ] Bandit high/medium = 0 (run in CI)
- [ ] Gemini review
PRBODY
)" 2>&1 | tail -3
```

Expected: PR URL printed.

- [ ] **Step 6: Verify PR is live**

```bash
gh pr view --web 2>&1 | tail -2
```

Expected: browser opens the PR. Close the browser when done.

---

## Self-Review Checklist (run after completing all tasks above)

Run through the spec §8 acceptance criteria. Each should map to at least one task above:

1. ✓ `netbox_ssl/adapters/aws_acm.py` implements `BaseAdapter` — Tasks 3, 4, 12, 13, 14
2. ✓ `AwsAcmAdapter` registered via lazy import — Task 15
3. ✓ `boto3` as `[aws]` optional extras — Task 1
4. ✓ Unit tests with `moto.mock_aws` — Tasks 3-14 (52 tests across the file)
5. ✓ Integration test documented (Docker, not CI-gated) — Task 19
6. ✓ `docs/how-to/aws-acm-sync.md` — Task 16
7. ✓ SSRF guards bypass via `REQUIRES_BASE_URL=False` — Task 3 class attrs
8. ✓ `PROHIBITED_SYNC_FIELDS` runtime check — Task 8
9. ✓ Security: no creds in logs/serializers/GraphQL/changelog — Task 14 (generic messages); Phase 1 already covers serializer/GraphQL/snapshot redaction
10. ✓ CHANGELOG entry — Task 17
11. ✓ CI passes — Task 18 + Task 20

If anything is missing: add a task. If any code in a later task references a symbol defined only in a later task, fix the ordering. Re-run the checklist after fixing.

---

## Deferred (not in this plan)

Per spec §7, the following are explicitly **out of scope** for this PR:

- Phase 3 — Azure Key Vault adapter (issue #101, separate plan)
- ACM private CA (`acm-pca` API)
- ACM write operations (Request/Renew/Import/Delete)
- DNS validation manipulation
- Cross-account role chaining beyond direct credentials
- `concurrent.futures.ThreadPoolExecutor` for parallel DescribeCertificate
- AWS Secrets Manager credential resolver scheme (`aws-sm:`)
- AWS SSO / WIF / SAML credential paths
- HTMX form polish (dropdown switching credential fields per auth_method)
- Adding a `failed` status to `CertificateStatusChoices`
