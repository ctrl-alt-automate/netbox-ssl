# AWS ACM Adapter Design (issue #100)

**Status:** Design — pending implementation plan
**Target release:** v1.1.0 (bundled with #101 Azure Key Vault adapter)
**Branch:** `feature/100-aws-acm-adapter` (off `dev`)
**Depends on:** Phase 1 multi-credential auth pattern (PR #104, merged to `dev`)

## Goal

Read-only ingestion of certificate metadata from AWS Certificate Manager (ACM)
as a NetBox SSL External Source. Operators with ACM-managed certificates get
automatic inventory in NetBox without rekeying, surfaced through the existing
adapter framework alongside Lemur and Generic REST.

## Non-goals

See §7 for the explicit out-of-scope list. In short: no writes to ACM, no
private CA support, no DNS validation manipulation, no cross-account role
chaining beyond direct credentials, no SNS subscriptions, no `export-certificate`
calls, no multi-region per source.

---

## 1. Architecture overview

A new adapter class `AwsAcmAdapter` lives in `netbox_ssl/adapters/aws_acm.py`,
registered through `netbox_ssl/adapters/__init__.py`. Architecturally it
diverges from Lemur and GenericREST: HTTP via `requests` is replaced by boto3
service calls. `AwsAcmAdapter` therefore **does not use** the
`BaseAdapter._make_request()` infrastructure; it builds and owns its own
boto3 client.

What the adapter reuses from the Phase 1 multi-credential infra:

- `BaseAdapter.resolve_credentials()` — returns `dict[str, str]`; the adapter
  feeds this into `boto3.client(...)` keyword arguments
- `BaseAdapter` class attributes: `SUPPORTED_AUTH_METHODS`,
  `IMPLICIT_AUTH_METHODS`, `REQUIRES_BASE_URL`, `REQUIRES_REGION`
- `BaseAdapter.credential_schema()` classmethod for form/serializer integration
- `FetchedCertificate` dataclass as the per-cert output type
- `PROHIBITED_SYNC_FIELDS` defensive check on adapter responses

What is new:

- `boto3` and `botocore` as runtime dependencies via `[aws]` optional extras
- `moto>=5.0` as a dev dependency, using its unified `mock_aws()` decorator
- `ExternalSourceTypeChoices.TYPE_AWS_ACM = "aws_acm"` enum value
- Lazy adapter registration so the plugin does not break when `[aws]` extras
  are not installed

Class attribute summary on `AwsAcmAdapter`:

```python
SUPPORTED_AUTH_METHODS = ("aws_explicit", "aws_instance_role")
IMPLICIT_AUTH_METHODS = ("aws_instance_role",)
REQUIRES_BASE_URL = False
REQUIRES_REGION = True
```

Credential schemas:

- `aws_explicit` → `{access_key_id (req, secret), secret_access_key (req, secret), session_token (opt, secret)}`
- `aws_instance_role` → `{}` (boto3 default credential chain handles it)

The boto3 client is cached as `self._client` per adapter instance. An adapter
instance lives only for the duration of one sync run, so credential refresh
(instance-role tokens) is not a concern within that window.

---

## 2. `AwsAcmAdapter` class design

```python
class AwsAcmAdapter(BaseAdapter):
    """Read-only adapter for AWS Certificate Manager."""

    SUPPORTED_AUTH_METHODS = ("aws_explicit", "aws_instance_role")
    IMPLICIT_AUTH_METHODS = ("aws_instance_role",)
    REQUIRES_BASE_URL = False
    REQUIRES_REGION = True

    def __init__(self, source) -> None:
        super().__init__(source)
        self._client = None  # lazy: built on first use

    @classmethod
    def credential_schema(cls, auth_method: str) -> dict[str, CredentialField]: ...

    def test_connection(self) -> tuple[bool, str]: ...

    def fetch_certificates(self) -> list[FetchedCertificate]: ...

    def get_certificate_detail(self, external_id: str) -> FetchedCertificate | None: ...

    # Private helpers
    def _get_client(self): ...
    def _build_client_kwargs(self) -> dict: ...
    def _list_certificate_arns(self) -> Iterator[str]: ...
    def _describe_and_get(self, arn: str) -> FetchedCertificate | None: ...
    @staticmethod
    def _parse_acm_certificate(describe_response: dict, get_response: dict) -> FetchedCertificate | None: ...
    @staticmethod
    def _map_acm_status(acm_status: str) -> str | None: ...
```

### Key design decisions

**Lazy client construction.** `__init__` only sets `self._client = None`.
`_get_client()` builds the boto3 client on first call. This makes `__init__`
cheap (no network or credential-resolution side effects) and keeps the adapter
mockable in unit tests by stubbing `_get_client`.

**`_build_client_kwargs()` is the bridge** from the Phase 1 multi-credential
infrastructure to boto3:

```python
def _build_client_kwargs(self) -> dict:
    kwargs = {"region_name": self.source.region}
    if self.source.auth_method == "aws_explicit":
        creds = self.resolve_credentials()  # dict[str, str]
        kwargs["aws_access_key_id"] = creds["access_key_id"]
        kwargs["aws_secret_access_key"] = creds["secret_access_key"]
        if "session_token" in creds:
            kwargs["aws_session_token"] = creds["session_token"]
    # aws_instance_role: omit credential kwargs; boto3 default chain handles it
    return kwargs
```

**`credential_schema()`:**

```python
@classmethod
def credential_schema(cls, auth_method: str) -> dict[str, CredentialField]:
    if auth_method == "aws_explicit":
        return {
            "access_key_id": CredentialField(
                required=True, label="Access Key ID", secret=True,
                help_text="AWS access key ID for the IAM user/role",
            ),
            "secret_access_key": CredentialField(
                required=True, label="Secret Access Key", secret=True,
                help_text="AWS secret access key (env-var ref recommended)",
            ),
            "session_token": CredentialField(
                required=False, label="Session Token", secret=True,
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

**`test_connection()`:** Calls `ListCertificates(MaxItems=1)` — cheapest valid
permissions check. Returns `(True, "Connection successful")` or
`(False, "Connection failed: <ErrorCode>")`. Generic message returned to UI;
full error logged internally to avoid credential leakage.

**`fetch_certificates()`:** Iterates `_list_certificate_arns()` and calls
`_describe_and_get(arn)` per ARN. Skips `None` results (parse failure or
status filter). Logs partial-failure count. Returns list deduped by ARN
(ARN is globally unique so no further dedup logic needed).

**`get_certificate_detail(external_id)`:** `external_id` is the cert ARN.
Direct call to `_describe_and_get(external_id)`. Used for on-demand refresh
of a single cert.

**`_map_acm_status()`:** Returns plugin status string or `None` (skip).

```python
_STATUS_MAP = {
    "ISSUED": CertificateStatusChoices.STATUS_ACTIVE,
    "EXPIRED": CertificateStatusChoices.STATUS_EXPIRED,
    "REVOKED": CertificateStatusChoices.STATUS_REVOKED,
    "PENDING_VALIDATION": CertificateStatusChoices.STATUS_PENDING,
    # FAILED, INACTIVE, VALIDATION_TIMED_OUT → not in map → None → skip
}
```

---

## 3. Data flow & mapping

Per-sync flow (sync engine calls `fetch_certificates()`):

```
fetch_certificates()
├─ _get_client()                                    # 1 boto3.client('acm', **kwargs)
├─ for arn in _list_certificate_arns():             # paginator.paginate(MaxItems=1000)
│   ├─ describe = client.describe_certificate(CertificateArn=arn)
│   │   └─ skip if _map_acm_status(status) is None  # FAILED/INACTIVE/VALIDATION_TIMED_OUT
│   ├─ get = client.get_certificate(CertificateArn=arn)
│   ├─ assert PROHIBITED_SYNC_FIELDS not in response keys (defensive)
│   ├─ cert = _parse_acm_certificate(describe, get)
│   └─ yield cert
└─ return list of FetchedCertificate
```

For N certs that pass the status filter: 1 paginated `ListCertificates` page
plus 2N per-cert calls. Accounts with more than 1000 certs trigger multiple
pages.

### Pagination

Use the boto3 built-in paginator (idiomatic, handles `NextToken` automatically):

```python
paginator = self._get_client().get_paginator("list_certificates")
for page in paginator.paginate(PaginationConfig={"PageSize": 1000}):
    for summary in page["CertificateSummaryList"]:
        yield summary["CertificateArn"]
```

### Field mapping

| ACM field (DescribeCertificate) | Plugin field | Notes |
|---|---|---|
| `CertificateArn` | `external_id` | Full ARN, unique per cert |
| `DomainName` | `common_name` | |
| `SubjectAlternativeNames` | `sans` | List → tuple |
| `NotBefore` | `valid_from` | datetime, ACM returns timezone-aware |
| `NotAfter` | `valid_to` | datetime |
| `Status` | (via `_map_acm_status`) | `None` = skip cert |
| `Issuer` | `issuer` | String (e.g. "Amazon" for AMAZON_ISSUED) |
| `Serial` | `serial_number` | Hex string |
| `KeyAlgorithm` | `algorithm` | "RSA_2048" → "rsa", "EC_prime256v1" → "ecdsa" |
| `KeyAlgorithm` | `key_size` | Parsed from string ("RSA_2048" → 2048; ECDSA → None) |
| (from `GetCertificate`) `Certificate` | `pem_content` | Public cert PEM |
| (from `GetCertificate`) `CertificateChain` | `issuer_chain` | PEM bundle (may be empty for IMPORTED certs) |
| (computed) | `fingerprint_sha256` | Computed inside `_parse_acm_certificate` from `pem_content` via `cryptography.x509.load_pem_x509_certificate(...).fingerprint(hashes.SHA256()).hex()`. `FetchedCertificate.fingerprint_sha256` is a required field, so failure to parse PEM = parse failure for the whole cert (skip). |

### Defensive parsing for IMPORTED vs AMAZON_ISSUED

ACM has two cert types: `IMPORTED` (BYOC, operator uploaded) and
`AMAZON_ISSUED` (issued by ACM's CA). Differences relevant to our adapter:

- IMPORTED certs lack `RenewalSummary` — irrelevant, we do not map it
- IMPORTED certs may have empty `CertificateChain` in `GetCertificate` response
  — use `.get("CertificateChain", "")` defensively
- IMPORTED certs have `Type: "IMPORTED"`, AMAZON_ISSUED have
  `Type: "AMAZON_ISSUED"` — adapter does not branch on this
- All optional fields use `.get()` with sensible defaults

### `PROHIBITED_SYNC_FIELDS` safety check

ACM does not expose private key material via the read-only API surface this
adapter uses. The check below is a belt-and-suspenders invariant:

```python
def _assert_no_prohibited_keys(response: dict) -> None:
    keys = {k.lower() for k in response.keys()}
    forbidden = keys & PROHIBITED_SYNC_FIELDS
    if forbidden:
        logger.error("ACM response contained prohibited keys: %s", forbidden)
        raise ValueError("Adapter response failed safety check")
```

If a hypothetical future ACM API change starts returning sensitive fields,
the adapter fails hard rather than silently leaking them into NetBox.

---

## 4. Error handling

Three failure categories with distinct behavior.

### Connectivity / authentication (whole-sync fatal)

Adapter cannot start at all. `test_connection()` returns `False` with a
generic message. `fetch_certificates()` returns an empty list and logs the
error.

| Exception | Trigger | User-facing message |
|---|---|---|
| `botocore.exceptions.NoCredentialsError` | `aws_instance_role` on non-AWS host | "No AWS credentials available — check that the host has an IAM role attached" |
| `botocore.exceptions.PartialCredentialsError` | Missing secret/key | "Incomplete AWS credentials — verify access_key_id and secret_access_key are both set" |
| `ClientError` with code `InvalidClientTokenId`/`SignatureDoesNotMatch` | Wrong credentials | "AWS authentication failed — verify access key is valid and active" |
| `ClientError` with code `UnrecognizedClientException` | IAM user deleted | "AWS credentials rejected — IAM user may have been deleted" |
| `ClientError` with code `AccessDeniedException` on `ListCertificates` | IAM policy missing `acm:ListCertificates` | "Insufficient permissions for ACM — adapter needs acm:ListCertificates, acm:DescribeCertificate, acm:GetCertificate" |
| `EndpointConnectionError` | Region typo or network down | "Cannot reach ACM in region '{region}' — verify region name and network connectivity" |
| `ClientError` with code `RequestExpired` | Clock skew | "Request signature expired — check system clock" |

For all the above: log the full exception with `str(e)` at WARNING level,
return the generic message to the UI / sync_log. Never include credential
values in messages.

### Per-certificate failures (skip, continue, count)

One cert fails, others succeed.

| Exception | Behavior |
|---|---|
| `ClientError` on `DescribeCertificate` for a specific ARN (e.g. `ResourceNotFoundException` — cert deleted between list and describe) | Skip cert, log warning, increment skipped counter |
| `ClientError` on `GetCertificate` for a specific ARN | Skip cert (without PEM, dedup is impossible), log warning, increment skipped counter |
| `_parse_acm_certificate` returns `None` (broken/unexpected data) | Skip cert, log warning |
| `KeyError` / `ValueError` during parsing | Skip cert, log warning, increment skipped counter |

This pattern matches `LemurAdapter._parse_lemur_certificate`, which also
returns `None` on parse failure and is filtered out at the loop level.

### Throttling (boto3 retries automatically)

boto3 ships with a default `Standard` retry mode: max 3 attempts, exponential
backoff on `Throttling` / `ThrottlingException` / `TooManyRequestsException`.
No additional logic required. If retries are exhausted, the resulting
`ClientError` falls into category 2 (per-cert skip).

### What we do not catch

- `Exception` (too broad — hides bugs)
- `KeyboardInterrupt`, `SystemExit` (let them propagate)
- `ImportError` for `boto3` (raise with a clear actionable message — see below)

### `ImportError` fail-fast on module load

```python
try:
    import boto3
    import botocore.exceptions
except ImportError as exc:
    raise ImportError(
        "AWS ACM adapter requires boto3. "
        "Install with: pip install netbox-ssl[aws]"
    ) from exc
```

The adapter module is only imported by registry helpers when an
`ExternalSource` with `source_type="aws_acm"` is configured (or when an
operator opens the form dropdown that contains AWS ACM). The registry uses
lazy imports (see §6) so missing extras do not break the rest of the plugin.

---

## 5. Testing strategy

```
  /\
 /e2e\        Optional smoke test against real AWS — operator-run only
 ------       
/integ\       Full sync flow: form → validator → adapter → mocked AWS
--------      
/  unit  \    Per-method tests with moto mock_aws decorator
----------
```

### Unit tests — `tests/test_aws_acm_adapter.py`

Primary coverage. Uses `moto.mock_aws` decorator to intercept all boto3 calls
to an in-memory AWS mock.

```python
import os
import pytest
import boto3
from moto import mock_aws
from unittest.mock import MagicMock, patch

pytestmark = pytest.mark.unit

@mock_aws
def test_fetch_certificates_returns_issued_active():
    client = boto3.client("acm", region_name="eu-west-1")
    arn = client.import_certificate(
        Certificate=TEST_CERT_PEM,
        PrivateKey=TEST_KEY_PEM,
        CertificateChain=TEST_CHAIN_PEM,
    )["CertificateArn"]

    source = MagicMock(spec=ExternalSource, source_type="aws_acm",
                      auth_method="aws_explicit", region="eu-west-1",
                      auth_credentials={
                          "access_key_id": "env:FAKE",
                          "secret_access_key": "env:FAKE",
                      })
    adapter = AwsAcmAdapter(source)
    with patch.dict(os.environ, {"FAKE": "test-value"}):
        certs = adapter.fetch_certificates()

    assert len(certs) == 1
    assert certs[0].external_id == arn
```

### Test coverage targets

| Scenario | Test name |
|---|---|
| Happy path: ISSUED, AMAZON_ISSUED type | `test_fetch_active_amazon_issued` |
| Happy path: ISSUED, IMPORTED type (no chain) | `test_fetch_active_imported_no_chain` |
| Status mapping: EXPIRED, REVOKED, PENDING_VALIDATION | `test_status_mapping_expired/revoked/pending` |
| Status filter: FAILED skipped | `test_failed_status_skipped` |
| Status filter: INACTIVE skipped | `test_inactive_status_skipped` |
| Status filter: VALIDATION_TIMED_OUT skipped | `test_timed_out_skipped` |
| Multi-region: cert in eu-west-1 vs us-east-1 | adapter only sees configured region |
| Pagination: >100 certs | paginator iterates, full list returned |
| Empty account: no certs | returns `[]` cleanly |
| `aws_explicit` credential schema returns 3 fields | `test_credential_schema_explicit` |
| `aws_instance_role` credential schema returns `{}` | `test_credential_schema_instance_role` |
| `_build_client_kwargs` includes session_token if provided | `test_kwargs_with_session_token` |
| `_build_client_kwargs` skips creds for instance_role | `test_kwargs_for_instance_role` |
| `test_connection()` returns True on valid creds | `test_connection_success` |
| `test_connection()` returns False with generic message on AccessDenied | `test_connection_no_perms` |
| `_map_acm_status` returns `None` for FAILED | `test_status_map_returns_none_for_failed` |
| `PROHIBITED_SYNC_FIELDS` check raises if response contains forbidden key | `test_prohibited_keys_check` |

Plus integration tests in `tests/test_credential_schema.py` for registry
helpers:

- `test_get_adapter_class_returns_aws_acm`
- `test_get_supported_auth_methods_for_aws_acm`
- `test_get_credential_schema_for_aws_acm_explicit`

### moto setup

- `moto>=5.0` — use unified `mock_aws` decorator (per-service `mock_acm` is
  deprecated in moto 5+)
- No real AWS calls in CI
- moto auto-generates dummy credentials, but the adapter path goes through
  `resolve_credentials()` → `os.environ` → our `env:FAKE` ref
- For tests that need real PEM (to test fingerprint computation), use
  `tests/cert_factory.py` — the existing self-signed cert generator

### Integration test (Docker, manual pre-PR — not CI-gated)

- Real NetBox container
- Apply migration 0021 (already applied; no new migration required)
- Create an `ExternalSource` with `source_type="aws_acm"`, `region="eu-west-1"`,
  `auth_credentials={"access_key_id": "env:NETBOX_AWS_ACCESS_KEY", ...}`
- Set real env vars from `aws configure get` for profile `netbox-ssl`
- Run sync via `python manage.py runscript ExternalSourceSync`
- Verify: 0 certs (fresh account) or N certs (if test cert was uploaded)
- Verify: GraphQL `has_credentials` returns `True` for this source

### Real-AWS smoke test (operator-run, documented, not in CI)

- Use existing `netbox-ssl` AWS profile via boto3 default chain
- Optionally upload a test cert via a `scripts/aws_acm_smoke.py` (not
  committed; documented in `docs/how-to/aws-acm-sync.md`)
- Verify connection + at least 1 cert fetch round-trip

---

## 6. Dependencies & packaging

### `pyproject.toml` changes

```toml
[project.optional-dependencies]
aws = [
    "boto3>=1.34,<2.0",
    "botocore>=1.34,<2.0",
]
dev = [
    # ... existing deps ...
    "moto[acm]>=5.0,<6.0",
    "boto3>=1.34,<2.0",
]
```

`moto[acm]` (instead of plain `moto`) installs only ACM-specific service
mocks instead of all ~200 AWS services. Saves install time and disk space.

### `flake.nix`

Already updated:

- `boto3` added to `pythonEnv` packages (core deps section)
- `moto` added to `pythonEnv` packages (testing tools section)

### `.envrc`

Already updated with a `python` wrapper that unsets `PYTHONPATH` so that
`python` resolves to python3.12 from the dev shell (not python3.13 from
`awscli2`). See `.envrc` for the full wrapper.

### CI updates (`.github/workflows/ci.yml`)

**Unit tests step:**

```yaml
- name: Install dependencies
  run: pip install pytest cryptography django requests boto3 moto
- name: Run unit tests
  run: |
    python -m pytest tests/test_parser.py tests/test_models.py \
                     tests/test_events.py tests/test_expiry_scan.py \
                     tests/test_aws_acm_adapter.py \
                     -v -p no:django
```

**Integration tests step (NetBox container):**

```yaml
- name: Install pytest in NetBox container
  run: |
    docker compose exec -T netbox bash -c "curl -sS https://bootstrap.pypa.io/get-pip.py | /opt/netbox/venv/bin/python"
    docker compose exec -T netbox /opt/netbox/venv/bin/pip install pytest boto3 'moto[acm]>=5.0,<6.0'
```

**No GitHub Actions secrets required** — moto is used for all AWS mocking;
no real AWS calls in any CI workflow.

### Lazy adapter registration

To avoid breaking the plugin when `[aws]` extras are not installed:

```python
# netbox_ssl/adapters/__init__.py

def _build_registry() -> dict[str, type[BaseAdapter]]:
    """Lazy registry — adapters with optional deps are loaded on demand."""
    registry: dict[str, type[BaseAdapter]] = {
        "lemur": LemurAdapter,
        "generic_rest": GenericRESTAdapter,
    }
    try:
        from .aws_acm import AwsAcmAdapter
        registry["aws_acm"] = AwsAcmAdapter
    except ImportError:
        # boto3 not installed — adapter unavailable but plugin still works
        pass
    return registry

_REGISTRY = _build_registry()
```

Effects:

- Operator without `[aws]` extras: plugin works, AWS ACM not in form dropdown
- Operator with `[aws]` extras: AWS ACM appears in `ExternalSourceTypeChoices`
  and form dropdown
- `get_adapter_class("aws_acm")` raises `KeyError` when extras missing — same
  failure mode as an unknown source type, no import error breaks the plugin

### Model-level enum addition

```python
# netbox_ssl/models/external_source.py
class ExternalSourceTypeChoices(ChoiceSet):
    TYPE_LEMUR = "lemur"
    TYPE_GENERIC_REST = "generic_rest"
    TYPE_AWS_ACM = "aws_acm"  # NEW

    CHOICES = [
        (TYPE_LEMUR, "Lemur", "purple"),
        (TYPE_GENERIC_REST, "Generic REST API", "blue"),
        (TYPE_AWS_ACM, "AWS Certificate Manager", "orange"),
    ]
```

`source_type` field's `max_length=30` already accommodates `aws_acm` (7
chars), so **no database migration is required for this PR**.

---

## 7. Out of scope

The following items are explicitly **not** in scope for issue #100:

### Adapter capabilities not implemented

- ACM write operations (`RequestCertificate`, `RenewCertificate`,
  `ImportCertificate`, `DeleteCertificate`) — adapter is read-only
- ACM Private CA (`acm-pca` API) — different service, different IAM
  permissions, separate feature
- DNS validation record manipulation during PENDING_VALIDATION (Route53 calls)
- Cross-account role chaining via multiple `sts:AssumeRole` hops — only
  direct credentials supported
- SNS notification subscription for cert expiry — NetBox has its own Event
  Rules; no overlap
- `export-certificate` API (returns passphrase-encrypted private key) — never
  called
- ACM "Mutual TLS" features (Truststore, etc.)

### Multi-region per source

One `ExternalSource` corresponds to one AWS region (Phase 1 model design).
Multi-region operators create one source per region. Consistent with Lemur
and GenericREST one-source-per-endpoint pattern.

### Performance optimisations

- `concurrent.futures.ThreadPoolExecutor` for parallel `DescribeCertificate`
  fan-out — sync remains sync. Roughly 10s per 500 certs is acceptable. Can
  be added if an operator with a very large account needs it.
- Caching ACM responses across sync runs — sync engine already handles
  revision detection via fingerprint
- `aioboto3` async — sync chosen in §1

### Security cleanup

- Auto-rotate IAM access keys — operator responsibility
- AWS Secrets Manager as a credential resolver scheme (`aws-sm:secret-name`)
  — Phase 1 supports only `env:`. Adding new schemes is its own RFC.
- AWS SSO / WIF / SAML credential paths — operators with those setups use
  `aws_explicit` with `session_token` or build a custom credential resolver

### UI / UX polish

- HTMX dropdown that shows/hides credential fields based on selected
  `auth_method` — Phase 1 displays the JSON field statically. Polish for
  v1.2+.
- Separate form fields for `access_key_id` / `secret_access_key` instead of
  one JSON field — same; future polish
- Auto-fill region dropdown with AWS regions — operator types it themselves

### Documentation depth

- Full IAM policy walkthrough with cross-account scenarios — minimum policy
  documented in `docs/how-to/aws-acm-sync.md`
- AWS-specific troubleshooting for less common errors (RegionDisabled, etc.)
  — error messages are descriptive enough for an operator to search

### Status mapping

- Retaining FAILED / INACTIVE / VALIDATION_TIMED_OUT certs in NetBox under a
  new `failed` status — we chose to skip them (§4 question A). If feedback
  emerges, that becomes its own issue.

---

## 8. Acceptance criteria

Mirrors the issue #100 acceptance list, refined per design above:

- [ ] `netbox_ssl/adapters/aws_acm.py` implements `BaseAdapter` with
      `fetch_certificates()`, `get_certificate_detail()`, `test_connection()`,
      `credential_schema()`
- [ ] `AwsAcmAdapter` registered in the adapter registry via lazy import,
      visible in the `ExternalSourceForm` dropdown when `[aws]` extras are
      installed
- [ ] `boto3` dependency declared as `[aws]` optional extras in
      `pyproject.toml`
- [ ] Unit tests with `moto.mock_aws` cover: status mapping (active/expired/
      revoked/pending + skip filter), credential schema, client kwargs,
      pagination, partial failures, IMPORTED vs AMAZON_ISSUED parsing
- [ ] Integration test documented (Docker, not CI-gated) against real AWS
- [ ] `docs/how-to/aws-acm-sync.md` written with minimum IAM policy example
- [ ] SSRF guards: ACM and STS endpoints implicitly bypass URL validation
      because `REQUIRES_BASE_URL=False` keeps the URL field empty/unused
- [ ] `PROHIBITED_SYNC_FIELDS` runtime check on adapter responses
- [ ] Security review: no credentials in logs, serializers, GraphQL responses,
      or changelog snapshots
- [ ] CHANGELOG entry under `[Unreleased]` (combined with #101 entry)
- [ ] CI passes: lint, unit (3.10/3.11/3.12), package-check, integration
      (v4.4 + v4.5), Playwright E2E

## References

- Issue #100: https://github.com/ctrl-alt-automate/netbox-ssl/issues/100
- ACM API docs: https://docs.aws.amazon.com/acm/latest/APIReference/
- boto3 ACM client: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/acm.html
- moto ACM mocks: https://docs.getmoto.org/en/latest/docs/services/acm.html
- Phase 1 multi-credential auth spec: `docs/superpowers/specs/2026-04-21-multi-credential-auth-pattern-design.md`
- Existing adapter base: `netbox_ssl/adapters/base.py`
- Lemur adapter precedent: `netbox_ssl/adapters/lemur.py`
