# Azure Key Vault Read-Only Adapter — Design

**Issue:** [#101](https://github.com/ctrl-alt-automate/netbox-ssl/issues/101)
**Target release:** v1.5.0
**Date:** 2026-09-11
**Status:** Approved, ready for implementation planning

## 1. Goal

Ingest certificate metadata from Azure Key Vault as an External Source, so
operators with Azure-managed PKI get their inventory in NetBox without rekeying
it by hand. Read-only: the adapter observes, it never issues, renews or deletes.

## 2. What changed since the issue was written

Issue #101 was written in April 2026. Three of its assumptions no longer hold,
and one of its acceptance criteria would weaken the plugin's security posture.
Recording the corrections here, because the issue text will keep saying
otherwise.

### 2.1 `Key Vault Certificate User` is the wrong minimum role

The issue names `Key Vault Certificate User` as the documented minimum RBAC
role. Comparing the two candidate roles' data-plane actions:

| Role | Data actions |
|---|---|
| `Key Vault Reader` | `vaults/*/read`, `vaults/secrets/readMetadata/action` |
| `Key Vault Certificate User` | `vaults/certificates/read`, **`vaults/secrets/getSecret/action`**, `vaults/secrets/readMetadata/action`, `vaults/keys/read` |

`Key Vault Reader`'s `vaults/*/read` wildcard already covers
`vaults/certificates/read`, which is what `get_certificate()` needs to return the
public `cer` bytes. Verified empirically against the test vault: the call returns
887 DER bytes.

`Key Vault Certificate User` additionally grants `secrets/getSecret/action`. In
Key Vault that is precisely the route by which a caller downloads the
certificate's PFX **including its private key**.

Recommending it would hand private-key access to a plugin whose ADR-02 is "No
Private Keys". **`Key Vault Reader` is both sufficient and strictly safer**, and
is what the documentation will state.

### 2.2 Federated credentials need no dedicated auth method

The issue asks whether to support Workload Identity Federation now or defer it,
leaning defer. The question is moot: `DefaultAzureCredential` is a chain that
already resolves managed identity, workload identity (GitHub OIDC) and a local
`az login`. The `azure_managed_identity` method covers all three.

This matters because the provisioned test environment has **no client secret by
design** — the deferred path is the only one that can be exercised live.

### 2.3 Tag sync has no infrastructure

The issue's mapping table includes `tags → NetBox tags if sync_tags=True`.
Neither `ExternalSource.sync_tags` nor `FetchedCertificate.tags` exists. This is
in scope for v1.5.0 (see §4), which makes it a shared-contract change affecting
all four adapters rather than an Azure-local one.

### 2.4 Two pre-existing gaps this work closes

Both are in the shared sync path, not in Azure:

- **`certificate_type` is never set by sync.** v1.4.0 added EKU-based detection
  to every import path except the sync engine, because `FetchedCertificate`
  carries no such field. Certificates arriving from Lemur, AWS ACM or Generic
  REST silently take the `server` default.
- **`status` is hardcoded to Active.** `sync_engine._create_certificate` sets
  `status=STATUS_ACTIVE` unconditionally, so an already-expired or
  source-disabled certificate still lands as Active.

## 3. Scope

**In scope**

- `AzureKvAdapter` implementing `BaseAdapter`, supporting `azure_managed_identity`
  (default) and `azure_explicit`
- `TYPE_AZURE_KV` source type and registry entry
- `ExternalSource.sync_tags`
- Three optional fields on `FetchedCertificate` (`tags`, `certificate_type`,
  `status`) and the sync-engine wiring to honour them
- Optional dependency extra `netbox-ssl[azure]`
- Unit tests (mocked SDK), sync-engine tests, live tests against the test vault
- A maintainer-only GitHub Actions workflow using OIDC
- Operator documentation

**Out of scope**

- Certificate issuance, import, renewal or key rotation via Key Vault
- Key material in any form
- Secrets-store ingestion — this is the certificates API
- Populating `tags` from Lemur, AWS ACM or Generic REST. The shared field is
  added now; those adapters keep returning the empty default and can fill it
  later without a further contract change.

## 4. Architecture

### 4.1 New files

| File | Purpose |
|---|---|
| `netbox_ssl/adapters/azure_kv.py` | The adapter — the only genuinely new behaviour |
| `netbox_ssl/migrations/0028_azure_kv_source.py` | `TYPE_AZURE_KV` choice + `sync_tags` field |
| `tests/test_azure_kv_adapter.py` | Unit tests against a mocked SDK |
| `tests/test_azure_kv_live.py` | Live tests, marker `azure_live` |
| `.github/workflows/azure-integration.yml` | OIDC workflow, dispatch + main |
| `docs/how-to/azure-key-vault-sync.md` | Operator guide |

### 4.2 Changed files

Shared contract, all changes default-compatible:

- `adapters/base.py` — three optional fields on `FetchedCertificate`
- `utils/sync_engine.py` — pass the new fields through `_create_certificate` and
  `_update_certificate`; apply tags after save, only when `source.sync_tags`
- `models/external_source.py` — `TYPE_AZURE_KV`, and `sync_tags`
  (`BooleanField`, **default `False`**: tag sync is opt-in, so upgrading
  never starts writing tags to existing certificates)
- `adapters/__init__.py` — registry entry inside the existing
  `try/except ImportError` shape used for AWS
- `pyproject.toml` — `azure` extra
- Form, serializer, GraphQL — expose `sync_tags`

Deliberately unchanged: the `BaseAdapter` method signatures, and the other three
adapters.

### 4.3 Why the shared fields are optional

Each new field defaults to "this adapter has no opinion" — `tags=()`,
`certificate_type=None`, `status=None` — and the engine turns that into today's
behaviour on every path. An adapter that knows nothing about them keeps working.
This is one coherent contract extension rather than three separate ones.

The default must be *distinguishable from a real value*, not merely equal to the
model default. An earlier draft of this section argued that `certificate_type =
"server"` "reproduces today's behaviour exactly". That holds only on **create**,
where the engine has to write something and the model default is `server`
anyway. It is false on **update** and **renewal**: before this change the engine
did not touch `certificate_type` at all, so an operator's `mtls` or `client`
override survived a sync. A literal `"server"` default would be indistinguishable
from "unset" and would silently revert that override on every sync of a Lemur,
Generic REST or AWS ACM source — the very behaviour the global constraint
("byte-for-byte unchanged") forbids.

The rule the engine implements is therefore:

| Path | Behaviour when the adapter supplies nothing |
|---|---|
| create | explicit fallback to the pre-#101 result (`STATUS_ACTIVE`, `server`, no tags) |
| update | field is not written; the operator's value stands |
| renewal | same fallback as create, since the new certificate has no prior value |

`sync_tags` is the one field with no "leave it alone" mode by design: opting in
makes the source authoritative, so an empty tag set at the source **clears** the
certificate's NetBox tags rather than preserving them. An opt-in flag that means
"authoritative" should not carry an unpredictable special case.

## 5. Data flow

```
CertificateClient(vault_url=source.base_url, credential=…)
  └─ list_properties_of_certificates()          paginated; the SDK handles tokens
       └─ get_certificate(name)                 returns .cer (DER) + properties
            └─ CertificateParser.parse_der(cer)
                 └─ FetchedCertificate
```

### 5.1 Mapping

Everything X.509 knows comes from X.509. `CertificateParser.parse_der()` already
exists (added in v0.9 for DER/PKCS#7 import) and returns every field in the
plugin's canonical form.

| Field | Source |
|---|---|
| `common_name`, `sans`, `issuer`, `valid_from`, `valid_to`, `key_size`, `algorithm`, `serial_number`, `fingerprint_sha256`, `pem_content`, `certificate_type` | `parse_der(cer)` |
| `external_id` | `properties.id` — the version-independent vault URI |
| `tags` | `properties.tags`, only when `source.sync_tags` |
| `status` | Azure `enabled` flag combined with expiry |

Azure's `x509_thumbprint` is deliberately unused: it is base64 SHA-1, while the
plugin's convention is colon-separated uppercase SHA-256, which the parser
already produces.

Parsing rather than field-mapping also means the adapter inherits every future
parser improvement — `certificate_type` being the immediate example — instead of
drifting from the other import paths.

### 5.2 Status mapping

| Condition | Status |
|---|---|
| `properties.enabled is False` | Archived |
| `valid_to < now` | Expired |
| otherwise | Active |

## 6. Security model

Five layers sit between the adapter and a private key. The first is the
strongest and is platform-enforced.

1. **RBAC.** `Key Vault Reader` grants `certificates/read` but not
   `secrets/getSecret`. The PFX is unreachable regardless of what the code does.
2. **API surface.** The adapter constructs only a `CertificateClient`. Never
   `SecretClient`, never `KeyClient`. Responses contain `kid` and `sid` —
   references to the key and secret — which are legitimate metadata and are never
   dereferenced. Enforced by an AST test over the module, not by a comment.
3. **Field assertion.** `_assert_no_prohibited_keys()` on every response, the
   same guard AWS ACM uses, against `PROHIBITED_SYNC_FIELDS`.
4. **Parser guard.** The PEM the adapter produces passes
   `CertificateParser.contains_private_key`.
5. **Engine guard.** `sync_engine._check_private_key()` rejects before create or
   update.

### 6.1 Credentials

`azure_managed_identity` stores nothing: `DefaultAzureCredential()` resolves
managed identity, workload identity and a local `az login`.

`azure_explicit` takes `tenant_id`, `client_id` and `client_secret` through the
existing `env:VAR_NAME` resolver, with `secret=True` on the last. Credentials
never appear in logs, serializers, GraphQL or the changelog.

### 6.2 Vault hostname validation

`base_url` must resolve to a Key Vault host. The accepted suffixes are
`.vault.azure.net` (global), `.vault.azure.cn` (China),
`.vault.usgovcloudapi.net` (US Government) and `.vault.microsoftazure.de`
(Germany). The Azure SDK issues its own HTTP requests and
therefore bypasses `BaseAdapter._make_request`, exactly as boto3 does for AWS
ACM, so the base class's response-size cap and redirect blocking do not apply. A
suffix check keeps the adapter from being pointed at an arbitrary host. This is
an addition to what #101 specifies.

## 7. Error handling

| Condition | Behaviour |
|---|---|
| `azure-identity` / `azure-keyvault-certificates` missing | Adapter is not registered; the rest of the plugin is unaffected (existing pattern) |
| Authentication failure | `test_connection` returns `(False, generic message)`; the credential is never logged |
| HTTP 403 | Actionable message naming the required role |
| Vault not found, DNS failure | Clear message identifying the vault URL |
| Certificate has no `cer` (issuance pending) | Skipped with a warning |
| Any single certificate fails | Logged and skipped; the run continues |
| Soft-deleted or purged certificate | Absent from the listing, so the existing diff phase marks it `source_removed` |

Per-certificate failures must never abort a run: `fetch_certificates()` catches
them internally rather than propagating.

## 8. Testing strategy

Four lanes, cheapest first.

| Lane | Covers | Runs |
|---|---|---|
| Host unit | AST guards: no `SecretClient`/`KeyClient` import; registry entry; documentation coverage | Everywhere, sub-second |
| Mock unit | The SDK mocked — the bulk of adapter behaviour | Everywhere |
| Container | Sync engine with the three new fields, `django_db` | Integration lanes |
| Live | The real test vault, marker `azure_live` | `main` / manual dispatch only |

### 8.1 TDD order

Contract first, because everything else depends on it.

1. **Shared contract.** Tests that `FetchedCertificate` carries the three fields
   with defaults, and that Lemur, Generic REST and AWS ACM behave identically.
   Then add the fields and wire the engine.
2. **Adapter core**, mocked: credential schema per auth method; `test_connection`
   success, auth failure and 403; mapping; the status matrix; tags on and off;
   a missing `cer` skipped without breaking the run; prohibited fields failing
   hard.
3. **Registration and UI**: registry, form, serializer, `sync_tags` exposure.
4. **Live tests.**
5. **Documentation**, enforced by the v1.4.0 coverage guards.

### 8.2 The privilege canary

Beyond reading the three test certificates correctly, one live test asserts that
`SecretClient.get_secret()` with the same identity returns **403**.

That verifies layer 1 empirically — not that our code declines to fetch the
private key, but that the platform forbids it. It doubles as a canary: if the
role is ever widened to `Key Vault Certificate User`, the test fails loudly
instead of the blast radius quietly growing.

The AST guard in §6 (layer 2) applies to the adapter module only, so a test constructing
a `SecretClient` is not a violation.

## 9. CI

A dedicated workflow, separate from the main pipeline:

```yaml
on:
  workflow_dispatch:
  push:
    branches: [main]

permissions:
  id-token: write     # OIDC
  contents: read
```

The federated credential is scoped to `refs/heads/main`, so this cannot run on
the pull request that introduces the adapter. During development the live checks
run locally against the same vault via `az login`; after merge the workflow
guards against drift.

`AZURE_CLIENT_ID`, `AZURE_TENANT_ID` and `AZURE_SUBSCRIPTION_ID` go in as
repository **variables**, not secrets — they are identifiers. No client secret
exists for this application, by design.

The `azure_live` marker must be registered in `pytest.ini`; the host lane runs
`--strict-markers` and will otherwise fail collection.

## 10. Migration and compatibility

Migration `0028` is additive: one new choice on `source_type` and one boolean
field with a default. No data migration.

No breaking changes. Existing external sources keep working untouched; the three
new `FetchedCertificate` fields default to today's behaviour.

The adapter's dependencies are optional. An installation without
`netbox-ssl[azure]` simply does not offer the source type.

## 11. Follow-ups, not in this release

- Populate `tags` from AWS ACM (`list_tags_for_certificate`) and Lemur labels,
  now that the shared field exists.
- Consider narrowing `DefaultAzureCredential`'s chain in server contexts, where
  probing IMDS can be slow. Plain `DefaultAzureCredential` is used for v1.5.0
  because it is what makes one code path work in CI, on an Azure host, and
  locally.
- The AWS ACM adapter maps some fields by hand rather than parsing. Aligning it
  with the parse-first approach would remove a second source of truth, but is out
  of scope here.
