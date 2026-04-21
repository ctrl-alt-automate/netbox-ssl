# Multi-Credential Auth Pattern for External Source Adapters — Design Spec

**Date:** 2026-04-21
**Author:** Elvis (via Claude Opus 4.7 brainstorm session)
**Status:** Approved — ready for implementation
**Context:** Post v1.0.1 — unblocks AWS ACM (#100) and Azure Key Vault (#101) first-party adapters.
**Reference issue:** [#99 — RFC: Multi-credential auth pattern](https://github.com/ctrl-alt-automate/netbox-ssl/issues/99)

## 1. Problem

The existing `ExternalSource.auth_credentials_reference` field holds a single `env:VAR_NAME` reference string. This works for Lemur and Generic REST adapters (one bearer token or API key) but does not accommodate the adapter families now on the roadmap (§4.1 AWS ACM, §4.2 Azure Key Vault):

| Provider | Credential components |
|---|---|
| AWS ACM | `access_key_id` + `secret_access_key` + optional `session_token` + optional `role_arn` |
| Azure Key Vault | `tenant_id` + `client_id` + `client_secret` — or a Managed Identity (no explicit credentials) |

Retrofitting multi-component credentials into a single-string field would force each adapter to invent its own ad-hoc parsing (e.g. comma-separated, JSON, positional). That duplicates logic, makes credential handling hard to audit, and blocks any shared UX improvements. The plugin needs one credential model that serves today's single-token adapters, tomorrow's multi-component cloud adapters, and whatever comes after (Google Certificate Manager, HashiCorp Vault, mTLS certs for authentication, etc.) without another model migration.

## 2. Goals and non-goals

### In scope

- A single canonical storage shape for credential references on `ExternalSource`.
- First-class role-based authentication paths (AWS instance role, Azure Managed Identity) that bypass explicit credential storage entirely.
- Per-adapter credential schema declaration so the ExternalSource form can validate early and produce field-specific error messages.
- Zero-code-change backward compatibility for existing Lemur / Generic REST configurations — operators run `manage.py migrate` and their sources continue to work.
- Changelog, API, and GraphQL scrubbing so credential references never leak outside the admin-facing form.
- A clear deprecation path for the legacy `auth_credentials_reference` field, removed in v2.0.0.
- Test coverage that exercises every auth-method permutation without requiring real cloud accounts.

### Out of scope

- Credential-source expansion beyond `env:` (no `vault:`, `file:`, `aws-sm:`, etc.) — env-refs are sufficient for the v1.1 adapters; new schemes can be added later without further model changes.
- Form UX beyond the existing `Textarea` JSON widget — labeled per-field rendering with HTMX is nice-to-have, not blocking.
- AWS IAM Identity Center (SSO), Workload Identity Federation (WIF), Azure CLI credentials, or any other non-server-side auth flavor. Documented as "not supported in v1.1" with a clear promotion path.
- Changes to adapters other than `LemurAdapter` and `GenericRESTAdapter` (the AWS and Azure adapters are separate deliverables in #100 and #101, built on top of this design).
- Credential **rotation** orchestration. The plugin continues to trust the host's env/role/MI to rotate; it only reads.

### Non-goals (explicit)

- This design does **not** introduce encrypted-at-rest storage of credentials in the plugin database. Credentials remain references only. ADR-02 (No Private Key Storage) and ADR-06 (External Sources Read-Only) are reaffirmed, not modified.
- This design does **not** introduce a new permission model for credentials. Existing NetBox permissions (`view_externalsource`, `change_externalsource`) govern access; credential content is already scrubbed from reads.

## 3. Key architectural decisions

Four decisions drove the design. Each is backed by a brainstorm Q&A captured here so the reasoning survives the conversation.

### 3.1 Graceful migration over strict compatibility

**Decision.** Add a new `auth_credentials` JSONField and run a Django data migration (0021) that backfills every existing row's `auth_credentials_reference` into `auth_credentials["token"]`. Operators run `manage.py migrate` and existing sources keep working — no manual reconfiguration.

**Alternative considered.** Preserving `auth_credentials_reference` as the primary storage forever and adding a secondary field only for multi-component adapters. Rejected because it splits credential storage into two patterns ("use this field sometimes, that field other times") which adds cognitive load for every future adapter contributor.

### 3.2 Role-based auth as a first-class path

**Decision.** The design supports `auth_method="aws_instance_role"` and `auth_method="azure_managed_identity"` as first-class choices from day one. Sources using these methods leave `auth_credentials` empty; the adapter delegates credential acquisition to the cloud SDK's default chain (IMDSv2, ECS task metadata, Managed Identity endpoint).

**Alternative considered.** Shipping explicit-credentials-only in v1.1 and adding role-based later. Rejected because the incremental design complexity is low (one `if auth_method in {...}: return empty_dict`) and deferring it would force early adopters to reconfigure when v1.2 lands.

### 3.3 Per-adapter credential schema declaration

**Decision.** Each adapter class declares a `credential_schema(auth_method: str) -> dict[str, CredentialField]` classmethod. The `ExternalSource` form reads this schema at save time and validates that (a) every `required=True` key is present, (b) no unknown keys are provided, and (c) every value is a valid `env:VAR_NAME` reference. Failed validation produces field-specific error messages.

**Alternative considered.** A generic "credentials bag" JSONField with no schema — adapters read `creds.get("access_key_id")` and runtime-fail on missing keys. Rejected because error messages would surface only at first sync ("credential X is None"), and the adapter contract would be invisible to form users and API consumers.

### 3.4 One canonical field in v1.1, deprecate the old one

**Decision.** The new `auth_credentials` JSONField becomes canonical. The existing `auth_credentials_reference` CharField is marked deprecated in v1.1 and removed in v2.0.0 per the existing [§8 Planned Breaking Changes](../../project-requirement-document/ROADMAP.md#8-planned-breaking-changes) pattern.

**Alternative considered.** Keeping both fields indefinitely. Rejected because the purpose of v2.0.0 is exactly the cleanup of deprecated surface area.

## 4. Architecture overview

```
                      ExternalSource (DB row)
                      ───────────────────────
                      source_type = "aws_acm"
                      auth_method = "aws_explicit"
                      auth_credentials = {
                        "access_key_id":     "env:AWS_KEY",
                        "secret_access_key": "env:AWS_SECRET"
                      }
                               │
                               │ (form save)
                               ▼
            ┌─────────────────────────────────────┐
            │ ExternalSourceSchemaValidator       │
            │   AwsAcmAdapter.credential_schema() │
            │   Checks required keys + env:refs   │
            └─────────────────────────────────────┘
                               │
                               │ (sync trigger)
                               ▼
                        AwsAcmAdapter
                        ─────────────
                        resolve_credentials() →
                               │
                               ▼
                       ┌──────────────────┐
                       │ CredentialResolver│
                       │  env:AWS_KEY  → $$│    (per component)
                       │  env:AWS_SECRET → $$│
                       └──────────────────┘
                               │
                               ▼
                      boto3.Session(
                         aws_access_key_id=...,
                         aws_secret_access_key=...
                      )
```

For role-based (`auth_method="aws_instance_role"`), `auth_credentials` is empty and the adapter skips `CredentialResolver` entirely — boto3 picks up credentials from IMDSv2 / ECS task metadata / environment.

### 4.1 Three core components

1. **`ExternalSource.auth_credentials`** — JSONField storing credential **references** (`"env:VAR_NAME"`), never raw values. Empty for role-based auth methods.
2. **`BaseAdapter.credential_schema()`** — classmethod on each adapter returning a `dict[str, CredentialField]` describing the required and optional credential components for a given `auth_method`.
3. **`CredentialResolver.resolve_many(refs: dict) -> dict`** — minor extension to the existing resolver; calls `resolve()` per value and returns a parallel dict. Cached per adapter instance for the duration of one sync run.

### 4.2 Separation of concerns

- **Credentials** live on `ExternalSource.auth_credentials` (JSON, values are refs).
- **Credential acquisition** is driven by `auth_method`:
  - `bearer` / `api_key` / `*_explicit` → explicit refs via `CredentialResolver`
  - `aws_instance_role` / `azure_managed_identity` → host identity via SDK default chain
- **Credential validation** happens in `ExternalSourceSchemaValidator` — used by the form, the REST serializer, and any future management command.
- **Credential usage** is owned by each adapter's `_build_session()` / `_build_credential()` method.

## 5. Data model

### 5.1 Extended `AuthMethodChoices`

```python
class AuthMethodChoices(ChoiceSet):
    AUTH_BEARER = "bearer"                             # existing
    AUTH_API_KEY = "api_key"                           # existing
    AUTH_AWS_EXPLICIT = "aws_explicit"                 # new v1.1
    AUTH_AWS_INSTANCE_ROLE = "aws_instance_role"       # new v1.1
    AUTH_AZURE_EXPLICIT = "azure_explicit"             # new v1.1
    AUTH_AZURE_MANAGED_IDENTITY = "azure_managed_identity"  # new v1.1

    CHOICES = [
        (AUTH_BEARER, "Bearer Token", "blue"),
        (AUTH_API_KEY, "API Key (Header)", "yellow"),
        (AUTH_AWS_EXPLICIT, "AWS Explicit Credentials", "orange"),
        (AUTH_AWS_INSTANCE_ROLE, "AWS Instance Role", "green"),
        (AUTH_AZURE_EXPLICIT, "Azure Service Principal", "blue"),
        (AUTH_AZURE_MANAGED_IDENTITY, "Azure Managed Identity", "green"),
    ]
```

### 5.2 `ExternalSource` field changes

```python
class ExternalSource(NetBoxModel):
    # NEW — primary credential storage (v1.1)
    auth_credentials = models.JSONField(
        default=dict,
        blank=True,
        help_text=(
            "Mapping of credential component name to a reference string "
            "(e.g. {'access_key_id': 'env:AWS_KEY'}). "
            "Leave empty for role-based auth methods."
        ),
    )

    # DEPRECATED — preserved one minor cycle, removed in v2.0.0
    auth_credentials_reference = models.CharField(
        max_length=512,
        blank=True,
        help_text=(
            "DEPRECATED in v1.1, removed in v2.0. "
            "Use auth_credentials instead. Kept for backward-compatibility."
        ),
    )
```

Neither field has `null=True` — `auth_credentials` defaults to `{}`, `auth_credentials_reference` defaults to `""`. Empty is a valid state for role-based auth.

### 5.3 Validation is **form-level, not DB-level**

Because the same model must accept both explicit-credentials rows and role-based rows (which have empty `auth_credentials`), DB-level constraints cannot enforce schema compliance. Form validation (and equivalent serializer validation) is the single gate. See §8.

## 6. Migration path

### 6.1 Migration `0021_external_source_auth_credentials`

```python
def _migrate_auth_credentials(apps, schema_editor):
    ExternalSource = apps.get_model("netbox_ssl", "ExternalSource")
    for source in ExternalSource.objects.all():
        if source.auth_credentials:
            continue  # already migrated (idempotent re-run)
        if source.auth_credentials_reference:
            # Lemur / GenericREST: wrap single string as {"token": ...}
            source.auth_credentials = {"token": source.auth_credentials_reference}
            source.save(update_fields=["auth_credentials"])


class Migration(migrations.Migration):
    dependencies = [("netbox_ssl", "0020_compliancetrendsnapshot_netboxmodel_fields")]
    operations = [
        migrations.AddField(
            model_name="externalsource",
            name="auth_credentials",
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.RunPython(_migrate_auth_credentials, migrations.RunPython.noop),
    ]
```

### 6.2 Migration properties

- **Idempotent**: re-running the migration is safe (skips rows where `auth_credentials` is already populated).
- **Additive**: only adds a column + copies data. No destructive operations.
- **Reverse-safe but lossy**: `RunPython.noop` as reverse — downgrade preserves the new column; the old field remains the single source of truth for pre-v1.1 code. Accepted trade-off because full reversibility would require re-flattening dicts into strings, which loses information for rows edited post-migration.

### 6.3 Deprecation timeline

- **v1.1.0 (this release)**: `auth_credentials_reference` marked deprecated in model help text, CHANGELOG, and [`docs/development/versioning.md`](../../docs/development/versioning.md).
- **v1.1.x**: field still accepted by form and serializer for backward compatibility; form prefers `auth_credentials` when both are set.
- **v2.0.0**: `auth_credentials_reference` removed in its own migration. Added to ROADMAP §8 Planned Breaking Changes alongside the existing `add_certificate` permission fallback removal.

### 6.4 Added to ROADMAP §8

```markdown
### 8.2 Removal of auth_credentials_reference field on ExternalSource

- Deprecated in: v1.1.0
- Removal target: v2.0.0
- Operator action: no code change needed IF you've migrated via manage.py
  migrate in v1.1 (the field content is already copied to
  auth_credentials["token"]). If you still rely on auth_credentials_reference
  in custom code, switch to auth_credentials before upgrading to v2.0.
```

## 7. Adapter credential schema declaration

### 7.1 `CredentialField` dataclass

```python
# netbox_ssl/adapters/base.py

@dataclass(frozen=True)
class CredentialField:
    """Metadata for one credential component.

    required:  Must be present in auth_credentials at form-save time.
    label:     User-facing label for form / UI rendering.
    secret:    If True, treat this component as highly sensitive
               (future: may drive UI masking, scheme restrictions).
    help_text: Short description shown in the form.
    """
    required: bool = True
    label: str = ""
    secret: bool = False
    help_text: str = ""
```

Intentionally **no `default` attribute**. Credentials must always be explicit; a default would silently inject values.

### 7.2 Adapter extensions

```python
class BaseAdapter(ABC):
    SUPPORTED_AUTH_METHODS: tuple[str, ...] = ()

    @classmethod
    def credential_schema(cls, auth_method: str) -> dict[str, CredentialField]:
        """Return required/optional credential components for this auth_method."""
        if auth_method not in cls.SUPPORTED_AUTH_METHODS:
            raise ValueError(
                f"{cls.__name__} does not support auth_method '{auth_method}'"
            )
        return {}
```

`SUPPORTED_AUTH_METHODS` is a `tuple` (not `frozenset`) because order is meaningful — the first value becomes the form default for a given `source_type`.

### 7.3 Concrete schemas

**Lemur** (trivial upgrade):

```python
class LemurAdapter(BaseAdapter):
    SUPPORTED_AUTH_METHODS = ("bearer",)

    @classmethod
    def credential_schema(cls, auth_method: str) -> dict[str, CredentialField]:
        return {
            "token": CredentialField(
                required=True, label="API Token",
                secret=True, help_text="Lemur API bearer token",
            ),
        }
```

**GenericREST**:

```python
class GenericRESTAdapter(BaseAdapter):
    SUPPORTED_AUTH_METHODS = ("bearer", "api_key")

    @classmethod
    def credential_schema(cls, auth_method: str) -> dict[str, CredentialField]:
        return {
            "token": CredentialField(
                required=True, label="API Token / Key",
                secret=True, help_text="Bearer token or API key value",
            ),
        }
```

**AWS ACM** (new adapter, scope lives in #100):

```python
class AwsAcmAdapter(BaseAdapter):
    SUPPORTED_AUTH_METHODS = ("aws_explicit", "aws_instance_role")

    @classmethod
    def credential_schema(cls, auth_method: str) -> dict[str, CredentialField]:
        if auth_method == "aws_explicit":
            return {
                "access_key_id":     CredentialField(required=True, label="AWS Access Key ID"),
                "secret_access_key": CredentialField(required=True, label="AWS Secret Access Key", secret=True),
                "session_token":     CredentialField(required=False, label="AWS Session Token", secret=True),
                "role_arn":          CredentialField(required=False, label="Role ARN"),
            }
        if auth_method == "aws_instance_role":
            return {
                "role_arn": CredentialField(required=False, label="Role ARN"),
            }
        raise ValueError(f"AwsAcmAdapter does not support {auth_method}")
```

**Azure Key Vault** (new adapter, scope lives in #101):

```python
class AzureKvAdapter(BaseAdapter):
    SUPPORTED_AUTH_METHODS = ("azure_explicit", "azure_managed_identity")

    @classmethod
    def credential_schema(cls, auth_method: str) -> dict[str, CredentialField]:
        if auth_method == "azure_explicit":
            return {
                "tenant_id":     CredentialField(required=True, label="Azure Tenant ID"),
                "client_id":     CredentialField(required=True, label="Azure Client ID"),
                "client_secret": CredentialField(required=True, label="Client Secret", secret=True),
            }
        if auth_method == "azure_managed_identity":
            return {
                "client_id": CredentialField(
                    required=False, label="User-Assigned Identity Client ID",
                    help_text="Omit for system-assigned managed identity",
                ),
            }
        raise ValueError(f"AzureKvAdapter does not support {auth_method}")
```

### 7.4 Adapter registry helpers

```python
# netbox_ssl/adapters/__init__.py

def get_adapter_class(source_type: str) -> type[BaseAdapter]:
    """Existing lookup: source_type → adapter class."""
    ...

def get_supported_auth_methods(source_type: str) -> tuple[str, ...]:
    """Return auth_methods the adapter for source_type supports."""
    return get_adapter_class(source_type).SUPPORTED_AUTH_METHODS

def get_credential_schema(source_type: str, auth_method: str) -> dict[str, CredentialField]:
    """Return credential schema for (source_type, auth_method) pair."""
    return get_adapter_class(source_type).credential_schema(auth_method)
```

## 8. Role-based auth handling

### 8.1 AWS — `aws_instance_role` and `aws_explicit + role_arn`

```python
class AwsAcmAdapter(BaseAdapter):
    def _build_boto3_session(self) -> boto3.Session:
        creds = self.source.auth_credentials

        if self.source.auth_method == "aws_explicit":
            resolved = CredentialResolver.resolve_many(creds)
            session = boto3.Session(
                aws_access_key_id=resolved["access_key_id"],
                aws_secret_access_key=resolved["secret_access_key"],
                aws_session_token=resolved.get("session_token"),
                region_name=self.source.region,
            )
        elif self.source.auth_method == "aws_instance_role":
            # boto3 default chain: IMDSv2 → ECS → env → config
            session = boto3.Session(region_name=self.source.region)
        else:
            raise ValueError(f"Unsupported auth_method: {self.source.auth_method}")

        role_arn_ref = creds.get("role_arn")
        if role_arn_ref:
            # role_arn is env-referenced like every other credential: the
            # validator rejects literal ARNs because "arn:" is not a supported
            # scheme. Operators who want a static ARN set it in an env var.
            resolved_arn = CredentialResolver.resolve(role_arn_ref)
            sts = session.client("sts")
            assumed = sts.assume_role(
                RoleArn=resolved_arn,
                RoleSessionName=f"netbox-ssl-{self.source.pk}",
            )
            session = boto3.Session(
                aws_access_key_id=assumed["Credentials"]["AccessKeyId"],
                aws_secret_access_key=assumed["Credentials"]["SecretAccessKey"],
                aws_session_token=assumed["Credentials"]["SessionToken"],
                region_name=self.source.region,
            )
        return session
```

**STS assume-role is a combinable layer** — works for both `aws_explicit` and `aws_instance_role`. Not modeled as a separate `auth_method` because that would require two separate schemas for what is really a post-auth step.

### 8.2 Azure — `azure_managed_identity` and `azure_explicit`

```python
class AzureKvAdapter(BaseAdapter):
    def _build_credential(self):
        from azure.identity import ClientSecretCredential, ManagedIdentityCredential
        creds = self.source.auth_credentials

        if self.source.auth_method == "azure_explicit":
            resolved = CredentialResolver.resolve_many(creds)
            return ClientSecretCredential(
                tenant_id=resolved["tenant_id"],
                client_id=resolved["client_id"],
                client_secret=resolved["client_secret"],
            )
        elif self.source.auth_method == "azure_managed_identity":
            client_id_ref = creds.get("client_id")
            client_id = (
                CredentialResolver.resolve(client_id_ref) if client_id_ref else None
            )
            return ManagedIdentityCredential(client_id=client_id)
        raise ValueError(f"Unsupported auth_method: {self.source.auth_method}")
```

**`ManagedIdentityCredential` explicitly, not `DefaultAzureCredential`.** `DefaultAzureCredential` silently tries Azure CLI tokens, environment variables, workload identity, etc. in sequence — opaque and surprising in a server-side plugin. The explicit class makes it obvious to auditors where credentials come from.

### 8.3 Security implications of role-based auth

Role-based auth is **more secure** than env-based explicit credentials:

- No plaintext secrets in environment variables (eliminates accidental leakage via logs, process listings, core dumps).
- Short-lived tokens via IMDSv2 / Managed Identity rotate automatically.
- Least-privilege IAM policies / Azure RBAC attached to the host identity.
- Credential rotation is the cloud provider's job, not the operator's.

Documentation must make this clear:

- `docs/how-to/aws-acm-sync.md` (deliverable of #100): minimum IAM policy example, IMDSv2 requirement, example STS assume-role setup.
- `docs/how-to/azure-key-vault-sync.md` (deliverable of #101): minimum Key Vault RBAC role (`Key Vault Certificate User`), System-Assigned vs User-Assigned MI guidance.
- `docs/how-to/external-source-ingestion.md` general section: why role-based is preferred when available.

### 8.4 Explicitly out of v1.1 scope

| Not supported in v1.1 | Why | Promotion path |
|---|---|---|
| AWS IAM Identity Center (SSO) | Requires `sso_*` entries in `~/.aws/config` — too many host-side moving parts | Add if a community member commits to maintaining + documenting |
| AWS Cognito Identity Pools | End-user auth, not server-to-server | Unlikely to be relevant; reject if proposed |
| Azure Workload Identity Federation (WIF) | OIDC-based federation (GitHub Actions → Azure); not a typical NetBox deployment shape | Consider in v1.2 if demand emerges |
| Azure CLI / Visual Studio credentials | Developer convenience, not production-worthy | Not planned |
| AWS federated SAML sessions | Specific to corporate AD-integrated AWS accounts | Not planned unless requested |

## 9. Form validation + error handling

### 9.1 `ExternalSourceSchemaValidator` — single source of truth

A utility class used by the form, serializer, and any future management command. Prevents validation drift between API and UI.

```python
# netbox_ssl/utils/external_source_validator.py

class ExternalSourceSchemaValidator:
    """Validate ExternalSource credential payload against the adapter schema."""

    @staticmethod
    def validate(source_type: str, auth_method: str, auth_credentials: dict) -> None:
        """Raise ValidationError with field-specific errors, or return cleanly."""
        from ..adapters import get_adapter_class

        try:
            adapter_cls = get_adapter_class(source_type)
        except KeyError:
            raise ValidationError({"source_type": f"Unknown source_type '{source_type}'"})

        if auth_method not in adapter_cls.SUPPORTED_AUTH_METHODS:
            raise ValidationError({
                "auth_method": (
                    f"{adapter_cls.__name__} does not support '{auth_method}'. "
                    f"Supported: {list(adapter_cls.SUPPORTED_AUTH_METHODS)}"
                )
            })

        schema = adapter_cls.credential_schema(auth_method)

        extra_keys = set(auth_credentials.keys()) - set(schema.keys())
        if extra_keys:
            raise ValidationError({
                "auth_credentials": (
                    f"Unknown credential keys: {sorted(extra_keys)}. "
                    f"Allowed: {sorted(schema.keys())}"
                )
            })

        for key, field_spec in schema.items():
            if field_spec.required and key not in auth_credentials:
                raise ValidationError({
                    "auth_credentials": (
                        f"Missing required credential '{key}' ({field_spec.label})"
                    )
                })

        for key, ref in auth_credentials.items():
            if not isinstance(ref, str) or not ref.strip():
                raise ValidationError({
                    "auth_credentials": (
                        f"Credential '{key}' must be a non-empty string reference"
                    )
                })
            if ":" in ref:
                scheme = ref.split(":", 1)[0].strip().lower()
                if scheme not in CredentialResolver.SUPPORTED_SCHEMES:
                    raise ValidationError({
                        "auth_credentials": (
                            f"Credential '{key}' uses unsupported scheme '{scheme}'. "
                            f"Supported: {sorted(CredentialResolver.SUPPORTED_SCHEMES)}"
                        )
                    })
```

**Validator does not resolve env-refs** — that would implicitly leak whether a specific env-var is set on the NetBox host. First real resolve happens at `test_connection()` or first sync.

### 9.2 Form

```python
# netbox_ssl/forms/external_source.py (new file)

class ExternalSourceForm(NetBoxModelForm):
    auth_credentials = forms.JSONField(
        required=False,
        widget=forms.Textarea(attrs={"rows": 5, "class": "font-monospace"}),
        help_text='JSON mapping, e.g. {"access_key_id": "env:AWS_KEY"}',
    )

    class Meta:
        model = ExternalSource
        fields = (
            "name", "source_type", "base_url",
            "auth_method", "auth_credentials",
            "field_mapping", "sync_interval_minutes",
            "enabled", "verify_ssl", "tenant",
        )

    def clean(self):
        cleaned = super().clean()
        ExternalSourceSchemaValidator.validate(
            source_type=cleaned.get("source_type"),
            auth_method=cleaned.get("auth_method"),
            auth_credentials=cleaned.get("auth_credentials") or {},
        )
        return cleaned
```

### 9.3 Error surface

| Scenario | Gate | Message |
|---|---|---|
| Unknown credential key | Form save | `"Unknown credential keys: ['foo']. Allowed: [...]"` |
| Missing required key | Form save | `"Missing required credential 'access_key_id' (AWS Access Key ID)"` |
| Invalid reference format | Form save | `"Credential 'access_key_id' uses unsupported scheme 'file'. Supported: ['env']"` |
| source_type × auth_method mismatch | Form save | `"AwsAcmAdapter does not support auth_method 'bearer'. Supported: ['aws_explicit', 'aws_instance_role']"` |
| Env-var not set | `test_connection()` | `"Connection failed: Environment variable 'AWS_KEY' is not set"` (logged internally; API returns generic) |
| Wrong credentials (auth OK, access denied) | `test_connection()` | `"Connection failed: AuthorizationError"` (generic per existing v0.7.5 pattern) |
| IAM role not attached | `test_connection()` | `"No credentials available. For aws_instance_role, ensure IMDSv2 is enabled and an IAM role is attached"` (role-specific hint, not credential-sensitive) |

**Rule (from v0.7.5 hardening):** API responses log `str(e)` internally but return generic messages. Form errors may be specific because they mirror the authenticated operator's input.

### 9.4 API serializer changes

```python
class ExternalSourceSerializer(NetBoxModelSerializer):
    auth_credentials_reference = serializers.CharField(write_only=True, required=False)
    auth_credentials = serializers.JSONField(write_only=True, required=False)

    class Meta:
        model = ExternalSource
        fields = [
            # ... existing ...
            "auth_method",
            "auth_credentials",
            "auth_credentials_reference",  # deprecated, still accepted
            "has_credentials",
        ]

    def get_has_credentials(self, obj) -> bool:
        if obj.auth_method in {"aws_instance_role", "azure_managed_identity"}:
            return True
        return bool(obj.auth_credentials)

    def validate(self, attrs):
        ExternalSourceSchemaValidator.validate(
            source_type=attrs.get("source_type") or (self.instance and self.instance.source_type),
            auth_method=attrs.get("auth_method") or (self.instance and self.instance.auth_method),
            auth_credentials=attrs.get("auth_credentials") or {},
        )
        return attrs
```

### 9.5 GraphQL exclusion

`auth_credentials` added to the explicit GraphQL exclusion list alongside `auth_credentials_reference`. A read-only `has_credentials: Boolean!` field is exposed for UI consumers.

### 9.6 Changelog scrubbing

```python
def snapshot(self):
    """Preserve key-level audit trail; redact reference values."""
    data = super().snapshot() or {}
    if isinstance(data.get("auth_credentials"), dict):
        data["auth_credentials"] = {
            key: "<redacted>" for key in data["auth_credentials"].keys()
        }
    if data.get("auth_credentials_reference"):
        data["auth_credentials_reference"] = "<redacted>"
    return data
```

**Key additions/removals remain visible** (structural audit trail); **value changes (env-ref rotations) are not visible** (prevents historical env-var name leakage). This matches the right granularity — structural audit is valuable, reference-value history is a reconnaissance signal.

## 10. Testing strategy

### 10.1 Layers

```
Unit tests           — schema + validator + form       (CI: always)
Adapter unit tests   — moto (AWS) / SDK patch (Azure)  (CI: always)
Integration tests    — Docker + NetBox DB              (CI: Docker jobs)
E2E tests            — real AWS/Azure free-tier        (manual, documented)
```

### 10.2 Unit — schema

```python
@pytest.mark.unit
def test_aws_explicit_schema_requires_key_and_secret():
    schema = AwsAcmAdapter.credential_schema("aws_explicit")
    assert schema["access_key_id"].required is True
    assert schema["secret_access_key"].required is True
    assert schema["secret_access_key"].secret is True
    assert schema["session_token"].required is False

@pytest.mark.unit
def test_credential_schema_rejects_unsupported_auth_method():
    with pytest.raises(ValueError, match="does not support"):
        AwsAcmAdapter.credential_schema("bearer")

@pytest.mark.unit
def test_lemur_schema_single_token_post_migration():
    schema = LemurAdapter.credential_schema("bearer")
    assert set(schema.keys()) == {"token"}
```

### 10.3 Unit — validator + form

```python
@pytest.mark.unit
def test_form_rejects_unknown_credential_keys():
    form = ExternalSourceForm(data={
        "source_type": "aws_acm", "auth_method": "aws_explicit",
        "auth_credentials": {"access_key_id": "env:KEY", "foo": "env:BAR"},
        ...
    })
    assert not form.is_valid()
    assert "Unknown credential keys" in str(form.errors["auth_credentials"])

@pytest.mark.unit
def test_form_accepts_empty_credentials_for_instance_role():
    form = ExternalSourceForm(data={
        "source_type": "aws_acm", "auth_method": "aws_instance_role",
        "auth_credentials": {}, ...
    })
    assert form.is_valid()
```

### 10.4 Unit — adapter credential resolution (AWS via moto, Azure via SDK patch)

```python
@mock_sts
@mock_acm
def test_aws_explicit_builds_session_from_env():
    os.environ["AWS_KEY"] = "AKIATEST"
    os.environ["AWS_SECRET"] = "secrettest"
    source = make_source(auth_method="aws_explicit", auth_credentials={
        "access_key_id": "env:AWS_KEY", "secret_access_key": "env:AWS_SECRET",
    })
    session = AwsAcmAdapter(source)._build_boto3_session()
    assert session.get_credentials().access_key == "AKIATEST"

@pytest.mark.unit
def test_azure_managed_identity_no_client_id():
    with patch("azure.identity.ManagedIdentityCredential") as mock_cred:
        source = make_source(auth_method="azure_managed_identity", auth_credentials={})
        AzureKvAdapter(source)._build_credential()
        mock_cred.assert_called_once_with(client_id=None)
```

### 10.5 Integration — Docker CI

- **Migration 0021 idempotence** — create v1.0.1-era source with `auth_credentials_reference="env:OLD"`, run migration, assert `auth_credentials == {"token": "env:OLD"}`, re-run migration, assert unchanged.
- **Form → model round-trip** — save via form, read via API, assert `auth_credentials` not in GET response and `has_credentials == True`.
- **Changelog scrub** — modify `auth_credentials`, inspect `ObjectChange.post_data`, assert `"<redacted>"` marker.

### 10.6 E2E — documented, not CI-gated

Manual validation scripts live at `tests/e2e/aws_acm_smoke.py` and `tests/e2e/azure_kv_smoke.py`. Each expects a live free-tier account reachable via env-vars and prints a pass/fail. Documented in `docs/development/testing-adapters.md`. Deliberately not in CI — credentials management and cost attribution are too messy to justify the coverage gain.

### 10.7 Security tests

```python
def test_auth_credentials_not_in_api_get_response(api_client):
    source = ExternalSourceFactory(auth_credentials={"token": "env:SECRET_VAR"})
    response = api_client.get(f"/api/plugins/ssl/external-sources/{source.pk}/")
    assert "auth_credentials" not in response.data

def test_changelog_redacts_credential_values():
    source = ExternalSourceFactory(auth_credentials={"token": "env:MY_SECRET"})
    snapshot = source.snapshot()
    assert snapshot["auth_credentials"] == {"token": "<redacted>"}
    assert "env:MY_SECRET" not in str(snapshot)
```

### 10.8 Coverage target

70% line coverage on new files (matches existing `.coveragerc` fail_under). Schema + validator reach 90%+ easily.

## 11. Implementation phasing

This spec ships as a single PR that lands the auth-pattern infrastructure. Downstream adapters (AWS ACM #100, Azure KV #101) build on it in separate PRs.

**Phase 1 — RFC infrastructure (this spec's implementation):**

1. Add `CredentialField` dataclass + `resolve_many()` to `CredentialResolver`.
2. Extend `AuthMethodChoices` with the four new enum values.
3. Add `auth_credentials` field + migration 0021 (with data backfill).
4. Extend `BaseAdapter` with `SUPPORTED_AUTH_METHODS` + `credential_schema()` classmethod.
5. Add schemas to `LemurAdapter` + `GenericRESTAdapter` (backward-compat trivial case).
6. Add `ExternalSourceSchemaValidator` utility.
7. Add `ExternalSourceForm` with schema-driven `clean()`.
8. Extend `ExternalSourceSerializer` with `auth_credentials` (write_only), `has_credentials` (read-only), `validate()` via the validator.
9. Exclude `auth_credentials` from GraphQL types.
10. Scrub `auth_credentials` in `ExternalSource.snapshot()`.
11. Update ROADMAP §8 with deprecation entry for `auth_credentials_reference`.
12. Update docs: `docs/how-to/external-source-ingestion.md` with the new JSON shape + deprecation note.
13. Tests across all layers per §10.

**Phase 2 — AWS ACM adapter** (separate PR, tracked in #100):

- `AwsAcmAdapter` class implementing the schemas defined here.
- `boto3` explicit dependency.
- moto-based tests.
- `docs/how-to/aws-acm-sync.md` with IAM policy example.

**Phase 3 — Azure Key Vault adapter** (separate PR, tracked in #101):

- `AzureKvAdapter` class implementing the schemas defined here.
- `azure-keyvault-certificates` + `azure-identity` explicit dependencies.
- SDK-patch-based tests.
- `docs/how-to/azure-key-vault-sync.md` with Key Vault RBAC example.

**Release target:** Phase 1 ships in v1.1.0 on its own (no adapter features, just infrastructure). Phase 2 and 3 can ship together as v1.1.1 or as separate patches (v1.1.1, v1.1.2) depending on review timing.

## 12. Security review checklist

Applied at PR review time, derived from v0.7.5 hardening patterns:

- [ ] `auth_credentials` **excluded from API GET responses** (`write_only=True`).
- [ ] `auth_credentials` **excluded from GraphQL types** (explicit fields list).
- [ ] `auth_credentials` **scrubbed in changelog snapshots** via `ExternalSource.snapshot()` override.
- [ ] `auth_credentials` **never logged as values** — only key names.
- [ ] `PROHIBITED_SYNC_FIELDS` **extended** with AWS/Azure key-material aliases (`pem_bundle`, `pfx`, `secret_value`, `key`).
- [ ] Form validation **rejects non-env schemes** (`file:`, `vault:`, etc. not supported until explicitly added).
- [ ] Serializer errors use **generic messages**; form errors may be specific (mirror operator input).
- [ ] `CredentialResolver.resolve_many()` fails fast on any missing ref — no partial credential return.
- [ ] `ManagedIdentityCredential` used explicitly, **not** `DefaultAzureCredential` (no implicit chain).
- [ ] `boto3` `allow_redirects=False` — not applicable for SDK-level calls, but `_make_request` HTTP calls preserve existing SSRF guards.
- [ ] Migration 0021 is **idempotent** — re-running is safe.

## 13. Open questions / follow-ups

None blocking. Items that may arise but can be deferred:

- **Form UX polish**: HTMX-driven field swap per-selected `auth_method` instead of the JSON textarea. Nice-to-have; v1.2 or later.
- **Credential scheme expansion**: `file:/path/to/cred`, `vault:secret/name`, `aws-sm:arn`. Each is a separate addition, behind its own RFC, with zero impact on this design.
- **Per-adapter connection-test UX**: form-preview button that runs `test_connection()` before save. Not in scope; current flow is save → open detail page → click "Test Connection".
- **Adapter auto-registration vs explicit list**: if the plugin grows to 10+ adapters, move from manual registry to entry-point-based discovery. Keep as-is for v1.1.
- **Migration for downstream forks**: anyone maintaining a fork with custom adapters must implement `credential_schema()` on their adapter classes. Documented in the v1.1 CHANGELOG as a breaking change for custom adapter authors (who are a small, advanced audience).

## 14. Relationship to existing decisions

- **ADR-01 (Passive over Active)** — reaffirmed. All credentials grant read-only access; no write credentials to external systems.
- **ADR-02 (No Private Key Storage)** — reaffirmed. `auth_credentials` stores references, not values.
- **ADR-06 (External Sources Read-Only)** — reaffirmed. This design extends the credential storage only; sync direction remains one-way.
- This spec may become **ADR-08** in the PRD if the design has wider philosophical implications. Decision left to the maintainer after the implementation PR lands.

## 15. References

- [Issue #99 — RFC: Multi-credential auth pattern](https://github.com/ctrl-alt-automate/netbox-ssl/issues/99)
- [Issue #100 — AWS ACM Read-Only Adapter](https://github.com/ctrl-alt-automate/netbox-ssl/issues/100)
- [Issue #101 — Azure Key Vault Read-Only Adapter](https://github.com/ctrl-alt-automate/netbox-ssl/issues/101)
- [`netbox_ssl/utils/credential_resolver.py`](../../netbox_ssl/utils/credential_resolver.py) — existing single-value resolver
- [`netbox_ssl/adapters/base.py`](../../netbox_ssl/adapters/base.py) — existing `BaseAdapter`, `PROHIBITED_SYNC_FIELDS`
- [`netbox_ssl/models/external_source.py`](../../netbox_ssl/models/external_source.py) — current `ExternalSource` model
- [PRD §5.6 ADR-06 External Sources as Read-Only Sync](../../project-requirement-document/PRD.md)
- [ROADMAP §4.1 AWS ACM + §4.2 Azure Key Vault](../../project-requirement-document/ROADMAP.md)
- [v0.7.5 security hardening patterns](../../CHANGELOG.md)
- boto3 credential provider chain: https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html
- azure-identity credential types: https://learn.microsoft.com/en-us/python/api/overview/azure/identity-readme
- moto (AWS mocking): https://docs.getmoto.org/
