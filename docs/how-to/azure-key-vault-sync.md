# Sync certificates from Azure Key Vault

The Azure Key Vault adapter ingests certificate metadata from one vault into
NetBox SSL as a read-only External Source. The adapter ships in the optional
`[azure]` extras — install it with:

```bash
pip install netbox-ssl[azure]
```

## When to use this

- Your PKI is managed through Azure Key Vault and you want it visible
  alongside every other certificate in NetBox
- You want scheduled, read-only inventory — not issuance, not renewal, not
  key export
- NetBox runs on Azure (or with a federated workload identity) and you would
  rather use the platform identity than store a secret

## Step 1 — Grant access

The minimum role is **`Key Vault Reader`**, assigned on the vault itself or
on its resource group. Its data actions (`Microsoft.KeyVault/vaults/*/read`)
let the adapter list certificates and read their metadata — never a secret
or key value — and that is sufficient: verified against a live vault.

!!! warning "Do not grant `Key Vault Certificate User`"
    A generic Azure tutorial will point you at `Key Vault Certificate User`.
    Do not use it here. It also grants `secrets/getSecret/action`, which
    permits downloading the certificate's PFX — **including the private
    key**. NetBox SSL never needs private key material (see
    [design invariant 1 in the security model](../explanation/security-model.md#design-invariant-1-no-private-keys-ever) —
    "No private keys, ever"), so the adapter is written to never construct a
    `SecretClient`, and granting the wider role does not enable anything the
    adapter would use.

    The test suite backs this with a privilege canary
    (`tests/test_azure_kv_live.py`, gated by
    `AZURE_KV_LEAST_PRIVILEGE_IDENTITY=1`) that asserts `SecretClient.get_secret()`
    is refused with a 403 under the CI identity. Widening the role fails that
    build loudly.

## Step 2 — Choose an auth method

### Option A — Managed Identity (`azure_managed_identity`)

For NetBox running on Azure (a VM, App Service or container with a managed
identity attached) or with a federated workload identity (for example GitHub
OIDC). Nothing is stored in NetBox — `auth_credentials` stays empty (`{}`)
and the adapter uses `DefaultAzureCredential`, which resolves the identity
automatically.

```json
{
  "name": "Azure Key Vault (prod)",
  "source_type": "azure_kv",
  "base_url": "https://your-vault-name.vault.azure.net",
  "auth_method": "azure_managed_identity",
  "auth_credentials": {}
}
```

For a **user-assigned** identity, set `AZURE_CLIENT_ID` in the NetBox process
environment to the identity's client ID — `DefaultAzureCredential` picks it
up automatically; there is no separate credential field for it.

### Option B — Service Principal (`azure_explicit`)

For NetBox installations outside Azure. Set `tenant_id`, `client_id` and
`client_secret` as `env:VAR_NAME` references — the plaintext values live in
your secret manager and the NetBox process environment, never in the
database:

```bash
export NETBOX_AZURE_TENANT_ID="..."
export NETBOX_AZURE_CLIENT_ID="..."
export NETBOX_AZURE_CLIENT_SECRET="..."
```

```json
{
  "name": "Azure Key Vault (prod)",
  "source_type": "azure_kv",
  "base_url": "https://your-vault-name.vault.azure.net",
  "auth_method": "azure_explicit",
  "auth_credentials": {
    "tenant_id": "env:NETBOX_AZURE_TENANT_ID",
    "client_id": "env:NETBOX_AZURE_CLIENT_ID",
    "client_secret": "env:NETBOX_AZURE_CLIENT_SECRET"
  }
}
```

## Step 3 — Create the source

The vault URL (`https://<vault-name>.vault.azure.net`, or the matching
sovereign-cloud domain) is the `base_url`. Create one External Source per
vault — the adapter, like AWS ACM, maps one source to one endpoint. Accepted
host suffixes are `.vault.azure.net`, `.vault.azure.cn`,
`.vault.usgovcloudapi.net` and `.vault.microsoftazure.de`; anything else, or
a non-`https` scheme, is rejected before any request is made.

Use **Test Connection** on the source detail page to confirm access before
the first sync.

## Step 4 — Optional tag sync

`sync_tags` is off by default. When enabled, each Azure tag `key`/`value`
pair becomes a NetBox tag named `key=value` (a valueless tag keeps just the
key).

!!! warning "sync_tags makes Azure authoritative for tags"
    With `sync_tags` on, every sync run **replaces** the certificate's whole
    NetBox tag set with the tags currently on the Azure certificate. Any tag
    an operator added by hand in NetBox on a synced certificate is removed on
    the next run, and an Azure certificate that carries **no tags at all**
    clears the certificate's NetBox tags entirely.

    There is no exception and no way to protect an individual tag. If you need
    operator-managed tags on synced certificates, leave `sync_tags` off — with
    it off the sync never reads, writes or clears tags.

    Tag names are created on demand. A name longer than NetBox's 100-character
    limit is shortened with a short digest appended so two long Azure tags
    cannot collapse into one, and names that differ only in punctuation
    (`env=prod` and `env:prod`) get distinct slugs. A tag that still cannot be
    created is logged and skipped; it never fails the sync run.

## Step 5 — Schedule

Sync runs via the `ExternalSourceSync` NetBox Script, the same script every
other external source uses. It picks up every enabled source whose schedule
is due. Plugin-bundled scripts are not auto-registered with NetBox — see the
`SCRIPTS_ROOT` note in [Custom Scripts](../reference/scripts.md) to expose
it, then schedule it from **Customization → Scripts**.

## What gets imported

Certificate fields are parsed from the vault's DER bytes (the `cer` property)
by the plugin's own X.509 parser — the same parser every other import path
uses, so results (including EKU-based certificate type) are consistent
across adapters. Azure's own SHA-1 `x509_thumbprint` is not used.

- `external_id` — a version-independent vault URI
  (`<vault_url>/certificates/<name>`), built by the adapter rather than
  taken from Azure's own `id`, which is pinned to a specific version and
  would make every renewal look like a brand-new certificate
- `common_name`, `serial_number`, `fingerprint_sha256`, `issuer`,
  `valid_from`, `valid_to`, `sans`, `key_size`, `algorithm`, `pem_content`,
  `issuer_chain`, `certificate_type` — all parsed from the DER bytes
- `status` — mapped from the vault's certificate properties (see below)
- `tags` — only when `sync_tags` is enabled, in which case the vault is
  authoritative and an empty Azure tag set clears NetBox's tags (see Step 4)

### Status mapping

| Azure certificate state | NetBox SSL Status |
|---|---|
| Disabled (`enabled: false`) | `archived` |
| Expired (`valid_to` in the past) | `expired` |
| Otherwise | `active` |

A disabled certificate outranks an expired one — disabling is an explicit
operator action, while expiry is a fact about the clock. Expiry itself is
judged on the certificate's own parsed validity period, never on Azure's
`expires_on` metadata, so the two values can never disagree.

## What it never does

- No issuance, no renewal, no revocation — this is a read-only inventory
  adapter, consistent with every other External Source
- No private key material, ever. The adapter only ever constructs a
  `CertificateClient`, never a `SecretClient` or `KeyClient`. See
  [design invariant 1 in the security model](../explanation/security-model.md#design-invariant-1-no-private-keys-ever)

## Troubleshooting

### "Access denied by Azure" / 403 on Test Connection

The identity is missing the `Key Vault Reader` role on the vault or its
resource group. Grant that role — not `Key Vault Certificate User` (see
Step 1) — and re-test.

### A certificate disappeared from the vault but is still in NetBox

Soft-deleted certificates are not returned by Azure's certificate list. The
next sync marks the corresponding NetBox certificate `source_removed`; it
stays in NetBox for historical/assignment purposes rather than being
deleted.

### A certificate never shows up in NetBox

A certificate whose issuance is still pending has no public certificate yet
— Azure's `cer` field is empty until issuance completes. The adapter skips
it (logged, not an error) and picks it up on a later sync once the public
certificate is available.

### Sync completes but 0 certificates found

Check the vault URL — one External Source covers exactly one vault. A
certificate in a different vault is invisible to a source pointed elsewhere.
