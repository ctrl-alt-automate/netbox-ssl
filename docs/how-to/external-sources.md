# How-to: Ingest Certificates from External Sources

The External Source framework (v0.8+) lets NetBox SSL synchronise certificates
from another system — Lemur, a custom certificate manager, or any JSON-over-HTTPS
endpoint — without manual CSV exports.

## When to use this

- You already run Lemur or a similar certificate manager and want NetBox SSL as
  the single-pane-of-glass
- You have an internal API that returns a list of certificates and want automated
  ingestion
- You want scheduled sync rather than ad-hoc imports

## Supported adapters

| Adapter | Source | Config |
|---------|--------|--------|
| `lemur` | Netflix Lemur | Lemur API URL + API key (via env var) |
| `generic_rest` | Any JSON REST endpoint | URL + optional auth header + field mapping |

Adapters live under `netbox_ssl/adapters/`. New adapters can be added by
subclassing `BaseAdapter`.

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

**`auth_credentials_reference` is removed in v2.0.0.** See [ROADMAP §8.2](https://github.com/ctrl-alt-automate/netbox-ssl/blob/main/project-requirement-document/ROADMAP.md#82-removal-of-auth_credentials_reference-field-on-externalsource).

## Step 1 — Create an ExternalSource record

Navigate to **Admin → NetBox SSL → External Sources → + Add**.

Fill in:

- **Name:** `Lemur Production`
- **Adapter type:** `lemur`
- **Endpoint URL:** `https://lemur.example.com/api/1`
- **Credentials:** use `env:LEMUR_API_KEY` (the value is resolved from the
  environment at runtime — the plaintext never lives in the database)
- **Enabled:** ✓
- **Sync schedule:** `daily` (or `hourly`, `weekly`, `manual`)

Save.

## Step 2 — Set the environment variable on your NetBox host

Set `LEMUR_API_KEY` in your NetBox environment. For systemd:

```ini
# /etc/systemd/system/netbox.service.d/override.conf
[Service]
Environment=LEMUR_API_KEY=your-api-key-here
```

Then:

```bash
sudo systemctl daemon-reload
sudo systemctl restart netbox netbox-rq
```

For Docker Compose, add to your `docker-compose.override.yml`:

```yaml
services:
  netbox:
    environment:
      LEMUR_API_KEY: your-api-key-here
```

!!! warning "Never put credentials in plaintext in the UI"
    The `credentials` field must always use the `env:VAR_NAME` pattern. Raw
    credentials will be rejected by validation. The pattern ensures secrets
    live in your secret manager, not the NetBox database.

## Step 3 — Run a manual sync

From the External Source detail page, click **Run Sync Now**.

The sync engine runs four phases in order:

1. **FETCH** — call the adapter to retrieve the current certificate list from
   the external system
2. **DIFF** — compare against existing NetBox SSL records (match on
   `serial_number + issuer`); compute: new, updated, removed
3. **APPLY** — inside a single transaction: create new records, update changed
   ones (without losing assignments), mark removed ones appropriately
4. **LOG** — write an `ExternalSourceSyncLog` entry with counts and duration

Check the result in the **Sync Logs** tab of the source's detail page.

## Step 4 — Enable scheduled sync

Schedule the `ExternalSourceSync` NetBox Script (Admin → Scripts) with your
desired cadence. It picks up every enabled source whose schedule is due.

## Security guarantees

The framework enforces several controls by design:

- **HTTPS-only** — plain HTTP URLs are rejected by validation
- **Private-IP blocking** — URLs resolving to RFC 1918, loopback, or link-local
  addresses are rejected (SSRF prevention)
- **No redirect following** — adapters set `allow_redirects=False`
- **Transaction boundaries** — every sync applies changes atomically; a failure
  rolls back
- **Streaming response cap** — oversized responses are truncated to prevent
  memory exhaustion
- **Private-key guard on PEM** — even if the upstream source returns private
  key content, the sync engine refuses to write it

## Troubleshooting

!!! question "Sync fails with \"credential could not be resolved\""
    The `env:VAR_NAME` variable is not set in the NetBox process environment.
    Check your systemd service override or Docker env, and restart NetBox.

!!! question "Sync fails with \"URL validation failed\""
    The endpoint URL points at a disallowed target (HTTP, private IP, localhost).
    Use HTTPS and a publicly resolvable hostname. For a lab, add an `/etc/hosts`
    entry pointing at a public DNS name.

!!! question "New certs appear but existing ones don't update"
    Check the adapter's match logic. The sync engine uses
    `serial_number + issuer` as the identity key. If your source returns
    slightly different issuer strings on each call, every cert will look "new".

!!! question "I want to write a new adapter"
    Subclass `netbox_ssl.adapters.base.BaseAdapter` and implement `fetch()` and
    `parse()`. See `netbox_ssl/adapters/generic_rest.py` for a reference
    implementation.
