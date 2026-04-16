# Security Model

This document explains **why** NetBox SSL is built the way it is — the trust
boundaries, the design invariants, and the layered defenses. For the
implementation-side checklist, see
[security review](../development/security-review.md).

## Design invariant 1: No private keys, ever

NetBox SSL is a **public-metadata** inventory. The database never stores
private keys. The parser actively rejects any PEM that contains one.

This is not a convenience decision. It's a **blast-radius** decision.

### Why this matters

- The plugin runs in the same NetBox process as everything else NetBox does.
  A bug in the plugin could expose data to every admin who has access to
  NetBox.
- Private keys are the most sensitive data in a TLS deployment — compromise
  means traffic decryption, impersonation, certificate forgery.
- Secrets management is a **specialist domain**: HashiCorp Vault, AWS Secrets
  Manager, Azure Key Vault, and internal systems are built for this. They have
  dedicated access control, audit logging, and key rotation.

By refusing private keys at the front door, the plugin keeps its trust boundary
small: an attacker with full read access to the NetBox SSL database cannot use
the contents to decrypt anything. Only metadata about certificates — which is
already visible to anyone who can connect to your services.

### What we track instead

The plugin stores a `private_key_location` field — a free-text breadcrumb
pointing at the secrets manager (e.g., `vault://secret/tls/api.example.com`,
`aws-sm:production/tls/api-cert`). This lets operators answer "where is the
key for this certificate?" without putting the key in NetBox.

## Design invariant 2: Passive administration

NetBox SSL **monitors and inventories** certificates. It does not:

- Deploy certificates to endpoints
- Run ACME clients (Certbot, acme.sh, Caddy, etc.)
- Rotate certificates actively
- Push configuration changes to devices

This is a deliberate scope decision. "Active" certificate management is a
different problem domain with different failure modes:

- Active tools need elevated access to production systems (SSH, Kubernetes
  admin, CI/CD secrets, CA API keys)
- Their failure modes include incorrect deployments, renewal race conditions,
  and downtime
- A plugin that runs in a NetBox process is not the right trust boundary for
  that work

Passive administration keeps NetBox SSL's privileges minimal: read access to
NetBox's own data, outbound HTTPS for ACME ARI and external source sync, and
nothing else. No SSH keys, no kubeconfig, no CA API credentials.

## Layered defense

For data that **does** cross the trust boundary — PEM inputs, external source
URLs, user-provided credentials — the plugin uses multiple independent layers:

### Input validation (outermost)

- **Size caps**: `max_length=65536` on PEM form fields, plus a size guard in
  the parser itself. Prevents request amplification and memory exhaustion.
- **Private-key regex**: broad pattern `-----BEGIN\s+(?:\w+\s+)*PRIVATE\s+KEY-----`
  catches RSA, EC, generic PRIVATE KEY, and variations. Rejection is immediate,
  before any parsing.
- **Parser boundaries**: the parser uses the `cryptography` library, which is
  hardened against malformed input. A parse error becomes a 400 response with
  a generic message.

### SSRF protection (outbound)

External sources and ARI polling make HTTPS calls. Shared `utils/url_validation.py`
enforces:

- HTTPS-only (plain HTTP is rejected by scheme check)
- DNS resolution: every returned IP is checked against private/loopback ranges
- Literal IP blocking: RFC 1918, 127.0.0.0/8, ::1, link-local, IPv6 ULA
- `allow_redirects=False`: redirects could send requests to different hosts
- Streaming response cap: prevents multi-GB download attempts

### Authorisation

Every request path enforces NetBox's permission model:

- Custom views use `LoginRequiredMixin` as first base class
- Every queryset uses `.restrict(request.user, "view"/"change")` — this
  enforces NetBox's ObjectPermission scoping
- Every `@action` endpoint checks `has_perm()` before writes
- Granular custom permissions (`import_certificate`, `renew_certificate`,
  `bulk_operations`, `manage_compliance`) allow fine-grained RBAC

### Error sanitisation

- Database exceptions never propagate to API responses. The handler logs
  `str(e)` internally, returns a generic message to the client
- GraphQL types use explicit field lists, never `fields="__all__"` — avoids
  accidentally exposing new sensitive fields on model changes

### Export hardening

CSV and JSON exports go through a dedicated exporter:

- `ALLOWED_FIELDS` frozenset — arbitrary `getattr()` on user-controlled field
  names is prevented
- CSV value sanitisation — prefixes `=`, `+`, `-`, `@`, `\t`, `\r` values to
  prevent CSV formula injection in spreadsheet consumers

## Credential handling

External source credentials are first-class security-sensitive data:

- Serializer field is `write_only=True` — never returned in API responses
- Field is omitted entirely from GraphQL
- Value must match `env:VAR_NAME` pattern at save time — raw credentials are
  rejected by validation
- Resolution happens at runtime via `credential_resolver.py`: looks up
  `VAR_NAME` in `os.environ`, raises `CredentialResolveError` on miss
- That specific exception is caught **before** any generic `ValueError`
  handler — ensures the error surfaces as "credential could not be resolved"
  rather than a generic server error

The net effect: credentials never live in the NetBox database, never appear
in logs, and never cross the API surface. They live where secrets belong —
in your secrets manager, referenced by name.

## Layered defense: why it matters

No single layer is sufficient. The `cryptography` library is hardened; we
still guard the parser with a size cap. Django's ORM prevents SQL injection;
we still use `.restrict()` to enforce row-level permissions. GitHub's secret
scanning helps; we still require `env:` references. Bandit catches common
patterns; we still run pip-audit for CVEs.

Security holds when multiple controls overlap. Remove any one and the others
still work.

## What's out of scope

- **Malicious admins.** A NetBox superuser can query the database directly.
  The plugin assumes trust in authenticated admins.
- **Compromised NetBox hosts.** If the NetBox server is compromised, the
  plugin's data is compromised. The plugin doesn't protect against host-level
  attacks.
- **Plaintext in upstream systems.** If your external source (Lemur, etc.)
  returns private keys, the plugin's guard stops them from landing in the
  NetBox database. But the upstream system still has them — secure it
  separately.

See [security review](../development/security-review.md) for the implementation
checklist and [architecture](architecture.md) for how the layers fit together.
