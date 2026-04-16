# How-to: Track ACME-Managed Certificates

ACME-issued certificates (Let's Encrypt, ZeroSSL, Buypass, Google Trust Services,
Buypass) renew on short cycles, typically every 60-90 days. This guide shows how
to mark a certificate as ACME-managed so NetBox SSL tracks provider, challenge
type, and auto-renewal status alongside the certificate itself.

## When to use this

- You issue certificates via Certbot, acme.sh, Caddy, Traefik, cert-manager, etc.
- You want visibility into which certificates are auto-renewed vs. manual
- You want to monitor ACME auto-renewal health from a single pane

!!! note "NetBox SSL does not issue certificates"
    This plugin is a passive inventory — it does not run ACME itself. You continue
    to issue certificates with your existing ACME client. NetBox SSL tracks the
    metadata.

## Auto-detection on import

When you import a certificate via Smart Paste or API, the plugin inspects the
issuer field. If the issuer matches a known ACME provider pattern (e.g.,
`Let's Encrypt`, `R3`, `ZeroSSL RSA Domain Secure Site CA`, etc.), two fields
are set automatically:

- `is_acme: true`
- `acme_provider: "Let's Encrypt"` (or the matching provider name)

No manual intervention needed for auto-detected cases.

## Manually marking a certificate as ACME

For non-standard or self-managed ACME providers:

1. Open the certificate detail page
2. Click **Edit**
3. Tick **Is ACME** and fill in:
   - **ACME Provider:** free-text name
   - **Account Email:** the email associated with your ACME account
   - **Challenge Type:** `HTTP-01`, `DNS-01`, or `TLS-ALPN-01`
   - **Server URL:** the ACME directory URL (e.g.,
     `https://acme-v02.api.letsencrypt.org/directory`)
   - **Auto-Renewal:** tick if your tooling auto-renews
   - **Renewal Days:** days before `valid_to` at which auto-renewal fires
4. Save

## ACME fields reference

| Field | Description |
|-------|-------------|
| `is_acme` | Boolean — is this an ACME-issued certificate? |
| `acme_provider` | Provider name (e.g., `Let's Encrypt`) |
| `acme_account_email` | Account email address |
| `acme_challenge_type` | `HTTP-01`, `DNS-01`, or `TLS-ALPN-01` |
| `acme_server_url` | ACME directory URL |
| `acme_auto_renewal` | Boolean — auto-renewal configured upstream? |
| `acme_last_renewed` | When the certificate was last renewed via ACME |
| `acme_renewal_days` | Days before `valid_to` that renewal is attempted |

## Filtering ACME certificates

In the certificate list view, a filter panel provides:

- **Is ACME** — show only ACME certificates (or only non-ACME)
- **ACME Provider** — filter by provider
- **Auto-Renewal** — find certificates without auto-renewal configured (a common
  gap in inventories)

## Renewal status

For ACME certificates, the plugin computes a `renewal_status`:

| Status | Description |
|--------|-------------|
| `OK` | Certificate valid, not yet in the renewal window |
| `Due` | Within the renewal window (`acme_renewal_days` days before `valid_to`) |
| `Expired` | Past `valid_to` — your ACME client failed to renew |
| `Manual` | Auto-renewal not configured |

`Due` and `Expired` statuses are good candidates for alerting — an Event Rule
matching on `renewal_status == "Expired"` catches silent auto-renewal failures.

## Going further

- [ARI monitoring](ari-monitoring.md) — combine ACME tracking with RFC 9773
  Renewal Information for CA-recommended renewal windows
- [Expiry Monitoring tutorial](../tutorials/03-expiry-monitoring.md) — set up
  alerting for `Due` and `Expired` certificates
- [API reference](../reference/api.md) — programmatic ACME field updates
