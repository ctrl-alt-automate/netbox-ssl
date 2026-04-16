# How-to: ARI Monitoring (RFC 9773)

ARI (ACME Renewal Information, [RFC 9773](https://datatracker.ietf.org/doc/rfc9773/))
lets a CA tell you when it would like you to renew a certificate — before the
certificate expires, and sometimes suddenly if there's a reason to rotate early
(e.g., a known issue with a CA sub-CA).

NetBox SSL can poll ARI endpoints for your ACME certificates and expose the
CA-recommended renewal window alongside the certificate itself.

## When to use this

- You operate Let's Encrypt, Google Trust Services, or Buypass certificates and
  want to honour CA-recommended renewal timing
- You want early warning if a CA decides to accelerate renewal (e.g., ahead of
  a planned root rotation)
- You want a second source of truth for renewal cadence beyond your own expiry
  thresholds

## Supported CAs

ARI is discovered automatically via the ACME directory URL:

| CA | ACME directory URL |
|----|---------------------|
| Let's Encrypt (prod) | `https://acme-v02.api.letsencrypt.org/directory` |
| Let's Encrypt (staging) | `https://acme-staging-v02.api.letsencrypt.org/directory` |
| Google Trust Services | `https://dv.acme-v02.api.pki.goog/directory` |

Other ACME providers may also support ARI — the plugin probes the `renewalInfo`
field in the directory response and gracefully skips CAs that don't advertise it.

## Step 1 — Mark a certificate as ACME-managed

Before ARI polling works, the certificate must have `is_acme: true` and a valid
`acme_server_url`. See the [ACME how-to](acme-auto-renewal.md) for the setup.

## Step 2 — Schedule the ARI poll script

Navigate to **Admin → Scripts → CertificateARIPoll** and schedule it daily.

The script:

- Finds all certificates with `is_acme=true` whose last ARI check is older than
  24 hours
- Computes the ARI CertID per RFC 9773: `base64url(AKI).base64url(serial)`
- GETs `{ari_endpoint}/{cert_id}` and honours `Retry-After` on 429 / 5xx
- Updates four fields on the certificate:
  - `ari_cert_id`
  - `ari_suggested_start`
  - `ari_suggested_end`
  - `ari_last_checked`
  - `ari_explanation_url` (if the CA included one)

## Step 3 — Interpret the renewal window

Each polled certificate now has a `suggested_start` and `suggested_end`
timestamp. The convention:

- Renew **after** `suggested_start`: CA recommends renewing in this window
- Renew **before** `suggested_end`: the window closes; beyond that the CA
  strongly encourages renewal
- If the window shifts unexpectedly (e.g., `suggested_start` jumps backward
  significantly), the plugin fires a `certificate.ari_window_shift` event — a
  possible signal that the CA is preparing to rotate early

Filter certs with `ari_window_active` in the list view (computed boolean — is
the current time between `suggested_start` and `suggested_end`?).

## Step 4 — Wire an Event Rule (optional)

Add an Event Rule matching `certificate.ari_window_active=true` to trigger your
automation: Slack message, Jira ticket, run your ACME client's renewal flag.

## Tuning

Plugin settings (in `PLUGINS_CONFIG`):

- `ari_poll_interval_hours`: minimum hours between polls per certificate
  (default: 24)
- `ari_respect_retry_after`: honour the CA's `Retry-After` header (default: `True`)
- `ari_max_retries`: max retries on 5xx (default: 3)

## Troubleshooting

!!! question "Script reports \"ARI not supported by CA\""
    The CA's ACME directory doesn't include `renewalInfo`. Nothing to do —
    ARI polling is a no-op for that cert.

!!! question "\"Retry-After\" delays stack up — polling is lagging\""
    If the CA is returning 429s consistently, your client is hitting rate
    limits. Lower the schedule cadence (e.g., every 48 hours instead of 24).

!!! question "Window active but my ACME client doesn't renew"
    NetBox SSL is passive — it tells you the CA recommends renewing, but it
    does not trigger your ACME client. Wire an Event Rule + webhook to trigger
    renewal, or poll the field from your automation.
