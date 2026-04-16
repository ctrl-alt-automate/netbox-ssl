# Tutorial 1: Your First Certificate Import

!!! note "Audience and outcome"
    **You are:** a NetBox admin who has just installed NetBox SSL (or is evaluating it).
    **You will:** import your first certificate, assign it to a Service, and see it
    appear on the expiry dashboard. **Time:** ~10 minutes.

## Prerequisites

- NetBox 4.4.0 or later with NetBox SSL 1.0 installed ([installation guide](../operations/installation.md))
- A PEM-encoded certificate on your clipboard (any public certificate — your company's
  production cert, a Let's Encrypt cert from one of your test hosts, anything)
- Admin or `add_certificate` permission

## Step 1 — Open the import page

Navigate to **Plugins → SSL Certificates → Certificates**. Click the **Import** button
in the top right.

You should land on a page with a single large text area labelled "PEM content".

## Step 2 — Paste your PEM

Paste the certificate text into the text area. Everything from
`-----BEGIN CERTIFICATE-----` through `-----END CERTIFICATE-----` is expected.

You can paste multiple certificates in one go if you have the full chain — NetBox SSL
will parse them all and let you save each as a separate record.

!!! warning "Private keys are rejected by design"
    NetBox SSL is a public-metadata inventory. If your PEM contains any private key
    header, the import will be refused. Private key storage belongs in a dedicated
    secrets manager, not in NetBox.

## Step 3 — Review and save

Once you paste, the plugin parses the content using the Python `cryptography` library
and shows a preview with:

- Common Name (CN) and any Subject Alternative Names (SANs)
- Validity period (`valid_from`, `valid_to`)
- Issuer (the CA that signed the certificate)
- Key algorithm (RSA, ECDSA, Ed25519) and key size
- SHA-256 fingerprint

Review the preview. If it looks right, click **Save**. Your certificate now has an
internal NetBox ID and shows up in the certificates list.

## Step 4 — Assign the certificate to a Service

A certificate without assignments is just metadata — the value comes from linking it
to the infrastructure that uses it.

From the certificate detail page, scroll to the **Assignments** tab and click the
**+ Add assignment** button.

Pick one of these target types:

- **Service** — an application listening on a port (e.g., `https` on a web server)
- **Device** — a physical appliance presenting a certificate (e.g., a firewall)
- **Virtual Machine** — a VM running a TLS-terminating service

Select the target from the dropdown, optionally add a note (e.g., "primary frontend"),
and save. The certificate now shows up under that target's certificates.

## Step 5 — See it on the expiry dashboard

Navigate to **Plugins → SSL Certificates → Analytics**.

Your new certificate appears in:

- The **expiry forecast** chart (bucketed by days-to-expiry)
- The **algorithm distribution** chart
- The **CA distribution** chart

If your certificate expires within the configured thresholds
(`expiry_warning_days` / `expiry_critical_days`), it also shows up on the home
dashboard widget.

## What just happened

Behind the scenes:

1. **Smart Paste** parsed your PEM using the `cryptography` library — a single code path
   that extracts every supported field.
2. A `Certificate` record was created with public metadata only. No part of the PEM
   content is stored as-is; fields are normalised into the database schema.
3. A `CertificateAssignment` record linked the certificate to your target (via a
   `GenericForeignKey`, which is how NetBox SSL can point at Services, Devices, or
   VMs with a single table).
4. Every change — creation, assignment, status — was logged in NetBox's changelog
   with a snapshot of the certificate state. Full audit trail, no extra config.

## Troubleshooting

!!! question "Import fails with \"private key detected\""
    Your PEM contains a private key header. Remove all `BEGIN PRIVATE KEY` /
    `BEGIN RSA PRIVATE KEY` / `BEGIN EC PRIVATE KEY` blocks. Only the certificate
    section is accepted.

!!! question "Import says \"duplicate certificate\""
    A certificate with the same serial number and issuer already exists. Search
    for the serial number in the certificates list to find the existing record.

!!! question "I don't see the Analytics menu item"
    Check your permissions — viewing analytics requires `view_certificate`. See
    the [permissions reference](../reference/permissions.md).

!!! question "My certificate shows up with algorithm \"Unknown\""
    The plugin detects RSA, ECDSA, and Ed25519. Anything else (very rare) is
    reported as Unknown. File an issue with a redacted copy of the certificate
    if you expected detection.

## Next steps

- [Tutorial 2 — Renewal Workflow](02-renewal-workflow.md) — what to do when this
  certificate approaches expiry
- [How-to: Bulk Import](../how-to/bulk-import.md) — import many certificates at
  once from CSV or JSON
- [How-to: ACME Auto-Renewal](../how-to/acme-auto-renewal.md) — mark a certificate
  as ACME-managed for automated renewal detection
