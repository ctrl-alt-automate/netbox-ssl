# How-to: Import Certificates from URLs

Inventory certificates by pointing the plugin at a list of URLs. For each URL the
plugin opens a TLS connection, scrapes the certificate the server presents during
the handshake, and imports it — no need to export or download certificates by hand.

## When to use this

- Inventorying the certificates actually deployed across many internal services
- Building a source-of-truth from live endpoints rather than files
- Periodically confirming what a host is serving (re-scanning updates `last_seen_at`)

Only the **public** certificate is captured — a TLS handshake never exposes the
private key. For importing certificates you already hold as PEM/CSV, use
[Bulk Import](bulk-import.md) instead.

## Prerequisites

- The **Can run URL certificate import** permission (`netbox_ssl.run_urlimport`).
  Grant it under **Admin → Permissions**; it is off by default, even for users who
  can otherwise add certificates.
- Network reachability from the NetBox host to each target `host:port`.

## Steps

1. Navigate to **Plugins → SSL Certificates → Import from URLs (CSV)**.
2. Upload a `.csv` file or paste CSV rows. Optionally set a **default tenant**
   (applied to rows without their own `tenant` column).
3. Click **Parse & preview**. Rows are validated and shown in a preview table;
   malformed rows are flagged and skipped.
4. Click **Run scan & import**. The plugin connects to each URL, scrapes the
   presented certificate, and imports it.
5. The results table shows a per-row outcome: **Imported**, **Imported (untrusted
   chain)**, **Matched existing**, **Blocked (policy)**, **Unreachable**, or **Error**.

For large lists, prefer the **Certificate URL Scan** NetBox Script (see
[Scripts](../reference/scripts.md)), which runs the same import as a background
job so long scans don't block the request.

## CSV format

Only the `url` column is required. The header row must be present.

```csv
url,assigned_device,assigned_vm,assigned_service,tenant,verify_chain,sni
https://web.internal.example.com:8443,web01,,,acme,true,
https://api.internal.example.com,,vm-api-01,,acme,true,
https://legacy.internal.example.com:9443,,,,acme,false,legacy.example.com
```

| Column | Required | Format | Notes |
|--------|----------|--------|-------|
| `url` | ✅ | `https://host[:port]` or `host:port` | Port defaults to `443`. Only `https` is accepted. |
| `assigned_device` | — | Device name or ID | Creates an assignment after import. |
| `assigned_vm` | — | VM name or ID | |
| `assigned_service` | — | Service name or `device_id:service_name` | Service names are not globally unique — use the disambiguator. |
| `tenant` | — | Tenant name, slug, or ID | Falls back to the form's default tenant. |
| `verify_chain` | — | `true` / `false` (default `true`) | `false` imports self-signed / untrusted certs with a flag. |
| `sni` | — | Hostname | Override SNI if it differs from the URL host (HA / multi-cert hosts). |

**Limits:** 500 rows per upload, 10 MB file, 2048 characters per URL.

Certificates are de-duplicated on `serial_number` + `issuer` (the same rule as
Smart Paste). A URL whose certificate already exists counts as **Matched
existing** — no duplicate is created, and the existing record's `last_seen_at`
(and `discovered_via_url`, if empty) is refreshed.

## Self-signed and internal certificates

Internal estates often use self-signed or privately-issued certificates that
won't verify against the public trust store. Set `verify_chain=false` on those
rows to import them anyway — they are stored with an **untrusted chain** flag in
the results so you can tell them apart. Leave `verify_chain=true` (the default)
for anything that should chain to a public CA.

## Security model

The import enforces these rules:

- **HTTPS only.** Plain HTTP and STARTTLS are not supported.
- **No private keys.** A TLS handshake never carries the private key; the plugin
  additionally rejects any private-key material defensively.
- **SSRF protection.** Private and loopback addresses are **blocked by default**.
  Loopback (`127.0.0.0/8`, `::1`) is *always* blocked — it cannot be allowlisted.
- **DNS-rebinding defense.** The plugin validates the resolved IP and connects to
  that exact address; it never re-resolves the hostname between validation and
  connect.
- **Hard caps.** 5 s connect/handshake, 10 s total per URL, 64 KB chain size.

### Allowing internal ranges

To scan internal services on private IP ranges, a NetBox administrator must
allowlist their CIDRs in `configuration.py`:

```python
PLUGINS_CONFIG = {
    "netbox_ssl": {
        "url_import_private_cidr_allowlist": [
            "10.0.0.0/8",
            "192.168.0.0/16",
        ],
    },
}
```

A URL resolving to an address inside an allowlisted CIDR is permitted; everything
else private (and all loopback) stays blocked. See
[Configuration](../reference/configuration.md#url-certificate-import) for details.

## Troubleshooting

| Outcome | Meaning / fix |
|---------|---------------|
| **Blocked (policy)** | The URL resolved to a private/loopback address that isn't allowlisted. Add its CIDR to `url_import_private_cidr_allowlist` (loopback can never be allowlisted). |
| **Unreachable** | Connection refused, timed out, or the TLS handshake failed. Check reachability from the NetBox host and that the port serves TLS. |
| **Imported (untrusted chain)** | The certificate didn't verify against the trust store and the row had `verify_chain=false`. Expected for self-signed internal certs. |
| **Error** | The scraped certificate could not be parsed. Confirm the endpoint serves a standard X.509 certificate. |
