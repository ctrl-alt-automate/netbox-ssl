# How-to: Bulk Import Certificates

Import many certificates at once from CSV, JSON, or concatenated PEM — useful for
initial inventory population, migrations from other systems, or scripted ingestion.

## When to use this

- Populating NetBox SSL for the first time with an existing inventory
- Migrating from a spreadsheet or another certificate manager via CSV export
- Scripted imports from internal tooling (CI, cron jobs, config management)

For a single certificate, use the [First Import tutorial](../tutorials/01-first-import.md).

## Bulk PEM import (concatenated)

If you have multiple PEM certificates in a single blob (e.g., a full chain or a
concatenated bundle), simply paste the whole blob into the single-cert import form.
Each `-----BEGIN CERTIFICATE-----` / `-----END CERTIFICATE-----` block is parsed
as a separate record.

## Bulk CSV/JSON import

The dedicated bulk import page takes metadata rows rather than PEM blobs — ideal
when you don't have the full PEM on hand or you're migrating from another system
that only exports metadata.

### Steps

1. Navigate to **Plugins → SSL Certificates → Bulk Import**
2. Paste CSV or JSON content, or upload a file (default cap: 5 MB)
3. The plugin auto-detects the format and validates every row
4. Review the preview table — rows with validation errors are flagged in red
5. Click **Confirm Import** to create the certificates

### CSV format

```csv
common_name,serial_number,issuer,valid_from,valid_to,fingerprint_sha256,algorithm,key_size,status,sans,tenant
example.com,01:23:45:67:89,CN=DigiCert CA,2024-01-01,2025-01-01,AA:BB:CC:DD:...,rsa,2048,active,example.com;www.example.com,Production
```

SANs are semicolon-separated in CSV because commas are the row delimiter.

### JSON format

```json
[
  {
    "common_name": "example.com",
    "serial_number": "01:23:45:67:89",
    "issuer": "CN=DigiCert CA",
    "valid_from": "2024-01-01",
    "valid_to": "2025-01-01",
    "fingerprint_sha256": "AA:BB:CC:DD:...",
    "algorithm": "rsa",
    "key_size": 2048,
    "status": "active",
    "sans": ["example.com", "www.example.com"]
  }
]
```

### Required fields

| Field | Description |
|-------|-------------|
| `common_name` | Certificate Common Name |
| `serial_number` | Serial number (hex with or without colons) |
| `issuer` | Issuer Distinguished Name |
| `valid_from` | Start date (ISO 8601: `YYYY-MM-DD`) |
| `valid_to` | End date (ISO 8601: `YYYY-MM-DD`) |
| `fingerprint_sha256` | SHA-256 fingerprint (hex with or without colons) |
| `algorithm` | `rsa`, `ecdsa`, `ed25519`, or `unknown` |

### Optional fields

| Field | Description |
|-------|-------------|
| `key_size` | Key size in bits |
| `status` | `active`, `expired`, `replaced`, `revoked`, `pending` (default: `active`) |
| `sans` | SANs — semicolon-separated in CSV, array in JSON |
| `tenant` | Tenant name or ID |
| `private_key_location` | Key storage location hint (e.g., `vault://path/to/key`) |
| `pem_content` | Full PEM content — if present, enables chain validation and algorithm auto-detection |
| `issuer_chain` | Chain of intermediate certificates |

!!! tip "Duplicate detection"
    Duplicates are detected using `serial_number` + `issuer`. Rows matching an
    existing certificate are rejected by default. Via the REST API you can set
    `on_duplicate: "skip"` to silently skip duplicates instead of erroring.

## DER and PKCS#7 file import (v0.9+)

If you have binary certificate files instead of PEM text:

- **DER** (`.der`, `.cer`): single binary certificate — the plugin converts to PEM
  on the fly during import.
- **PKCS#7** (`.p7b`, `.p7c`): bundle containing a certificate and its chain —
  the plugin extracts every certificate from the bundle as a separate record.

Use the `POST /api/plugins/netbox-ssl/certificates/import-file/` endpoint with
multipart file upload, or paste the file content into the bulk import page (it
auto-detects the format).

## Programmatic bulk import via API

For scripted ingestion from your CI or automation:

```bash
curl -X POST https://netbox.example/api/plugins/netbox-ssl/certificates/bulk-import/ \
  -H "Authorization: Token $NETBOX_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "format": "json",
    "data": [ { "common_name": "example.com", ... }, ... ],
    "on_duplicate": "skip"
  }'
```

Response includes per-row status (`created`, `skipped`, `error`) and total counts.

See the [API reference](../reference/api.md) for the full endpoint specification.

## Troubleshooting

!!! question "Some rows show \"invalid date format\""
    Dates must be ISO 8601 (`YYYY-MM-DD`). If your source uses a different format
    (e.g., `DD/MM/YYYY`), preprocess with `awk`/`sed` or a Python script before
    import.

!!! question "\"Duplicate\" errors on rows I expected to be new"
    Check that the `serial_number` is unique per issuer. Some CAs reuse serial
    numbers across sub-CAs; make sure `issuer` is specific enough (fully qualified DN).

!!! question "Bulk import rejected with \"batch too large\""
    The default limit is 100 per batch (set by `bulk_import_max_batch_size`).
    Split your import into smaller chunks, or increase the limit in plugin
    config if your NetBox has the capacity.
