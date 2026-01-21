# Usage Guide

This guide covers the main workflows for using the NetBox SSL Plugin.

## Certificate Management

### Importing Certificates

The Smart Paste feature makes importing certificates effortless:

1. Navigate to **Plugins > SSL Certificates > Certificates**
2. Click the **Import** button
3. Paste your certificate in PEM format
4. Click **Import Certificate**

<p align="center">
  <img src="images/certificate-import.png" alt="Certificate Import" width="700">
</p>

The plugin automatically extracts:
- Common Name (CN) and Subject Alternative Names (SANs)
- Validity period (valid_from, valid_to)
- Issuer information and certificate chain
- Serial number and SHA256 fingerprint
- Key algorithm (RSA, ECDSA, Ed25519) and size

> **Tip:** You can paste the full chain (certificate + intermediates + root) in one go. The plugin will parse them all.

> **Security:** Private keys are automatically rejected. If your PEM contains `-----BEGIN PRIVATE KEY-----`, the import will fail with a security warning.

### Duplicate Detection

The plugin prevents duplicate imports by checking:
- **Serial number + Issuer combination** — Must be unique

If you try to import a certificate that already exists, you'll see an error message with a link to the existing certificate.

---

## Janus Renewal Workflow

The Janus workflow is the heart of NetBox SSL. When you import a certificate with a Common Name matching an existing certificate, the plugin detects this as a potential renewal.

### How It Works

1. **Import the new certificate** as usual
2. **Plugin detects the match** and shows a comparison dialog:

| | Old Certificate | New Certificate |
|---|---|---|
| Valid To | 2024-01-15 | 2025-01-15 |
| Serial | 01:23:45:... | 67:89:AB:... |
| Assignments | 3 services | — |

3. **Choose your action:**

   **Renew & Transfer** (recommended)
   - Creates the new certificate
   - Copies all assignments from old → new
   - Sets old certificate status to "Replaced"
   - Links old and new for audit trail

   **Create as New**
   - Creates a separate certificate entry
   - No assignments are copied
   - Old certificate remains unchanged

### Why "Janus"?

Janus was the Roman god of transitions, doorways, and new beginnings. The renewal workflow embodies this:
- The old certificate **ends** its service
- The new certificate **begins** its service
- Assignments pass through the **doorway** seamlessly

---

## Certificate Assignments

Assignments link certificates to your infrastructure. This creates a clear picture of certificate dependencies.

<p align="center">
  <img src="images/assignments-list.png" alt="Certificate Assignments" width="700">
</p>

### Assignment Types

| Type | Best For | Example |
|------|----------|---------|
| **Service** (recommended) | Port-specific deployments | HTTPS (443) on web-server-01 |
| **Device** | Device-wide certificates | Load balancer with termination |
| **Virtual Machine** | VM-level certificates | Kubernetes ingress controller |

> **Recommendation:** Use Service assignments whenever possible. They provide port-level granularity, so you can track different certificates on different ports of the same device.

### Creating an Assignment

1. Navigate to a certificate's detail page
2. In the **Assignments** panel, click **+ Add**
3. Select the assignment type (Service, Device, or VM)
4. Choose the target object
5. Check **Primary** if this is the main certificate
6. Add optional notes
7. Click **Save**

### Viewing Assignments

Assignments appear in multiple places:
- **Certificate detail page** — Shows all objects using this certificate
- **Device/VM/Service detail pages** — Shows certificates panel
- **Assignments list** — Global view at *Plugins > SSL Certificates > Assignments*

---

## Certificate Status

Certificates have lifecycle statuses:

| Status | Description |
|--------|-------------|
| **Active** | Certificate is valid and in use |
| **Expired** | Validity period has ended |
| **Replaced** | Superseded via Janus renewal |
| **Revoked** | Manually marked as revoked |
| **Pending** | Awaiting deployment |

---

## Expiry Monitoring

### Dashboard Widget

Add the SSL Certificate Status widget to your NetBox dashboard:

1. Go to the NetBox dashboard
2. Scroll down and click **+ Add Widget**
3. Select **SSL Certificate Status**
4. Position and save

<p align="center">
  <img src="images/dashboard-widget.png" alt="Dashboard Widget" width="400">
</p>

The widget shows:
- **Healthy** — All certificates OK
- **Critical** — Expiring within 14 days
- **Warning** — Expiring within 30 days
- **Orphan** — Certificates without assignments

### Filtering by Expiry

In the certificate list view:
- Use the **Status** filter for expired certificates
- Sort by **Valid To** to see upcoming expirations
- Use API filters like `valid_to__lt=2024-06-01` for custom queries

---

## Multi-Tenancy

### Tenant Assignment

Certificates can be scoped to tenants for organizational isolation:

1. When creating/importing a certificate, select a **Tenant**
2. The certificate is now associated with that tenant

### Tenant Validation

When assigning a tenanted certificate:
- Target object must have the **same tenant** or **no tenant**
- Cross-tenant assignments are rejected

This prevents accidentally linking Production certificates to Development infrastructure.

---

## Bulk Operations

### Bulk Import

Import multiple certificates at once:
1. Concatenate your PEM certificates in a single text block
2. Paste into the import form
3. Each certificate is imported separately

### Bulk Edit

1. Select multiple certificates in the list view (checkboxes)
2. Click **Edit Selected**
3. Apply common settings (tenant, tags, status)
4. Save

---

## Certificate Signing Requests (CSRs)

Track pending certificate requests before they become issued certificates.

### Importing a CSR

1. Navigate to **Plugins > SSL Certificates > CSRs**
2. Click the **Import** button
3. Paste your CSR in PEM format
4. Click **Import CSR**

The plugin extracts:
- Common Name (CN) and subject fields (O, OU, L, ST, C)
- Subject Alternative Names (SANs)
- Key algorithm and size
- SHA256 fingerprint for duplicate detection

### CSR Workflow

| Status | Description |
|--------|-------------|
| **Pending** | CSR awaiting approval |
| **Approved** | Ready to submit to CA |
| **Rejected** | CSR was rejected |
| **Issued** | Certificate has been issued |
| **Expired** | CSR expired without issuance |

### Linking CSR to Certificate

When a certificate is issued from a CSR:
1. Import the new certificate
2. Edit the CSR record
3. Set **Resulting Certificate** to link them
4. Update status to **Issued**

This creates an audit trail from request to issued certificate.

---

## Certificate Authorities

Track which CAs issue your certificates for better visibility and compliance.

### Adding a Certificate Authority

1. Navigate to **Plugins > SSL Certificates > Certificate Authorities**
2. Click **+ Add**
3. Fill in the CA details:
   - **Name** — Unique identifier (e.g., "DigiCert EV")
   - **Type** — Public, Internal, or ACME
   - **Issuer Pattern** — For auto-detection (e.g., "digicert")
   - **Website/Portal URLs** — For quick access
   - **Is Approved** — Whether this CA is approved for use

### CA Types

| Type | Description | Example |
|------|-------------|---------|
| **Public** | Commercial CA | DigiCert, Sectigo, GlobalSign |
| **Internal** | Organization's private CA | Active Directory CS, EJBCA |
| **ACME** | Automated CA | Let's Encrypt, ZeroSSL |

### Auto-Detection

When importing certificates, the plugin can automatically link them to a CA:

1. Set an **Issuer Pattern** on the CA (e.g., "let's encrypt")
2. Import a certificate with matching issuer
3. The `issuing_ca` field is automatically populated

> **Tip:** Use lowercase patterns for case-insensitive matching.

### Approved CAs

Use the **Is Approved** flag to track which CAs are sanctioned for use:
- Filter certificates by `issuing_ca__is_approved=false` to find non-compliant certificates
- Create compliance policies to enforce approved CA usage

---

## Compliance Policies

Define and enforce certificate standards across your organization.

### Creating a Policy

1. Navigate to **Plugins > SSL Certificates > Compliance Policies**
2. Click **+ Add**
3. Configure the policy:
   - **Name** — Descriptive name (e.g., "Minimum 2048-bit keys")
   - **Policy Type** — What to check
   - **Severity** — Critical, Warning, or Info
   - **Parameters** — Type-specific settings (JSON)
   - **Tenant** — Scope to specific tenant (optional)

### Policy Types

| Type | Description | Parameters |
|------|-------------|------------|
| `min_key_size` | Minimum key size | `{"min_bits": 2048}` |
| `max_validity_days` | Maximum validity period | `{"max_days": 397}` |
| `algorithm_allowed` | Allowed algorithms | `{"algorithms": ["rsa", "ecdsa"]}` |
| `algorithm_forbidden` | Forbidden algorithms | `{"algorithms": ["dsa"]}` |
| `expiry_warning` | Expiry threshold | `{"warning_days": 30}` |
| `chain_required` | Chain must be present | `{}` |
| `san_required` | SANs required | `{"min_count": 1}` |
| `wildcard_forbidden` | No wildcards allowed | `{}` |
| `issuer_allowed` | Allowed issuers | `{"issuers": ["DigiCert"]}` |
| `issuer_forbidden` | Forbidden issuers | `{"issuers": ["Unknown CA"]}` |

### Running Compliance Checks

**Single Certificate:**
1. Go to certificate detail page
2. Click **Run Compliance Check** (or use API)

**Bulk Check via API:**
```bash
curl -X POST \
  -H "Authorization: Token YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"certificate_ids": [1, 2, 3]}' \
  http://localhost:8000/api/plugins/netbox-ssl/certificates/bulk-compliance-check/
```

### Viewing Results

- **Certificate detail page** — Shows compliance status
- **Compliance Checks list** — All check results at *Plugins > SSL Certificates > Compliance Checks*
- **Filter by result** — `result=fail` to find violations

---

## Chain Validation

Verify certificate chains are complete and valid.

### What Chain Validation Checks

1. **Chain Completeness** — All intermediate certificates present
2. **Signature Verification** — Each certificate signed by the next
3. **Validity Periods** — All certificates in chain are valid
4. **Trust Path** — Chain leads to a trusted root

### Chain Status

| Status | Description |
|--------|-------------|
| **Unknown** | Not yet validated |
| **Valid** | Chain is complete and valid |
| **Invalid** | Validation failed (see message) |
| **Self-Signed** | Certificate is self-signed |
| **No Chain** | Chain required but not provided |

### Running Validation

**Single Certificate:**
```bash
curl -X POST \
  -H "Authorization: Token YOUR_TOKEN" \
  http://localhost:8000/api/plugins/netbox-ssl/certificates/1/validate-chain/
```

**Bulk Validation:**
```bash
curl -X POST \
  -H "Authorization: Token YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"certificate_ids": [1, 2, 3]}' \
  http://localhost:8000/api/plugins/netbox-ssl/certificates/bulk-validate-chain/
```

### Importing with Chain

When importing a certificate, include the full chain:

```
-----BEGIN CERTIFICATE-----
(your certificate)
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
(intermediate certificate)
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
(root certificate - optional)
-----END CERTIFICATE-----
```

The plugin stores intermediates in the `issuer_chain` field.

---

## Data Export

Export certificates in various formats for reporting and integration.

### Export Formats

| Format | Description | Use Case |
|--------|-------------|----------|
| **JSON** | Full data export | API integration, backup |
| **CSV** | Spreadsheet format | Excel, reporting |
| **PEM** | Certificate format | Deployment, verification |

### Exporting via UI

1. Navigate to certificate list
2. Select certificates (checkboxes)
3. Click **Export** dropdown
4. Choose format

### Exporting via API

**Single Certificate:**
```bash
# JSON (default)
curl -H "Authorization: Token YOUR_TOKEN" \
  "http://localhost:8000/api/plugins/netbox-ssl/certificates/1/export/"

# CSV
curl -H "Authorization: Token YOUR_TOKEN" \
  "http://localhost:8000/api/plugins/netbox-ssl/certificates/1/export/?format=csv"

# PEM
curl -H "Authorization: Token YOUR_TOKEN" \
  "http://localhost:8000/api/plugins/netbox-ssl/certificates/1/export/?format=pem"
```

**Bulk Export:**
```bash
# Export all active certificates as CSV
curl -H "Authorization: Token YOUR_TOKEN" \
  "http://localhost:8000/api/plugins/netbox-ssl/certificates/export/?status=active&format=csv"

# Export with filters
curl -X POST \
  -H "Authorization: Token YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"certificate_ids": [1, 2, 3], "format": "json"}' \
  "http://localhost:8000/api/plugins/netbox-ssl/certificates/export/"
```

### Export Fields (CSV/JSON)

- Common name, serial number, fingerprint
- Issuer and issuing CA
- Validity dates and days remaining
- Algorithm, key size
- Status and tenant
- SANs (comma-separated in CSV)
- Chain validation status
- Assignment count

---

## Keyboard Shortcuts

NetBox SSL inherits NetBox's keyboard shortcuts:
- `/` — Focus search
- `?` — Show keyboard help
- `j`/`k` — Navigate list items

---

**Next:** [API](api.md) — Learn about the REST API and GraphQL queries
