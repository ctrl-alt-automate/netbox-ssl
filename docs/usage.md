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

## Keyboard Shortcuts

NetBox SSL inherits NetBox's keyboard shortcuts:
- `/` — Focus search
- `?` — Show keyboard help
- `j`/`k` — Navigate list items

---

**Next:** [API](api.md) — Learn about the REST API and GraphQL queries
