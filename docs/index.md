# NetBox SSL Plugin

<p align="center">
  <strong>Project Janus</strong> — Your Single Source of Truth for TLS/SSL certificate management
</p>

<p align="center">
  <em>Named after Janus, the Roman god of doorways and transitions — because every certificate guards a doorway, and every renewal is a transition.</em>
</p>

---

Welcome to the **NetBox SSL Plugin** documentation!

Track certificates, monitor expiration dates, and never lose sight of where your certificates are deployed.

<p align="center">
  <img src="images/certificate-list.png" alt="NetBox SSL Certificate List" width="800">
</p>

## Quick Navigation

| Getting Started | Daily Usage | Reference |
|:---------------:|:-----------:|:---------:|
| [Installation](installation.md) | [Usage Guide](usage.md) | [API](api.md) |
| [Configuration](configuration.md) | [Janus Renewal](usage.md#janus-renewal-workflow) | [Data Models](data-models.md) |
| | [CSR Management](usage.md#certificate-signing-requests-csrs) | |
| | [Compliance](usage.md#compliance-policies) | |
| | [Scripts](scripts.md) | |

## What Can You Do?

### Track All Your Certificates

Import certificates with a simple paste — the plugin extracts all X.509 attributes automatically. No more spreadsheets or forgotten certificates.

<p align="center">
  <img src="images/certificate-detail.png" alt="Certificate Detail View" width="700">
</p>

### Seamless Renewals with Janus Workflow

When you renew a certificate, the Janus workflow automatically transfers all assignments from the old certificate to the new one and archives the old certificate. No manual updates needed.

### Know Where Every Certificate Lives

Assign certificates to Services, Devices, or Virtual Machines. See at a glance which infrastructure depends on which certificate.

<p align="center">
  <img src="images/assignments-list.png" alt="Certificate Assignments" width="700">
</p>

### Never Miss an Expiration

The dashboard widget shows certificates that need attention:
- **Critical** — Less than 14 days remaining
- **Warning** — Less than 30 days remaining
- **Orphan** — Not assigned to any infrastructure

<p align="center">
  <img src="images/dashboard-widget.png" alt="Dashboard Widget" width="400">
</p>

### Track Certificate Requests

Manage the full certificate lifecycle with CSR tracking:
- Import and parse Certificate Signing Requests
- Track approval status from request to issuance
- Link issued certificates back to their CSRs

### Manage Certificate Authorities

Keep track of which CAs issue your certificates:
- Register public, internal, and ACME CAs
- Auto-detect CA from certificate issuer field
- Track approved vs. non-approved CAs

### Enforce Compliance Policies

Define and enforce certificate standards:
- Minimum key sizes and allowed algorithms
- Maximum validity periods
- Required SANs and forbidden wildcards
- Approved issuer restrictions

### Validate Certificate Chains

Verify your certificate chains are complete:
- Check chain completeness and signatures
- Identify self-signed and missing intermediates
- Bulk validate across your inventory

### Export Your Data

Export certificates for reporting and integration:
- JSON for API integration
- CSV for spreadsheets and reporting
- PEM for deployment verification

## Security Philosophy

NetBox SSL is designed with **Passive Administration** in mind:

- **Inventory, not deployment** — The plugin tracks certificates; it doesn't deploy them
- **No private keys** — Private keys are never stored in the database
- **Key location hints** — Document where keys are stored (Vault, HSM, etc.)
- **Private key rejection** — PEM input containing private keys is automatically rejected

## Compatibility

| NetBox Version | Plugin Version | Status |
|:--------------:|:--------------:|:------:|
| 4.5.x          | 0.1.x          | Primary |
| 4.4.x          | 0.1.x          | Supported |
| 4.3.x and older| —              | Unsupported |

## Documentation

- **[Installation](installation.md)** — Get the plugin installed and configured
- **[Configuration](configuration.md)** — Customize thresholds, permissions, and widgets
- **[Usage](usage.md)** — Learn the import and renewal workflows
- **[Scripts](scripts.md)** — Expiry notifications and automation
- **[API](api.md)** — REST API and GraphQL reference
- **[Data Models](data-models.md)** — Database schema and relationships

## Getting Help

- **[GitHub Issues](https://github.com/ctrl-alt-automate/netbox-ssl/issues)** — Report bugs or request features
- **[NetBox Slack](https://netdev.chat/)** — Community chat (#netbox channel)
