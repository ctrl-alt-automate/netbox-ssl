# NetBox SSL Plugin

**Project Janus** - A NetBox plugin for TLS/SSL certificate management.

> *Janus, the Roman god of beginnings and endings, doorways and passages.*
> This plugin focuses on certificate lifecycle (renewal) and binding to services (ports/doorways).

## Overview

NetBox SSL provides a "Single Source of Truth" for TLS/SSL certificates in your infrastructure. The philosophy is **Passive Administration** - the plugin serves as an inventory and monitoring system, not an active deployment tool.

### Key Features

- **Smart Paste Import** - Paste PEM certificates, automatic X.509 parsing
- **Janus Renewal Workflow** - Replace & Archive with automatic assignment transfer
- **Certificate Assignments** - Link certificates to Services, Devices, and VMs
- **Expiry Dashboard** - Widget with Critical/Warning/Info categorization
- **Multi-Tenancy** - Optional tenant isolation for certificates
- **Full API** - REST API and GraphQL support

### Security

- **No private key storage** - Private keys are never stored in the database
- **Private key rejection** - PEM input containing private keys is rejected
- **Key location hints** - Optional field for documenting key storage location (e.g., Vault path)

## Compatibility

| NetBox Version | Plugin Version | Status |
|----------------|----------------|--------|
| 4.5.x          | 0.1.x          | Primary |
| 4.4.x          | 0.1.x          | Supported |
| 4.3.x and older| -              | Unsupported |

## Installation

### Via pip

```bash
pip install netbox-ssl
```

### Via source

```bash
cd /opt/netbox/netbox
git clone https://github.com/your-org/netbox-ssl.git
pip install ./netbox-ssl
```

### Configuration

Add to `configuration.py`:

```python
PLUGINS = [
    "netbox_ssl",
]

PLUGINS_CONFIG = {
    "netbox_ssl": {
        "expiry_warning_days": 30,  # Days for warning status
        "expiry_critical_days": 14,  # Days for critical status
    },
}
```

Run migrations:

```bash
cd /opt/netbox/netbox
python manage.py migrate netbox_ssl
```

## Usage

### Importing Certificates

1. Navigate to **SSL Certificates > Certificates > Import**
2. Paste your certificate in PEM format
3. Optionally add the certificate chain (intermediates + root)
4. Specify an optional private key location hint
5. Click **Import Certificate**

The plugin will:
- Reject any private key material for security
- Parse all X.509 attributes automatically
- Check for duplicates (serial + issuer)
- Detect potential renewals (same CN)

### Janus Renewal Workflow

When importing a certificate with a CN matching an existing certificate:

1. The plugin detects the potential renewal
2. Shows a comparison between old and new certificate
3. Offers two options:
   - **Renew & Transfer**: Creates new cert, copies all assignments, archives old cert
   - **Create as New**: Creates a separate certificate entry

### Assigning Certificates

Certificates can be assigned to:
- **Services** (recommended) - Port-level granularity
- **Devices** - Device-level assignment
- **Virtual Machines** - VM-level assignment

Service-level assignment is recommended as it allows different certificates per port on the same device.

### Dashboard Widget

The dashboard widget shows:
- **Expired** certificates (red)
- **Critical** certificates expiring within 14 days (red)
- **Warning** certificates expiring within 30 days (orange)
- **Orphan** certificates without assignments (gray)

## Development

### Prerequisites

- Python 3.10+
- Docker & Docker Compose
- (Optional) Nix with direnv

### Quick Start

```bash
# Clone the repository
git clone https://github.com/your-org/netbox-ssl.git
cd netbox-ssl

# Start development environment
docker-compose up -d

# View logs
docker-compose logs -f netbox

# Access NetBox
open http://localhost:8000
# Login: admin / admin
```

### Testing with Different NetBox Versions

```bash
# NetBox 4.5 (default)
docker-compose up -d

# NetBox 4.4
NETBOX_VERSION=v4.4-latest docker-compose up -d
```

### Running Tests

```bash
# In the NetBox container
docker-compose exec netbox python manage.py test netbox_ssl
```

## Data Models

### Certificate

| Field | Type | Description |
|-------|------|-------------|
| common_name | String | Primary CN |
| serial_number | String | CA serial number (hex) |
| fingerprint_sha256 | String | SHA256 fingerprint |
| issuer | String | Issuer DN |
| issuer_chain | Text | Chain of trust (PEM) |
| valid_from | DateTime | Start date |
| valid_to | DateTime | Expiration date |
| sans | Array | Subject Alternative Names |
| key_size | Integer | Key size in bits |
| algorithm | Choice | RSA, ECDSA, Ed25519 |
| status | Choice | Active, Expired, Replaced, Revoked |
| private_key_location | String | Hint for key location |
| tenant | FK | Optional tenant |

### CertificateAssignment

| Field | Type | Description |
|-------|------|-------------|
| certificate | FK | The certificate |
| assigned_object | GFK | Service, Device, or VM |
| is_primary | Boolean | Primary certificate flag |
| notes | Text | Assignment notes |

## API

### REST API

```bash
# List certificates
curl -H "Authorization: Token $TOKEN" http://localhost:8000/api/plugins/ssl/certificates/

# Get certificate
curl -H "Authorization: Token $TOKEN" http://localhost:8000/api/plugins/ssl/certificates/1/

# Filter by status
curl -H "Authorization: Token $TOKEN" "http://localhost:8000/api/plugins/ssl/certificates/?status=active"

# Filter expiring soon
curl -H "Authorization: Token $TOKEN" "http://localhost:8000/api/plugins/ssl/certificates/?expiring_soon=true"
```

### GraphQL

```graphql
{
  certificate_list {
    id
    common_name
    valid_to
    days_remaining
    expiry_status
  }
}
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Submit a pull request

## License

Apache License 2.0

## Acknowledgments

- NetBox community for the excellent plugin framework
- The `cryptography` library for X.509 parsing
