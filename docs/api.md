# API Reference

NetBox SSL provides both REST API and GraphQL endpoints for automation and integration.

## Authentication

All API requests require authentication via NetBox API tokens.

### Getting a Token

1. Navigate to your **User Profile > API Tokens**
2. Click **+ Add Token**
3. Save the token securely

### Using the Token

```bash
curl -H "Authorization: Token YOUR_API_TOKEN" \
     http://localhost:8000/api/plugins/netbox-ssl/certificates/
```

---

## REST API

Base URL: `/api/plugins/netbox-ssl/`

### Certificates

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/certificates/` | List all certificates |
| `POST` | `/certificates/` | Create a certificate |
| `GET` | `/certificates/{id}/` | Get certificate details |
| `PUT` | `/certificates/{id}/` | Full update |
| `PATCH` | `/certificates/{id}/` | Partial update |
| `DELETE` | `/certificates/{id}/` | Delete certificate |
| `POST` | `/certificates/import/` | Import from PEM |
| `POST` | `/certificates/bulk-import/` | Bulk import from PEM |
| `GET/POST` | `/certificates/export/` | Export certificates |
| `GET` | `/certificates/{id}/export/` | Export single certificate |

### Assignments

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/assignments/` | List all assignments |
| `POST` | `/assignments/` | Create assignment |
| `GET` | `/assignments/{id}/` | Get assignment details |
| `PUT` | `/assignments/{id}/` | Update assignment |
| `DELETE` | `/assignments/{id}/` | Delete assignment |

---

## Filtering

### Certificate Filters

| Parameter | Type | Example | Description |
|-----------|------|---------|-------------|
| `common_name` | String | `example.com` | Filter by CN (contains) |
| `common_name__ic` | String | `example` | Case-insensitive contains |
| `status` | Choice | `active` | Filter by status |
| `tenant_id` | Integer | `1` | Filter by tenant |
| `issuer` | String | `DigiCert` | Filter by issuer |
| `valid_to__lt` | DateTime | `2024-06-01` | Expiring before date |
| `valid_to__gt` | DateTime | `2024-01-01` | Expiring after date |
| `tag` | String | `production` | Filter by tag slug |

### Examples

```bash
# List active certificates
curl -H "Authorization: Token $TOKEN" \
     "http://localhost:8000/api/plugins/netbox-ssl/certificates/?status=active"

# Certificates expiring in next 30 days
curl -H "Authorization: Token $TOKEN" \
     "http://localhost:8000/api/plugins/netbox-ssl/certificates/?valid_to__lt=$(date -d '+30 days' +%Y-%m-%d)"

# Filter by tenant
curl -H "Authorization: Token $TOKEN" \
     "http://localhost:8000/api/plugins/netbox-ssl/certificates/?tenant_id=1"

# Search by common name
curl -H "Authorization: Token $TOKEN" \
     "http://localhost:8000/api/plugins/netbox-ssl/certificates/?common_name__ic=example"
```

---

## Creating Objects

### Create a Certificate

```bash
curl -X POST \
     -H "Authorization: Token $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "common_name": "api.example.com",
       "serial_number": "01:23:45:67:89:AB:CD:EF",
       "issuer": "CN=Example CA, O=Example Inc",
       "valid_from": "2024-01-01T00:00:00Z",
       "valid_to": "2025-01-01T00:00:00Z",
       "fingerprint_sha256": "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99",
       "algorithm": "rsa",
       "key_size": 2048,
       "status": "active",
       "sans": ["api.example.com", "*.api.example.com"]
     }' \
     http://localhost:8000/api/plugins/netbox-ssl/certificates/
```

### Create an Assignment

```bash
curl -X POST \
     -H "Authorization: Token $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "certificate": 1,
       "assigned_object_type": "ipam.service",
       "assigned_object_id": 1,
       "is_primary": true,
       "notes": "Production HTTPS endpoint"
     }' \
     http://localhost:8000/api/plugins/netbox-ssl/assignments/
```

---

## Bulk Import

Import multiple certificates in a single request for efficient migrations and automation.

### Endpoint

`POST /api/plugins/netbox-ssl/certificates/bulk-import/`

### Features

- **Atomic transactions**: All certificates succeed or all fail
- **Batch size limit**: Maximum 100 certificates per request (configurable)
- **Validation first**: All certificates validated before any are created
- **Detailed errors**: Failed certificate index and specific error messages

### Configuration

The batch size limit can be configured in your NetBox `configuration.py`:

```python
PLUGINS_CONFIG = {
    "netbox_ssl": {
        "bulk_import_max_batch_size": 100,  # Default: 100, max certificates per request
    }
}
```

### Request Format

```json
[
  {
    "pem_content": "-----BEGIN CERTIFICATE-----\nMIID...",
    "private_key_location": "Vault: /secret/prod/web1",
    "tenant": 1
  },
  {
    "pem_content": "-----BEGIN CERTIFICATE-----\nMIIE...",
    "tenant": 2
  }
]
```

### Example Request

```bash
curl -X POST \
     -H "Authorization: Token $TOKEN" \
     -H "Content-Type: application/json" \
     -d '[
       {
         "pem_content": "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----",
         "private_key_location": "Vault: /secret/prod/web1"
       },
       {
         "pem_content": "-----BEGIN CERTIFICATE-----\nMIIE...\n-----END CERTIFICATE-----",
         "private_key_location": "Vault: /secret/prod/web2"
       }
     ]' \
     http://localhost:8000/api/plugins/netbox-ssl/certificates/bulk-import/
```

### Success Response (201 Created)

```json
{
  "created_count": 2,
  "certificates": [
    {
      "id": 10,
      "common_name": "www.example.com",
      "serial_number": "01:23:45:67:89",
      "status": "active",
      "valid_to": "2025-01-20T00:00:00Z"
    },
    {
      "id": 11,
      "common_name": "api.example.com",
      "serial_number": "01:23:45:67:90",
      "status": "active",
      "valid_to": "2025-06-15T00:00:00Z"
    }
  ]
}
```

### Error Response (400 Bad Request)

```json
{
  "detail": "Validation failed for one or more certificates.",
  "failed_certificates": [
    {
      "index": 2,
      "errors": {
        "pem_content": ["Invalid PEM format or unable to parse certificate."]
      }
    },
    {
      "index": 5,
      "errors": {
        "pem_content": ["Certificate already exists: www.example.com (ID: 3)"]
      }
    }
  ]
}
```

### Python Example

```python
import requests
from pathlib import Path

# Load certificates from files
cert_files = Path("/path/to/certs").glob("*.pem")
certificates = []

for cert_file in cert_files:
    certificates.append({
        "pem_content": cert_file.read_text(),
        "private_key_location": f"Vault: /secret/certs/{cert_file.stem}"
    })

# Bulk import (batch of 100 max)
response = requests.post(
    "http://localhost:8000/api/plugins/netbox-ssl/certificates/bulk-import/",
    headers={"Authorization": "Token YOUR_TOKEN"},
    json=certificates[:100]
)

if response.status_code == 201:
    result = response.json()
    print(f"Imported {result['created_count']} certificates")
else:
    print(f"Error: {response.json()}")
```

---

## Data Export

Export certificates in multiple formats for integration, reporting, and backup purposes.

### Supported Formats

| Format | Content-Type | Description |
|--------|--------------|-------------|
| `csv` | `text/csv` | Comma-separated values for spreadsheets |
| `json` | `application/json` | JSON array with full certificate data |
| `yaml` | `application/x-yaml` | YAML format (requires PyYAML) |
| `pem` | `application/x-pem-file` | PEM bundle with certificate chain |

### Bulk Export Endpoint

`GET/POST /api/plugins/netbox-ssl/certificates/export/`

#### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `format` | String | `json` | Export format (csv, json, yaml, pem) |
| `ids` | List[int] | - | Specific certificate IDs to export |
| `fields` | List[str] | - | Fields to include (see below) |
| `include_pem` | Boolean | `false` | Include PEM content (json/yaml only) |
| `include_chain` | Boolean | `true` | Include certificate chain (pem only) |

#### Available Fields

**Default fields:** `id`, `common_name`, `serial_number`, `fingerprint_sha256`, `issuer`, `valid_from`, `valid_to`, `days_remaining`, `algorithm`, `key_size`, `status`, `tenant`, `sans`

**Extended fields:** All default fields plus `is_expired`, `is_expiring_soon`, `expiry_status`, `private_key_location`, `assignment_count`, `created`, `last_updated`

#### Configuration

The maximum export size can be configured in your NetBox `configuration.py`:

```python
PLUGINS_CONFIG = {
    "netbox_ssl": {
        "max_export_size": 1000,  # Default: 1000, max certificates per export
    }
}
```

### Export Examples

#### CSV Export

```bash
# Export all active certificates as CSV
curl -H "Authorization: Token $TOKEN" \
     "http://localhost:8000/api/plugins/netbox-ssl/certificates/export/?format=csv&status=active"
```

Response (file download):
```csv
id,common_name,serial_number,fingerprint_sha256,issuer,valid_from,valid_to,days_remaining,algorithm,key_size,status,tenant
1,example.com,01:23:45:67:89,AA:BB:CC:DD,CN=Test CA,2024-01-01T00:00:00,2025-01-01T00:00:00,180,rsa,2048,active,Production
```

#### JSON Export

```bash
# Export specific certificates as JSON with PEM content
curl -X POST \
     -H "Authorization: Token $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"format": "json", "ids": [1, 2, 3], "include_pem": true}' \
     http://localhost:8000/api/plugins/netbox-ssl/certificates/export/
```

Response:
```json
[
  {
    "id": 1,
    "common_name": "example.com",
    "serial_number": "01:23:45:67:89",
    "fingerprint_sha256": "AA:BB:CC:DD:EE:FF...",
    "issuer": "CN=Test CA, O=Example Inc",
    "valid_from": "2024-01-01T00:00:00",
    "valid_to": "2025-01-01T00:00:00",
    "days_remaining": 180,
    "algorithm": "rsa",
    "key_size": 2048,
    "status": "active",
    "tenant": "Production",
    "sans": ["example.com", "www.example.com"],
    "pem_content": "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----"
  }
]
```

#### PEM Export

```bash
# Export certificates as PEM bundle with chain
curl -H "Authorization: Token $TOKEN" \
     "http://localhost:8000/api/plugins/netbox-ssl/certificates/export/?format=pem&include_chain=true"
```

Response:
```
# Certificate: example.com
# Serial: 01:23:45:67:89
# Expires: 2025-01-01

-----BEGIN CERTIFICATE-----
MIID...
-----END CERTIFICATE-----

# Certificate Chain
-----BEGIN CERTIFICATE-----
MIIE...
-----END CERTIFICATE-----
```

#### Custom Field Selection

```bash
# Export only specific fields
curl -H "Authorization: Token $TOKEN" \
     "http://localhost:8000/api/plugins/netbox-ssl/certificates/export/?format=json&fields=id&fields=common_name&fields=valid_to&fields=days_remaining"
```

### Single Certificate Export

`GET /api/plugins/netbox-ssl/certificates/{id}/export/`

Export a single certificate with the certificate's common name as the filename.

```bash
# Export single certificate as PEM
curl -H "Authorization: Token $TOKEN" \
     "http://localhost:8000/api/plugins/netbox-ssl/certificates/1/export/?format=pem"

# Response headers include:
# Content-Disposition: attachment; filename="example.com.pem"
```

### Python Example

```python
import requests

# Export expiring certificates
response = requests.get(
    "http://localhost:8000/api/plugins/netbox-ssl/certificates/export/",
    headers={"Authorization": "Token YOUR_TOKEN"},
    params={
        "format": "json",
        "status": "active",
        "valid_to__lt": "2024-06-01",
        "fields": ["id", "common_name", "valid_to", "days_remaining", "tenant"]
    }
)

if response.status_code == 200:
    certificates = response.json()
    for cert in certificates:
        print(f"{cert['common_name']}: {cert['days_remaining']} days remaining")

# Save PEM bundle to file
response = requests.get(
    "http://localhost:8000/api/plugins/netbox-ssl/certificates/export/",
    headers={"Authorization": "Token YOUR_TOKEN"},
    params={"format": "pem", "tenant_id": 1}
)

with open("certificates.pem", "w") as f:
    f.write(response.text)
```

---

## GraphQL

NetBox SSL extends NetBox's GraphQL API.

### Query Certificates

```graphql
query {
  certificate_list {
    id
    common_name
    serial_number
    issuer
    valid_from
    valid_to
    status
    days_remaining
    expiry_status
    algorithm
    key_size
    tenant {
      name
    }
    sans
  }
}
```

### Query with Filters

```graphql
query {
  certificate_list(filters: {status: "active"}) {
    id
    common_name
    valid_to
    days_remaining
    assignments {
      id
      is_primary
      assigned_object {
        ... on ServiceType {
          name
          ports
          device {
            name
          }
        }
        ... on DeviceType {
          name
        }
        ... on VirtualMachineType {
          name
        }
      }
    }
  }
}
```

### Single Certificate

```graphql
query {
  certificate(id: 1) {
    common_name
    serial_number
    fingerprint_sha256
    issuer
    issuer_chain
    valid_from
    valid_to
    sans
    algorithm
    key_size
    status
    private_key_location
    replaced_by {
      id
      common_name
    }
  }
}
```

### Query Assignments

```graphql
query {
  certificate_assignment_list {
    id
    certificate {
      common_name
      valid_to
    }
    assigned_object_type
    assigned_object_id
    is_primary
    notes
  }
}
```

---

## Webhooks

NetBox SSL triggers webhooks for certificate lifecycle events.

### Supported Events

| Object Type | Events |
|-------------|--------|
| Certificate | Created, Updated, Deleted |
| CertificateAssignment | Created, Updated, Deleted |

### Configuration

1. Navigate to **Admin > Webhooks**
2. Create a new webhook:
   - **Name:** Certificate Notifications
   - **Content types:** `netbox_ssl | certificate`
   - **Events:** Select desired events
   - **URL:** Your webhook endpoint
   - **HTTP method:** POST

### Payload Example

```json
{
  "event": "created",
  "timestamp": "2024-01-15T10:30:00Z",
  "model": "certificate",
  "username": "admin",
  "data": {
    "id": 1,
    "common_name": "example.com",
    "status": "active",
    "valid_to": "2025-01-15T00:00:00Z",
    "days_remaining": 365
  }
}
```

---

## Python SDK Example

```python
import pynetbox

nb = pynetbox.api('http://localhost:8000', token='your-token')

# List certificates
certs = nb.plugins.netbox_ssl.certificates.all()
for cert in certs:
    print(f"{cert.common_name}: {cert.days_remaining} days remaining")

# Get expiring certificates
expiring = nb.plugins.netbox_ssl.certificates.filter(
    status='active',
    valid_to__lt='2024-06-01'
)

# Create assignment
nb.plugins.netbox_ssl.assignments.create(
    certificate=1,
    assigned_object_type='ipam.service',
    assigned_object_id=5,
    is_primary=True
)
```

---

**Next:** [Data Models](data-models.md) — Database schema reference
