# Data Models

This page documents the database models used by NetBox SSL Plugin.

## Overview

```
┌─────────────────────────────────────────┐
│              Certificate                │
│  • common_name                          │
│  • serial_number, fingerprint           │
│  • issuer, validity dates               │
│  • algorithm, key_size                  │
│  • status, tenant                       │
└─────────────────┬───────────────────────┘
                  │ 1:N
                  │
┌─────────────────┴───────────────────────┐
│         CertificateAssignment           │
│  • certificate (FK)                     │
│  • assigned_object (GFK)                │
│  • is_primary, notes                    │
└─────────────────┬───────────────────────┘
                  │ GenericForeignKey
                  │
        ┌─────────┼─────────┐
        ▼         ▼         ▼
    ┌───────┐ ┌───────┐ ┌───────┐
    │Device │ │  VM   │ │Service│
    └───────┘ └───────┘ └───────┘
```

---

## Certificate

The main model for storing certificate metadata.

### Fields

| Field | Type | Required | Description |
|-------|------|:--------:|-------------|
| `common_name` | CharField(255) | Yes | Primary CN from certificate subject |
| `serial_number` | CharField(255) | Yes | Certificate serial (hex format) |
| `fingerprint_sha256` | CharField(95) | Yes | SHA256 fingerprint with colons |
| `issuer` | CharField(500) | Yes | Issuer Distinguished Name |
| `issuer_chain` | TextField | | Intermediate + root certs (PEM) |
| `valid_from` | DateTimeField | Yes | Certificate validity start |
| `valid_to` | DateTimeField | Yes | Certificate validity end |
| `sans` | JSONField | | Subject Alternative Names (array) |
| `algorithm` | CharField(20) | Yes | Key algorithm |
| `key_size` | IntegerField | | Key size in bits |
| `status` | CharField(20) | Yes | Certificate lifecycle status |
| `private_key_location` | CharField(500) | | Hint for key storage location |
| `replaced_by` | ForeignKey(self) | | Link to replacement certificate |
| `tenant` | ForeignKey(Tenant) | | Optional tenant for isolation |
| `comments` | TextField | | User notes |
| `tags` | ManyToMany(Tag) | | NetBox tags |

### Status Choices

| Value | Label | Description |
|-------|-------|-------------|
| `active` | Active | Certificate is valid and in use |
| `expired` | Expired | Validity period has ended |
| `replaced` | Replaced | Superseded by a newer certificate |
| `revoked` | Revoked | Certificate was revoked |
| `pending` | Pending | Awaiting deployment |

### Algorithm Choices

| Value | Label | Notes |
|-------|-------|-------|
| `rsa` | RSA | Most common, key_size required |
| `ecdsa` | ECDSA | Elliptic curve, key_size = curve bits |
| `ed25519` | Ed25519 | Modern curve, key_size = null |

### Computed Properties

These properties are calculated dynamically:

| Property | Type | Description |
|----------|------|-------------|
| `days_remaining` | int | Days until expiration (negative if expired) |
| `days_expired` | int | Days since expiration (0 if not expired) |
| `is_expired` | bool | True if validity period has ended |
| `is_expiring_soon` | bool | True if within warning threshold |
| `is_critical` | bool | True if within critical threshold |
| `expiry_status` | str | One of: `ok`, `warning`, `critical`, `expired` |

### Unique Constraint

Certificates must be unique on `(serial_number, issuer)` combination. This prevents duplicate imports while allowing certificates from different CAs to have the same serial.

---

## CertificateAssignment

Links certificates to infrastructure objects.

### Fields

| Field | Type | Required | Description |
|-------|------|:--------:|-------------|
| `certificate` | ForeignKey | Yes | Reference to Certificate |
| `assigned_object_type` | ForeignKey(ContentType) | Yes | Type of target object |
| `assigned_object_id` | PositiveInteger | Yes | ID of target object |
| `is_primary` | BooleanField | Yes | Primary certificate flag (default: True) |
| `notes` | TextField | | Assignment notes |
| `tags` | ManyToMany(Tag) | | NetBox tags |

### Supported Object Types

The `assigned_object` GenericForeignKey supports:

| Content Type | Model | Use Case |
|--------------|-------|----------|
| `dcim.device` | Device | Physical servers, load balancers |
| `virtualization.virtualmachine` | VirtualMachine | VMs, containers |
| `ipam.service` | Service | Port-specific assignments (recommended) |

> **Tip:** Service assignments are recommended because they provide port-level granularity.

### Unique Constraint

Assignments must be unique on `(certificate, assigned_object_type, assigned_object_id)`. This prevents assigning the same certificate to the same object twice.

### Validation Rules

1. **Tenant Boundary:** If certificate has a tenant, target object must have same tenant or no tenant
2. **Object Existence:** Target object must exist and be of a supported type

---

## CompliancePolicy

Defines compliance rules for certificate validation.

### Fields

| Field | Type | Required | Description |
|-------|------|:--------:|-------------|
| `name` | CharField(100) | Yes | Unique policy name |
| `description` | TextField | | Detailed description |
| `policy_type` | CharField(30) | Yes | Type of compliance check |
| `severity` | CharField(20) | Yes | Severity when violated |
| `enabled` | BooleanField | Yes | Whether policy is active |
| `parameters` | JSONField | | Policy parameters (varies by type) |
| `tenant` | ForeignKey(Tenant) | | Limit to specific tenant |
| `tags` | ManyToMany(Tag) | | NetBox tags |

### Policy Type Choices

| Value | Label | Description |
|-------|-------|-------------|
| `min_key_size` | Minimum Key Size | Check key meets minimum bits |
| `max_validity_days` | Maximum Validity Period | Check validity period limit |
| `algorithm_allowed` | Algorithm Allowed | Check algorithm is in allowed list |
| `algorithm_forbidden` | Algorithm Forbidden | Check algorithm not in forbidden list |
| `expiry_warning` | Expiry Warning Threshold | Check expiry within warning days |
| `chain_required` | Chain Required | Check certificate chain is present |
| `san_required` | SAN Required | Check SANs are present |
| `wildcard_forbidden` | Wildcard Forbidden | Check no wildcard domains |
| `issuer_allowed` | Issuer Allowed | Check issuer in allowed list |
| `issuer_forbidden` | Issuer Forbidden | Check issuer not in forbidden list |

### Severity Choices

| Value | Label | Description |
|-------|-------|-------------|
| `critical` | Critical | Urgent compliance violation |
| `warning` | Warning | Important but not critical |
| `info` | Info | Informational finding |

### Policy Parameters Examples

```json
// min_key_size
{"min_bits": 2048}

// max_validity_days
{"max_days": 397}

// algorithm_allowed
{"algorithms": ["rsa", "ecdsa", "ed25519"]}

// algorithm_forbidden
{"algorithms": ["dsa"]}

// expiry_warning
{"warning_days": 30}

// san_required
{"min_count": 1}

// issuer_allowed
{"issuers": ["DigiCert", "Let's Encrypt"]}

// issuer_forbidden
{"issuers": ["Unknown CA", "Self-Signed"]}
```

---

## ComplianceCheck

Stores results of compliance checks against certificates.

### Fields

| Field | Type | Required | Description |
|-------|------|:--------:|-------------|
| `certificate` | ForeignKey | Yes | Certificate that was checked |
| `policy` | ForeignKey | Yes | Policy that was applied |
| `result` | CharField(20) | Yes | Result of the check |
| `message` | TextField | | Detailed result message |
| `checked_at` | DateTimeField | Yes | When check was performed |
| `checked_value` | CharField(255) | | Actual value that was checked |
| `expected_value` | CharField(255) | | Expected value per policy |
| `tags` | ManyToMany(Tag) | | NetBox tags |

### Result Choices

| Value | Label | Description |
|-------|-------|-------------|
| `pass` | Pass | Certificate meets policy |
| `fail` | Fail | Certificate violates policy |
| `error` | Error | Error during check |
| `skipped` | Skipped | Check was skipped |

### Computed Properties

| Property | Type | Description |
|----------|------|-------------|
| `is_passing` | bool | True if result is pass |
| `is_failing` | bool | True if result is fail |
| `severity` | str | Severity from associated policy |

### Unique Constraint

Only one check result per (certificate, policy) combination. Running compliance checks updates the existing record.

---

## Database Tables

| Model | Table Name |
|-------|------------|
| Certificate | `netbox_ssl_certificate` |
| CertificateAssignment | `netbox_ssl_certificateassignment` |
| CompliancePolicy | `netbox_ssl_compliancepolicy` |
| ComplianceCheck | `netbox_ssl_compliancecheck` |

### Indexes

The following indexes are created for performance:

- `certificate.common_name` — For CN searches
- `certificate.serial_number` — For serial lookups
- `certificate.valid_to` — For expiry queries
- `certificate.status` — For status filtering
- `assignment.certificate_id` — For certificate lookups

---

## Migrations

Migrations are stored in `netbox_ssl/migrations/`.

### Running Migrations

```bash
# Apply all pending migrations
python manage.py migrate netbox_ssl

# Check migration status
python manage.py showmigrations netbox_ssl

# Roll back to specific migration
python manage.py migrate netbox_ssl 0001

# Roll back all (remove tables)
python manage.py migrate netbox_ssl zero
```

### Creating New Migrations

After modifying models:

```bash
python manage.py makemigrations netbox_ssl
python manage.py migrate netbox_ssl
```

---

## Example Queries

### Django ORM

```python
from netbox_ssl.models import Certificate, CertificateAssignment

# Get active certificates expiring within 30 days
from django.utils import timezone
from datetime import timedelta

expiring = Certificate.objects.filter(
    status='active',
    valid_to__lte=timezone.now() + timedelta(days=30)
)

# Get certificates with their assignments
certs = Certificate.objects.prefetch_related('assignments')
for cert in certs:
    print(f"{cert.common_name}: {cert.assignments.count()} assignments")

# Find orphan certificates (no assignments)
orphans = Certificate.objects.filter(
    status='active',
    assignments__isnull=True
)

# Get all certificates for a device
from dcim.models import Device
device = Device.objects.get(name='web-server-01')
assignments = CertificateAssignment.objects.filter(
    assigned_object_type__model='device',
    assigned_object_id=device.id
)
```

### Raw SQL

```sql
-- Expiring certificates
SELECT common_name, valid_to,
       (valid_to - NOW()) AS time_remaining
FROM netbox_ssl_certificate
WHERE status = 'active'
  AND valid_to < NOW() + INTERVAL '30 days'
ORDER BY valid_to;

-- Certificate assignment counts
SELECT c.common_name, COUNT(a.id) AS assignment_count
FROM netbox_ssl_certificate c
LEFT JOIN netbox_ssl_certificateassignment a ON a.certificate_id = c.id
GROUP BY c.id
ORDER BY assignment_count DESC;
```
