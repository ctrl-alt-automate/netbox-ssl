# Permissions

NetBox SSL provides granular permissions beyond standard Django CRUD for fine-grained access control.

## Custom Permissions

### Certificate Permissions

| Permission | Codename | Description |
|-----------|----------|-------------|
| Import certificates | `netbox_ssl.import_certificate` | Import via PEM, DER, PKCS#7, or bulk import |
| Renew certificates | `netbox_ssl.renew_certificate` | Perform Janus Renewal workflow |
| Bulk operations | `netbox_ssl.bulk_operations` | Execute any bulk endpoint (required in addition to the operation-specific permission) |

### Compliance Permissions

| Permission | Codename | Description |
|-----------|----------|-------------|
| Manage compliance | `netbox_ssl.manage_compliance` | Run compliance checks and manage policies |

## Bulk Operations

Bulk endpoints require **both** `bulk_operations` and the relevant operation permission:

| Endpoint | Required Permissions |
|----------|---------------------|
| `POST /bulk-import/` | `bulk_operations` + `import_certificate` |
| `POST /bulk-data-import/` | `bulk_operations` + `import_certificate` |
| `POST /bulk-validate-chain/` | `bulk_operations` + `change_certificate` |
| `POST /bulk-compliance-check/` | `bulk_operations` + `manage_compliance` |
| `POST /bulk-detect-acme/` | `bulk_operations` + `change_certificate` |
| `POST /bulk-status-update/` | `bulk_operations` + `change_certificate` |
| `POST /bulk-assign/` | `bulk_operations` + `add_certificateassignment` |

## Single-Object Endpoints

| Endpoint | Required Permission |
|----------|-------------------|
| `POST /import/` | `import_certificate` |
| `POST /{id}/validate-chain/` | `change_certificate` |
| `POST /{id}/compliance-check/` | `manage_compliance` |
| `POST /{id}/detect-acme/` | `change_certificate` |
| `GET /export/` | `view_certificate` (via `.restrict()`) |

## Tenant-Scoped Access

NetBox's ObjectPermission system supports tenant-based scoping. To restrict a user to certificates of specific tenants:

1. Go to **Admin > Permissions > Object Permissions**
2. Create a new ObjectPermission
3. Set **Object types** to `netbox_ssl | certificate`
4. Set **Actions** to the desired permissions (view, add, change, delete)
5. Under **Constraints**, add: `{"tenant__name": "Your Tenant"}`
6. Assign to the desired user/group

The plugin's `.restrict()` calls on all querysets ensure these constraints are enforced.

## Read-Only Audit Role

To create a read-only audit user that can view everything but modify nothing:

1. Create a group "SSL Auditors"
2. Assign ObjectPermission with:
   - **Object types**: all netbox_ssl models
   - **Actions**: `view` only
   - **Constraints**: none (sees all tenants)
3. Do **not** assign any custom permissions (`import_certificate`, `renew_certificate`, etc.)
