# Permissions

NetBox SSL provides granular permissions beyond standard Django CRUD for
fine-grained access control.

## How NetBox grants a permission

!!! warning "Django groups and roles are ignored"
    NetBox does **not** read Django's own permission tables. Ticking a
    permission on a Django group or role grants nothing — the only thing that
    grants a permission is an **ObjectPermission**.

NetBox assembles the permissions a user holds from `ObjectPermission.actions`:

```python
# netbox/netbox/authentication/__init__.py
perm_name = f"{object_type.app_label}.{action}_{object_type.model}"
```

So a codename splits into an **action** and a **model**:

```
netbox_ssl . renew _ certificate
    │          │        └── object type: netbox_ssl | certificate
    │          └── action to enter under "Additional actions"
    └── app label
```

To grant `netbox_ssl.renew_certificate`:

1. Go to **Admin → Permissions → Object Permissions → + Add**
2. **Object types**: `netbox_ssl | certificate`
3. **Additional actions**: `renew` — the bare verb, *not* `renew_certificate`
4. Assign the permission to the user or group
5. Leave **Constraints** empty to cover all objects

The same pattern applies to every custom permission in the tables below: take
the codename, drop the model suffix, and enter what remains as the action.

## Custom Permissions

### Certificate Permissions

| Permission | Codename | Object type | Action to enter |
|-----------|----------|-------------|-----------------|
| Import certificates | `netbox_ssl.import_certificate` | `netbox_ssl \| certificate` | `import` |
| Renew certificates | `netbox_ssl.renew_certificate` | `netbox_ssl \| certificate` | `renew` |
| Bulk operations | `netbox_ssl.bulk_certificate` | `netbox_ssl \| certificate` | `bulk` |
| URL import | `netbox_ssl.urlimport_certificate` | `netbox_ssl \| certificate` | `urlimport` |

### Compliance Permissions

| Permission | Codename | Object type | Action to enter |
|-----------|----------|-------------|-----------------|
| Manage compliance | `netbox_ssl.manage_compliancepolicypolicy` | `netbox_ssl \| compliancepolicy` | `manage` |

!!! note "Renamed in v1.4"
    Three codenames changed because their old form could never be granted.
    NetBox requires the text after the final underscore to name a real model,
    and `operations`, `urlimport` and `compliance` are not models
    ([#166](https://github.com/ctrl-alt-automate/netbox-ssl/issues/166)):

    | Old (ungrantable) | New |
    |---|---|
    | `bulk_certificate` | `bulk_certificate` |
    | `urlimport_certificate` | `urlimport_certificate` |
    | `manage_compliancepolicy` | `manage_compliancepolicypolicy` |

    No ObjectPermission could reference the old names, so nothing needs
    migrating — but if you scripted permission creation against them, update
    your automation.

## Upgrading from v0.8.x

v0.9 introduced custom permissions beyond CRUD. For backward compatibility,
import endpoints accept both the new `import_certificate` permission and the
legacy `add_certificate` permission. This fallback is slated for removal in
v2.0.0.

## Bulk Operations

Bulk endpoints require **both** `bulk_certificate` and the relevant operation permission:

| Endpoint | Required Permissions |
|----------|---------------------|
| `POST /bulk-import/` | `bulk_certificate` + `import_certificate` |
| `POST /bulk-data-import/` | `bulk_certificate` + `import_certificate` |
| `POST /bulk-validate-chain/` | `bulk_certificate` + `change_certificate` |
| `POST /bulk-compliance-check/` | `bulk_certificate` + `manage_compliancepolicy` |
| `POST /bulk-detect-acme/` | `bulk_certificate` + `change_certificate` |
| `POST /bulk-status-update/` | `bulk_certificate` + `change_certificate` |
| `POST /bulk-assign/` | `bulk_certificate` + `add_certificateassignment` |

## Single-Object Endpoints

| Endpoint | Required Permission |
|----------|-------------------|
| `POST /import/` | `import_certificate` |
| `POST /{id}/validate-chain/` | `change_certificate` |
| `POST /{id}/compliance-check/` | `manage_compliancepolicy` |
| `POST /{id}/detect-acme/` | `change_certificate` |
| `GET /export/` | `view_certificate` (via `.restrict()`) |

## Tenant-Scoped Access

NetBox's ObjectPermission system supports tenant-based scoping. To restrict a user to certificates of specific tenants:

1. Go to **Admin > Permissions > Object Permissions**
2. Create a new ObjectPermission
3. Set **Object types** to `netbox_ssl | certificate`
4. Set **Actions** to the desired permissions (view, add, change, delete),
   plus any custom actions under **Additional actions** (e.g. `renew`)
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
