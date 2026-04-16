# Upgrading

This guide covers upgrading between NetBox SSL plugin versions.

## General Upgrade Procedure

```bash
# 1. Backup your database
pg_dump netbox > netbox_backup_$(date +%Y%m%d).sql

# 2. Upgrade the plugin
pip install --upgrade netbox-ssl

# 3. Run migrations
python manage.py migrate netbox_ssl

# 4. Collect static files
python manage.py collectstatic --no-input

# 5. Verify the installation
python manage.py check --tag netbox_ssl

# 6. Restart NetBox
sudo systemctl restart netbox netbox-rq
```

## Version-Specific Notes

### v0.9.x → v1.0.0

**No breaking changes.** v1.0 is a stability and documentation release.

- No new migrations
- No API changes
- No model changes

### v0.8.x → v0.9.0

**New migrations:** 5 (0015–0019)

**Permissions change:**
v0.9 introduces granular permissions: `import_certificate`, `renew_certificate`, `bulk_operations`, `manage_compliance`. For backward compatibility, import endpoints accept both `import_certificate` and the legacy `add_certificate` permission. This fallback will be removed in v1.1+.

**Recommended:** After upgrading, assign the new custom permissions to your users/groups via Admin > Permissions. See [permissions documentation](permissions.md) for details.

**New features requiring configuration:**
- ARI polling: enable via the `CertificateARIPoll` scheduled script
- Performance: field deferral controlled by `lazy_load_pem_content` setting (default: True)
- Compliance: policies can now use `tag_filter` to scope to tagged certificates

### v0.7.x → v0.8.0

**New migrations:** 5 (0010–0014)

- Auto-archive: configure `auto_archive_enabled` and `auto_archive_after_days` in plugin settings
- External sources: new `ExternalSource` model for syncing certificates from external systems
- Lifecycle tracking: `CertificateLifecycleEvent` model tracks status changes automatically

### v0.6.x → v0.7.0

**New migrations:** 2 (0008–0009)

- Analytics dashboard: accessible via navigation menu, no configuration needed
- Compliance reporting: requires compliance policies to be configured
- Certificate map: available at `/plugins/ssl/certificate-map/`

### v0.5.x → v0.6.0

**New migrations:** 1 (0007 merge + 0008)

- Event rules: configure via NetBox Admin > Event Rules
- Expiry scan: schedule the `CertificateExpiryScan` script
- Configure `expiry_scan_thresholds` in plugin settings

## Rollback Procedure

If an upgrade causes issues:

```bash
# 1. Install the previous version
pip install netbox-ssl==<previous_version>

# 2. Reverse migrations to the previous state
python manage.py migrate netbox_ssl <last_migration_of_previous_version>

# 3. Restart NetBox
sudo systemctl restart netbox netbox-rq
```

**Migration numbers per version:**
| Version | Last Migration |
|---------|---------------|
| v0.5.x | 0007 |
| v0.6.x | 0009 |
| v0.7.x | 0009 |
| v0.8.x | 0014 |
| v0.9.x | 0019 |

## Verification

After any upgrade, run the health check:

```bash
python manage.py check --tag netbox_ssl
```

Expected output for a healthy installation:

```
System check identified some issues:

INFOS:
?: (netbox_ssl.I001) NetBox SSL Plugin Status: X certificates, Y assignments
    HINT: Plugin is installed and database is accessible.
```

If you see errors (E-level), check the [troubleshooting guide](troubleshooting.md).
