# Troubleshooting

Common issues and their solutions when running NetBox SSL.

## Health Check

Always start by running the plugin health check:

```bash
python manage.py check --tag netbox_ssl
```

### Check Results

| Code | Level | Meaning |
|------|-------|---------|
| `netbox_ssl.I001` | Info | Plugin status — shows certificate and assignment counts |
| `netbox_ssl.I002` | Info | Tables not yet created — run `migrate netbox_ssl` |
| `netbox_ssl.I003` | Info | Plugin not initialized — run `migrate netbox_ssl` |
| `netbox_ssl.E001` | Error | Certificate model missing required fields |
| `netbox_ssl.E002` | Error | Assignment model structure invalid |
| `netbox_ssl.E003` | Error | URL configuration not registered |
| `netbox_ssl.E004` | Error | Required templates missing |
| `netbox_ssl.E005` | Error | Private key detection not working |
| `netbox_ssl.E006` | Error | Cryptography library not installed |

## Common Issues

### "Conflicting migrations detected"

**Symptom:** NetBox fails to start with `CommandError: Conflicting migrations detected; multiple leaf nodes`

**Cause:** Parallel migrations without a merge migration (usually after upgrading across multiple versions).

**Solution:**
```bash
python manage.py makemigrations --merge netbox_ssl
python manage.py migrate netbox_ssl
```

### Templates not updating after upgrade

**Symptom:** UI shows old templates after plugin upgrade.

**Cause:** Django caches templates in production mode.

**Solution:**
```bash
# Collect static files
python manage.py collectstatic --no-input

# Restart NetBox to clear template cache
sudo systemctl restart netbox
# Or with Docker:
docker-compose restart netbox netbox-worker
```

### "Permission denied" on import after v0.9 upgrade

**Symptom:** Users who could import certificates before v0.9 get "Permission denied".

**Cause:** v0.9 introduced the `import_certificate` custom permission. While there's a backward-compatible fallback to `add_certificate`, some configurations may not trigger it.

**Solution:** Assign the `import_certificate` permission to affected users/groups via Admin > Permissions. See [permissions documentation](permissions.md).

### Assignment list shows "FieldError"

**Symptom:** The assignments page throws `FieldError: Field 'assigned_object' does not generate an automatic reverse relation`.

**Cause:** Fixed in v0.8.1. Upgrade to the latest version.

**Solution:**
```bash
pip install --upgrade netbox-ssl
```

### ARI polling returns no results

**Symptom:** `CertificateARIPoll` script runs but skips all certificates.

**Possible causes:**
1. Certificates not marked as ACME (`is_acme = False`)
2. Certificates don't have `pem_content` stored (needed for CertID construction)
3. ACME provider not supported (only Let's Encrypt and Google Trust Services have ARI)
4. `ari_retry_after` hasn't elapsed yet

**Solution:** Check certificate ACME status and ensure PEM content is stored:
```
GET /api/plugins/netbox-ssl/certificates/?is_acme=true&has_ari=false
```

### Docker: Plugin not found

**Symptom:** `ModuleNotFoundError: No module named 'netbox_ssl'`

**Cause:** Plugin not mounted or installed in the Docker container.

**Solution:** Ensure the plugin is mounted in `docker-compose.yml`:
```yaml
volumes:
  - ./netbox_ssl:/opt/netbox/netbox/netbox_ssl:ro
```

Or install via pip in the container:
```bash
docker exec netbox-ssl-netbox-1 pip install netbox-ssl
```

## Logs

NetBox SSL logs to Django's logging framework under the `netbox_ssl` logger namespace:

- `netbox_ssl.events` — Certificate event firing
- `netbox_ssl.ari` — ARI polling operations
- `netbox_ssl.sync` — External source synchronization

Enable debug logging in `configuration.py`:

```python
LOGGING = {
    "loggers": {
        "netbox_ssl": {
            "level": "DEBUG",
        },
    },
}
```

## Getting Help

If these steps don't resolve your issue:

1. Check [existing issues](https://github.com/ctrl-alt-automate/netbox-ssl/issues) on GitHub
2. Run `python manage.py check --tag netbox_ssl` and include the output in your report
3. Open a [new issue](https://github.com/ctrl-alt-automate/netbox-ssl/issues/new) with your NetBox version, plugin version, and error details
