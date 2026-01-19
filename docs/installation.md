# Installation

Get NetBox SSL up and running in minutes.

## Requirements

- **NetBox 4.4.x or 4.5.x**
- Python 3.10 or higher
- PostgreSQL (included with NetBox)
- Redis (included with NetBox)

---

## Quick Install

### Via pip (Recommended)

```bash
pip install netbox-ssl
```

### Via Source

```bash
cd /opt/netbox/netbox
git clone https://github.com/ctrl-alt-automate/netbox-ssl.git
pip install ./netbox-ssl
```

---

## Configuration

Add the plugin to your NetBox `configuration.py`:

```python
PLUGINS = [
    "netbox_ssl",
]

# Optional: customize expiry thresholds
PLUGINS_CONFIG = {
    "netbox_ssl": {
        "expiry_warning_days": 30,   # Show warning status
        "expiry_critical_days": 14,  # Show critical status
    },
}
```

See [Configuration](configuration.md) for all available options.

---

## Database Migration

After configuring the plugin, create the database tables:

```bash
cd /opt/netbox/netbox
python manage.py migrate netbox_ssl
```

---

## Restart NetBox

Restart the NetBox services to load the plugin:

```bash
sudo systemctl restart netbox netbox-rq
```

---

## Verify Installation

Check that the plugin loaded correctly:

```bash
python manage.py check --tag netbox_ssl
```

Then navigate to **Plugins > SSL Certificates** in the NetBox UI. You should see the Certificates menu item.

<p align="center">
  <img src="images/certificate-list.png" alt="Certificate List" width="700">
</p>

---

## Docker Installation

If you're running NetBox in Docker, add the plugin to your Docker image:

```dockerfile
FROM netboxcommunity/netbox:v4.5

RUN pip install netbox-ssl
```

Or add it to your `plugin_requirements.txt`:

```
netbox-ssl
```

---

## Upgrading

To upgrade to a new version:

```bash
# Upgrade the package
pip install --upgrade netbox-ssl

# Run any new migrations
cd /opt/netbox/netbox
python manage.py migrate netbox_ssl

# Restart services
sudo systemctl restart netbox netbox-rq
```

---

## Uninstallation

If you need to remove the plugin:

1. Remove `"netbox_ssl"` from `PLUGINS` in `configuration.py`

2. Remove the database tables:
   ```bash
   cd /opt/netbox/netbox
   python manage.py migrate netbox_ssl zero
   ```

3. Uninstall the package:
   ```bash
   pip uninstall netbox-ssl
   ```

4. Restart NetBox:
   ```bash
   sudo systemctl restart netbox netbox-rq
   ```

---

## Troubleshooting

### Plugin not appearing in menu

- Check that `"netbox_ssl"` is in your `PLUGINS` list
- Verify migrations ran: `python manage.py showmigrations netbox_ssl`
- Check NetBox logs: `journalctl -u netbox -f`

### Migration errors

- Ensure you're using a compatible NetBox version (4.4+)
- Check PostgreSQL permissions for the netbox user

### Import errors

- Verify the `cryptography` library is installed: `pip show cryptography`

---

**Next:** [Configuration](configuration.md) — Customize plugin settings
