# Configuration

Customize NetBox SSL to fit your organization's needs.

## Plugin Configuration

Add settings to your `configuration.py`:

```python
PLUGINS = [
    "netbox_ssl",
]

PLUGINS_CONFIG = {
    "netbox_ssl": {
        "expiry_warning_days": 30,
        "expiry_critical_days": 14,
    },
}
```

---

## Available Options

### Expiry Thresholds

Control when certificates show warning/critical status:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `expiry_warning_days` | Integer | **30** | Days before expiry → Warning status |
| `expiry_critical_days` | Integer | **14** | Days before expiry → Critical status |

**Example:** Alert earlier for production certificates:

```python
PLUGINS_CONFIG = {
    "netbox_ssl": {
        "expiry_warning_days": 60,   # 2 months warning
        "expiry_critical_days": 30,  # 1 month critical
    },
}
```

---

## Custom Fields

Extend certificates with your own metadata via NetBox Custom Fields:

1. Navigate to **Admin > Customization > Custom Fields**
2. Click **+ Add**
3. Configure the field:
   - **Content Types:** Select `netbox_ssl | certificate`
   - **Name:** e.g., `cost_center`
   - **Type:** Select appropriate type

**Common custom field ideas:**
- `cost_center` — For billing/chargeback
- `environment` — Production, Staging, Development
- `certificate_authority` — Let's Encrypt, DigiCert, Internal CA
- `auto_renew` — Boolean for automation tracking

---

## Permissions

NetBox SSL uses NetBox's built-in permission system. Configure access via **Admin > Users & Groups**.

### Certificate Permissions

| Permission | Allows |
|------------|--------|
| `netbox_ssl.view_certificate` | View certificate list and details |
| `netbox_ssl.add_certificate` | Import/create new certificates |
| `netbox_ssl.change_certificate` | Edit existing certificates |
| `netbox_ssl.delete_certificate` | Remove certificates |

### Assignment Permissions

| Permission | Allows |
|------------|--------|
| `netbox_ssl.view_certificateassignment` | View assignments |
| `netbox_ssl.add_certificateassignment` | Create new assignments |
| `netbox_ssl.change_certificateassignment` | Edit assignments |
| `netbox_ssl.delete_certificateassignment` | Remove assignments |

**Example: Read-only auditor role:**
- Grant only `view_certificate` and `view_certificateassignment`

**Example: Certificate manager role:**
- Grant all certificate permissions
- Grant all assignment permissions

---

## Dashboard Widget

Add the SSL Certificate Status widget to monitor certificate health:

1. Go to the **NetBox Dashboard**
2. Click **+ Add Widget** (bottom of page)
3. Select **SSL Certificate Status**
4. Drag to position
5. Click **Save**

<p align="center">
  <img src="images/dashboard-widget.png" alt="Dashboard Widget" width="400">
</p>

The widget displays:
- **All healthy** — No action needed
- **Critical count** — Certificates expiring within critical threshold
- **Warning count** — Certificates expiring within warning threshold
- **Orphan count** — Certificates without any assignments

---

## Tags

Organize certificates with NetBox tags:

1. Create tags at **Organization > Tags**
2. Apply tags when creating/editing certificates
3. Filter by tags in list views

**Suggested tag structure:**
- `production` / `staging` / `development`
- `internal-ca` / `public-ca`
- `auto-renew` / `manual-renew`
- `team:platform` / `team:security`

---

## Integration Tips

### Webhooks

Trigger external actions on certificate events:

1. Navigate to **Admin > Webhooks**
2. Create a webhook with:
   - **Content types:** `netbox_ssl | certificate`
   - **Events:** Created, Updated, Deleted
   - **URL:** Your automation endpoint

**Use cases:**
- Notify Slack/Teams when certificates are created
- Trigger renewal automation when status changes to "Replaced"
- Update CMDB on certificate changes

### Custom Scripts

Use NetBox Custom Scripts to automate certificate operations:

```python
from extras.scripts import Script
from netbox_ssl.models import Certificate

class ExpiringCertificatesReport(Script):
    class Meta:
        name = "Expiring Certificates Report"

    def run(self, data, commit):
        certs = Certificate.objects.filter(
            status='active'
        ).order_by('valid_to')[:10]

        for cert in certs:
            self.log_info(f"{cert.common_name}: {cert.days_remaining} days")
```

---

**Next:** [Usage](usage.md) — Learn the import and renewal workflows
