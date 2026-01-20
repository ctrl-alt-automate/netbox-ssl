# Custom Scripts

NetBox SSL includes built-in custom scripts for certificate management automation.

## Certificate Expiry Notification

The `CertificateExpiryNotification` script checks for certificates that are expiring soon and generates detailed reports suitable for webhook notifications.

### Features

- Configurable warning and critical thresholds
- Optional tenant filtering
- Include/exclude expired certificates
- Filter by certificate status (Active only)
- Structured JSON output for webhooks
- Human-readable log output

### Running the Script

1. Navigate to **Customization > Scripts**
2. Select **Certificate Expiry Notification**
3. Configure options:
   - **Warning Days**: Days before expiry to trigger warning (default: plugin setting)
   - **Critical Days**: Days before expiry to trigger critical alert (default: plugin setting)
   - **Tenant**: Filter by specific tenant (optional)
   - **Include Expired**: Include already expired certificates
   - **Active Only**: Only check certificates with "Active" status
4. Click **Run Script**

### Script Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `warning_days` | Integer | 30* | Days threshold for warning alerts |
| `critical_days` | Integer | 14* | Days threshold for critical alerts |
| `tenant` | Tenant | None | Filter results by tenant |
| `include_expired` | Boolean | True | Include expired certificates in report |
| `active_only` | Boolean | True | Only check Active certificates |

*Default values are taken from plugin configuration.

---

## Scheduling with NetBox Jobs

NetBox 4.4+ supports scheduled jobs. To run the expiry notification on a schedule:

### Using the NetBox UI

1. Run the script once manually to verify it works
2. In the script results, click **Schedule**
3. Configure the schedule:
   - **Interval**: Daily recommended
   - **Start Time**: Off-peak hours (e.g., 06:00 UTC)
4. Save the scheduled job

### Using the API

```bash
# Create a scheduled job via API
curl -X POST \
  -H "Authorization: Token $NETBOX_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Daily Certificate Expiry Check",
    "object_type": "extras.script",
    "interval": 86400,
    "data": {
      "warning_days": 30,
      "critical_days": 14,
      "include_expired": true,
      "active_only": true
    }
  }' \
  https://netbox.example.com/api/extras/scheduled-jobs/
```

---

## External Scheduling with Cron

For environments without NetBox job scheduling, use external cron:

### Prerequisites

1. NetBox API token with script execution permissions
2. Access to a system with cron (or similar scheduler)

### Cron Configuration

```bash
# /etc/cron.d/netbox-ssl-expiry

# Run daily at 6:00 AM UTC
0 6 * * * root /opt/scripts/check_ssl_expiry.sh
```

### Script Wrapper

```bash
#!/bin/bash
# /opt/scripts/check_ssl_expiry.sh

NETBOX_URL="https://netbox.example.com"
NETBOX_TOKEN="your-api-token"
SCRIPT_ID="netbox_ssl.CertificateExpiryNotification"

# Execute the script via API
curl -X POST \
  -H "Authorization: Token $NETBOX_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "data": {
      "warning_days": 30,
      "critical_days": 14
    },
    "commit": false
  }' \
  "${NETBOX_URL}/api/extras/scripts/${SCRIPT_ID}/"
```

---

## Webhook Integration

Configure NetBox webhooks to forward script results to external systems.

### Setting Up a Webhook

1. Navigate to **Operations > Webhooks**
2. Click **+ Add**
3. Configure:
   - **Name**: SSL Expiry Alerts
   - **Content Types**: Job Result
   - **Events**: Created
   - **URL**: Your notification endpoint
   - **HTTP Method**: POST
   - **Body Template**: (see below)

### Example Webhook Body Template

```jinja2
{% if data.name == "Certificate Expiry Notification" %}
{
  "type": "certificate_expiry_alert",
  "netbox_url": "{{ request.scheme }}://{{ request.get_host }}",
  "summary": {
    "total_alerts": {{ data.output.summary.total_alerts | default:0 }},
    "expired": {{ data.output.summary.expired_count | default:0 }},
    "critical": {{ data.output.summary.critical_count | default:0 }},
    "warning": {{ data.output.summary.warning_count | default:0 }}
  },
  "generated_at": "{{ data.output.summary.generated_at }}"
}
{% endif %}
```

### Example Webhook Payload

The script returns structured JSON data suitable for webhook consumption:

```json
{
  "summary": {
    "total_alerts": 5,
    "expired_count": 1,
    "critical_count": 2,
    "warning_count": 2,
    "thresholds": {
      "warning_days": 30,
      "critical_days": 14
    },
    "filters": {
      "tenant": null,
      "active_only": true,
      "include_expired": true
    },
    "generated_at": "2025-01-20T10:00:00+00:00"
  },
  "expired": [
    {
      "id": 42,
      "common_name": "expired.example.com",
      "serial_number": "01:23:45:67:89",
      "issuer": "CN=Example CA",
      "valid_to": "2025-01-15T00:00:00+00:00",
      "days_expired": 5,
      "tenant": "Acme Corp",
      "url": "/plugins/ssl/certificates/42/"
    }
  ],
  "critical": [
    {
      "id": 43,
      "common_name": "critical.example.com",
      "serial_number": "01:23:45:67:90",
      "issuer": "CN=Example CA",
      "valid_to": "2025-01-25T00:00:00+00:00",
      "days_remaining": 5,
      "tenant": null,
      "url": "/plugins/ssl/certificates/43/"
    }
  ],
  "warning": [
    {
      "id": 44,
      "common_name": "warning.example.com",
      "serial_number": "01:23:45:67:91",
      "issuer": "CN=Example CA",
      "valid_to": "2025-02-10T00:00:00+00:00",
      "days_remaining": 21,
      "tenant": "Acme Corp",
      "url": "/plugins/ssl/certificates/44/"
    }
  ]
}
```

---

## Integration Examples

### Slack Notification

```python
# Example Slack webhook handler
import json
import requests

def handle_ssl_alert(payload):
    summary = payload["summary"]

    if summary["total_alerts"] == 0:
        return  # No action needed

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "🔐 SSL Certificate Alert"
            }
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Expired:* {summary['expired_count']}"},
                {"type": "mrkdwn", "text": f"*Critical:* {summary['critical_count']}"},
                {"type": "mrkdwn", "text": f"*Warning:* {summary['warning_count']}"},
            ]
        }
    ]

    requests.post(SLACK_WEBHOOK_URL, json={"blocks": blocks})
```

### PagerDuty Integration

```python
# Example PagerDuty integration
def handle_ssl_alert(payload):
    summary = payload["summary"]

    # Only alert on critical issues
    if summary["critical_count"] > 0 or summary["expired_count"] > 0:
        trigger_pagerduty_alert(
            severity="critical",
            summary=f"SSL Certificates: {summary['expired_count']} expired, {summary['critical_count']} critical",
            details=payload
        )
```

---

## Best Practices

1. **Schedule during off-peak hours** — Reduce load on NetBox
2. **Start with conservative thresholds** — 30/14 days allows time for renewal
3. **Use tenant filtering for multi-team environments** — Route alerts to responsible teams
4. **Monitor script execution** — Check scheduled job status regularly
5. **Test webhooks with non-production endpoints first**

---

**Next:** [API](api.md) — REST API reference
