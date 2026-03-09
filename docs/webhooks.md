# Event Rules & Webhooks

NetBox SSL integrates with NetBox's [Event Rules](https://docs.netbox.dev/en/stable/features/event-rules/) system to enable automated notifications when certificate events occur. This allows you to send alerts to Slack, Microsoft Teams, PagerDuty, or any other webhook-compatible service.

## How It Works

1. Certificate changes (create, update, delete) automatically trigger NetBox Event Rules
2. The **Certificate Expiry Scan** script periodically checks for expiring certificates and logs events
3. You configure Event Rules in NetBox to match certificate events and forward them to your notification channels

## Certificate Events

### Standard Events (Automatic)

These events fire automatically when certificates are modified:

| Event | Trigger |
|-------|---------|
| **Object Created** | A new certificate is imported or created |
| **Object Updated** | Certificate fields are modified (including status changes) |
| **Object Deleted** | A certificate is removed |

### Status Transitions

Status changes are captured in the event payload. Common transitions:

| From | To | Meaning |
|------|----|---------|
| Active | Expired | Certificate has passed its validity date |
| Active | Replaced | Certificate was renewed via Janus workflow |
| Active | Revoked | Certificate was manually revoked |

### Enriched Payloads

Certificate event payloads include computed fields for richer context:

- `days_remaining` — Days until expiration (negative if expired)
- `expiry_status` — Category: `ok`, `warning`, `critical`, `expired`
- `assignment_count` — Number of infrastructure objects using this certificate

## Scheduled Expiry Scan

The **Certificate Expiry Scan** script proactively checks for certificates approaching expiry thresholds.

### Configuration

Add scan thresholds to your `configuration.py`:

```python
PLUGINS_CONFIG = {
    "netbox_ssl": {
        "expiry_scan_thresholds": [14, 30, 60, 90],  # Days before expiry
        "expiry_scan_cooldown_hours": 24,              # Prevent duplicate alerts
    },
}
```

### Running the Scan

**Manual:** Navigate to *Scripts > Certificate Expiry Scan* in NetBox and click Run.

**Scheduled:** Use NetBox's job scheduler to run the scan periodically (e.g., daily at 8:00 AM).

### Scan Options

| Option | Default | Description |
|--------|---------|-------------|
| Tenant | (all) | Filter scan to a specific tenant |
| Dry Run | No | Preview events without firing them |
| Ignore Cooldown | No | Fire events even if recently fired |
| Cleanup Old Events | Yes | Remove event log entries older than 90 days |

### Idempotency

The scan is idempotent by design:

- Each fired event is logged in the `CertificateEventLog` table
- Within the cooldown window (default: 24 hours), duplicate events are suppressed
- The `ignore_cooldown` option overrides this for testing

## Setting Up Event Rules

### Step 1: Create a Webhook

Navigate to **Operations > Webhooks** and create a new webhook:

- **Name:** e.g., "Slack Certificate Alerts"
- **URL:** Your webhook endpoint URL
- **HTTP Method:** POST
- **Content Type:** application/json

### Step 2: Create an Event Rule

Navigate to **Operations > Event Rules** and create a rule:

- **Name:** e.g., "Certificate Expiry Alert"
- **Content Types:** Select "NetBox SSL > Certificate"
- **Events:** Check "Updates" (status changes trigger updates)
- **Action:** Select your webhook from Step 1

### Step 3: Add Conditions (Optional)

Use conditions to filter which events trigger the rule. For example, to only alert on status changes to "expired":

```json
{
    "and": [
        {"attr": "status.value", "value": "expired"}
    ]
}
```

## Example Webhook Configurations

### Slack

Create a [Slack Incoming Webhook](https://api.slack.com/messaging/webhooks) and configure the webhook body template:

```json
{
    "text": "Certificate Alert: {{ data.common_name }}",
    "blocks": [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Certificate {{ data.status.label }}*\n*CN:* {{ data.common_name }}\n*Expires:* {{ data.valid_to }}\n*Issuer:* {{ data.issuer }}"
            }
        }
    ]
}
```

### Microsoft Teams

Create a [Teams Incoming Webhook](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook) and use an Adaptive Card template:

```json
{
    "type": "message",
    "attachments": [
        {
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {
                        "type": "TextBlock",
                        "text": "Certificate {{ data.status.label }}: {{ data.common_name }}",
                        "weight": "bolder",
                        "size": "medium"
                    },
                    {
                        "type": "FactSet",
                        "facts": [
                            {"title": "Common Name", "value": "{{ data.common_name }}"},
                            {"title": "Status", "value": "{{ data.status.label }}"},
                            {"title": "Expires", "value": "{{ data.valid_to }}"},
                            {"title": "Issuer", "value": "{{ data.issuer }}"}
                        ]
                    }
                ]
            }
        }
    ]
}
```

### PagerDuty

Use the [PagerDuty Events API v2](https://developer.pagerduty.com/docs/events-api-v2/trigger-events/):

- **URL:** `https://events.pagerduty.com/v2/enqueue`
- **Body template:**

```json
{
    "routing_key": "YOUR_INTEGRATION_KEY",
    "event_action": "trigger",
    "payload": {
        "summary": "Certificate {{ data.status.label }}: {{ data.common_name }}",
        "severity": "{% if data.status.value == 'expired' %}critical{% else %}warning{% endif %}",
        "source": "netbox-ssl",
        "component": "{{ data.common_name }}",
        "custom_details": {
            "certificate_id": "{{ data.id }}",
            "issuer": "{{ data.issuer }}",
            "valid_to": "{{ data.valid_to }}",
            "serial_number": "{{ data.serial_number }}"
        }
    }
}
```

## Changelog Enrichment

Certificate changelogs are enriched with additional context:

- **Status transitions** show clear "before → after" values
- **Renewal events** link the old and new certificates
- **Assignment changes** (add/remove) are reflected in the parent certificate's changelog
- **Computed fields** (days_remaining, expiry_status) are included in changelog snapshots

View the changelog on any certificate's detail page under the "Changelog" tab.
