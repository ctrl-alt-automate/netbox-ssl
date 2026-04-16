# Tutorial 3: Expiry Monitoring with Events and Webhooks

!!! note "Audience and outcome"
    **You are:** a NetBox admin who wants proactive alerting — don't wait until a
    certificate expires, get notified weeks in advance.
    **You will:** configure expiry thresholds, schedule the expiry scan script, set
    up a NetBox Event Rule, and wire a Slack webhook.
    **Time:** ~20 minutes.

## Prerequisites

- NetBox SSL 1.0 installed with at least one certificate expiring within 90 days
  (or set a manually adjusted `valid_to` on a test cert for this tutorial)
- NetBox admin permissions (to edit plugin config, schedule scripts, and create
  Event Rules)
- A Slack workspace with permission to create an incoming webhook

## Overview

The pipeline has four moving parts:

1. **Plugin settings** define what counts as "warning" and "critical"
2. **A scheduled script** (`CertificateExpiryScan`) runs periodically, fires events
   on certificates that crossed a threshold
3. **NetBox Event Rules** match these events and trigger an action (webhook)
4. **The webhook** posts a formatted message to Slack (or Teams, or PagerDuty)

## Step 1 — Tune the thresholds

In your NetBox `configuration.py`, under `PLUGINS_CONFIG`:

```python
PLUGINS_CONFIG = {
    "netbox_ssl": {
        "expiry_warning_days": 30,       # orange on dashboard, info events
        "expiry_critical_days": 14,      # red on dashboard, warning events
        "expiry_scan_thresholds": [14, 30, 60, 90],  # event fires at each
        "expiry_scan_cooldown_hours": 24,            # no duplicate events within 24h
    },
}
```

Restart NetBox for the change to load:

```bash
sudo systemctl restart netbox netbox-rq
```

## Step 2 — Schedule the expiry scan

Navigate to **Admin → Scripts**. Find `CertificateExpiryScan` in the list and click it.

Click the **Schedule Job** button and pick:

- **Interval:** 24 hours is a good default (the cooldown prevents duplicate
  events within that window anyway)
- **Start time:** any convenient time (e.g., 02:00 local)

The script now runs every 24 hours. On each run it iterates over every certificate
and fires a `certificate.expiry_warning` event for each cert that crossed one of
the configured thresholds **and** hasn't fired an event within the cooldown window.

## Step 3 — Create a NetBox Event Rule

Navigate to **Admin → Event Rules → + Add**.

Fill in:

- **Name:** `NetBox SSL — Expiry Warnings`
- **Object types:** `netbox_ssl | Certificate`
- **Events:** pick `Custom` and enter `certificate.expiry_warning`
- **Action type:** `Webhook`
- **Webhook:** we'll create it in the next step — come back to this field

Save the rule (with no webhook yet — you'll link it in a moment).

## Step 4 — Create the Slack webhook

First, in Slack: **Apps → Incoming Webhooks → Add to Slack**, pick a channel,
copy the webhook URL (starts with `https://hooks.slack.com/services/...`).

In NetBox: **Admin → Webhooks → + Add**.

- **Name:** `Slack SSL Alerts`
- **URL:** paste the Slack URL
- **HTTP method:** `POST`
- **HTTP content type:** `application/json`
- **Body template:**

```json
{
  "text": ":warning: *Certificate expiring soon*",
  "attachments": [
    {
      "color": "#FFA500",
      "fields": [
        {"title": "Common Name", "value": "{{ data.common_name }}", "short": true},
        {"title": "Days remaining", "value": "{{ data.days_remaining }}", "short": true},
        {"title": "Issuer", "value": "{{ data.issuer }}", "short": false},
        {"title": "Valid to", "value": "{{ data.valid_to }}", "short": true},
        {"title": "Assignments", "value": "{{ data.assignment_count }}", "short": true}
      ]
    }
  ]
}
```

Save the webhook, then go back to your Event Rule and link it.

## Step 5 — Test the pipeline

For a safe test, pick a certificate and manually adjust its `valid_to` to, say,
13 days from now (so it crosses both the warning and critical thresholds).

Then run `CertificateExpiryScan` on demand:

1. Go to **Admin → Scripts → CertificateExpiryScan**
2. Click **Run Script** (don't re-schedule, just run once)
3. Wait for completion (usually seconds)

Check Slack. You should see a message styled like the template above.

## What just happened

- `CertificateExpiryScan` iterated over all Active certificates and computed
  `days_remaining` for each
- For certificates crossing a threshold, it checked `CertificateEventLog` — a
  small table that tracks which events have already fired, to prevent spamming
- For each new event, the script called `fire_event("certificate.expiry_warning", ...)`
  which triggers NetBox's Event Rule dispatcher
- The Event Rule matched and enqueued the webhook
- `netbox-rq` worker picked up the webhook and POSTed it to Slack

## Troubleshooting

!!! question "No events fired even though certs are close to expiry"
    Check `CertificateEventLog`: recent events within the cooldown window suppress
    new ones. Clear the cooldown by deleting the relevant log entries, or set
    `expiry_scan_cooldown_hours: 0` temporarily.

!!! question "Scan runs but no webhook POST happens"
    Verify the Event Rule matches the exact event name `certificate.expiry_warning`
    (case-sensitive). Check the NetBox `netbox-rq` worker logs for delivery errors.

!!! question "Slack receives the POST but the formatting is broken"
    The body template is a Jinja2 template. Check the exact field names in the
    event payload by looking at `netbox_ssl/utils/events.py` — the payload
    includes the certificate snapshot plus `days_remaining`, `threshold`, and
    `scan_id`.

## Going further

- Replace the Slack webhook with a Teams or PagerDuty payload — see
  [Webhooks reference](../reference/webhooks.md) for templates
- Add multiple Event Rules for different thresholds (e.g., critical → PagerDuty,
  warning → Slack)
- Enable email digests via the `CertificateExpiryNotification` script —
  configure `notification_email_enabled: True` in plugin settings
- Look into [ARI monitoring](../how-to/ari-monitoring.md) for ACME certificates —
  it complements expiry thresholds with CA-recommended renewal windows

## Next steps

- [How-to: Compliance Policies](../how-to/compliance-policies.md) — go beyond
  expiry: check algorithm strength, key size, and more
- [Explanation: Architecture](../explanation/architecture.md) — understand how
  events, scripts, and the sync engine fit together
