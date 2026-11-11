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
- The NetBox background worker (`netbox-rq`) running — it runs scheduled scripts
  and delivers webhooks
- A Slack workspace with permission to create an incoming webhook

## Overview

The pipeline has four moving parts:

1. **Plugin settings** define what counts as "warning" and "critical"
2. **A scheduled script** (`CertificateExpiryScan`) runs periodically and raises an
   *Object updated* event for each certificate that crossed a threshold
3. **A NetBox Event Rule** on certificates matches those events and triggers an
   action (webhook)
4. **The webhook** posts a formatted message to Slack (or Teams, or PagerDuty)

!!! warning "Requires v1.5 or newer"
    In earlier releases the scan reported its events but NetBox never received
    them, so the rule in Step 4 did not fire. Upgrade before following this
    tutorial.

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

## Step 2 — Register and schedule the expiry scan

The scan ships inside the plugin, and NetBox does not list a plugin's scripts on
its own. Register it once: put

```python
# netbox_ssl_scripts.py
from netbox_ssl.scripts import CertificateExpiryScan
```

in a file and upload that file under **Customization → Scripts → Add**
(*File Upload*). [Custom Scripts](../reference/scripts.md#making-the-scripts-available-to-netbox)
lists every bundled script and has a command-line alternative.

Now open **Customization → Scripts → Certificate Expiry Scan** and schedule it:

- **Recurs every:** `1440` — the interval in minutes; daily is a good default
  (the cooldown prevents duplicate events within that window anyway)
- **Schedule at:** any convenient first run (e.g., 02:00 local)
- **Commit changes:** leave ticked — without it NetBox discards the run's events

Click **Run Script**. The script now runs every 24 hours. On each run it goes
over every Active certificate and raises an event for each one that crossed one
of the configured thresholds **and** has not raised one within the cooldown
window.

## Step 3 — Create the Slack webhook

First, in Slack: **Apps → Incoming Webhooks → Add to Slack**, pick a channel,
copy the webhook URL (starts with `https://hooks.slack.com/services/...`).

In NetBox: **Operations → Webhooks → + Add**.

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

Save the webhook.

## Step 4 — Create a NetBox Event Rule

Navigate to **Operations → Event Rules → + Add**.

Fill in:

- **Name:** `NetBox SSL — Expiry Warnings`
- **Object types:** `NetBox SSL > Certificate`
- **Event types:** `Object updated`
- **Action type:** `Webhook`
- **Webhook:** `Slack SSL Alerts`
- **Conditions:** limit the rule to certificates inside your widest threshold,
  so an ordinary edit of a healthy certificate stays quiet:

```json
{
  "and": [
    {"attr": "days_remaining", "value": 90, "op": "lte"}
  ]
}
```

Save the rule.

!!! note "Why *Object updated*?"
    Nothing about a certificate changes when it merely gets older, so NetBox
    would raise no event at all. The scan saves each certificate that crossed a
    threshold — unchanged — which makes NetBox raise a regular *Object updated*
    event for it. There is no separate "expiry" event type to pick.

## Step 5 — Test the pipeline

You need one certificate that expires within your widest threshold (90 days with
the settings above). If you have none, import a short-lived test certificate.

Then run the scan on demand:

1. Go to **Customization → Scripts → Certificate Expiry Scan**
2. Leave **Recurs every** empty, keep **Commit changes** ticked and **Dry Run**
   unticked
3. Click **Run Script** and wait for completion (usually seconds)

Check Slack. You should see a message styled like the template above. To repeat
the test, tick **Ignore Cooldown** — otherwise the scan stays quiet about that
certificate for the next 24 hours.

## What just happened

- `CertificateExpiryScan` went over all Active certificates and compared each
  `valid_to` with the thresholds
- For certificates crossing a threshold, it checked `CertificateEventLog` — a
  small table that tracks which events have already fired, to prevent spamming
- For each new event, the script saved the certificate, which made NetBox queue
  an *Object updated* event for it
- When the script finished, NetBox matched the queued events against your Event
  Rule and enqueued the webhook
- The `netbox-rq` worker picked up the webhook and POSTed it to Slack

## Troubleshooting

!!! question "The script is not listed under Customization → Scripts"
    It has not been registered yet — see Step 2. A wrapper file that was only
    copied into `SCRIPTS_ROOT` is not enough.

!!! question "No events fired even though certs are close to expiry"
    Recent events within the cooldown window suppress new ones. Run the scan
    with **Ignore Cooldown** ticked, or set `expiry_scan_cooldown_hours: 0`
    temporarily.

!!! question "Scan runs but no webhook POST happens"
    Work through these in order:

    1. The plugin is older than v1.5 — the scan's events never reached NetBox
       before that release
    2. **Commit changes** was unticked or **Dry Run** was ticked — both
       suppress events
    3. The Event Rule is disabled, is not on *Object updated*, or its conditions
       do not match the certificate's `expiry_status`
    4. The `netbox-rq` worker is not running, or logged a delivery error

!!! question "Slack receives the POST but the formatting is broken"
    The body template is a Jinja2 template, and `data` is the certificate
    exactly as the REST API returns it. Open
    `/api/plugins/ssl/certificates/<id>/` for the certificate to see every field
    you can use, including `days_remaining`, `expiry_status` and
    `assignment_count`.

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
