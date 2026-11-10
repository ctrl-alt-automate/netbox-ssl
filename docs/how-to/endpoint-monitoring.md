# How-to: Website-centric Endpoint Monitoring

Most of NetBox SSL is certificate-centric: you import a certificate and record
where it is deployed. Endpoint monitoring inverts that. You register a **URL you
care about**, and the plugin repeatedly asks that URL which certificate it is
actually serving — then reconciles the answer with your inventory.

That makes it the fastest way to answer "is what we *think* is deployed the same
as what is *really* deployed?"

## When to use this

- You want drift detection: the live certificate no longer matches the inventory
- You want to catch renewals performed outside NetBox (ACME, a load balancer, a
  hosting provider) without importing anything by hand
- You want to be alerted when a public endpoint goes unreachable or starts
  serving an untrusted chain

## Step 1 — Register an endpoint

Navigate to **SSL → Monitored Endpoints → + Add** and fill in:

| Field | Required | Notes |
|-------|:--------:|-------|
| **Name** | yes | Human label, e.g. `HR portal` |
| **URL** | yes | `https://host` or `https://host:port` |
| **SNI** | no | Override the TLS server name; defaults to the URL host |
| **Assigned object** | no | Link the endpoint to a Device, VM, or Service |
| **Tenant** | no | Used for filtering and for scoping poll runs |

A new endpoint starts with status **Pending** — nothing has been polled yet.

## Step 2 — Make the poll script available

!!! important "This step is not optional"
    NetBox does not auto-discover scripts bundled inside a plugin. Until you
    register `MonitoredEndpointPoll`, **nothing ever polls your endpoints** and
    every one of them stays on **Pending** indefinitely.

Add the class to your `SCRIPTS_ROOT` wrapper module (see
[Custom Scripts](../reference/scripts.md#making-the-scripts-available-to-netbox)):

```python
# /opt/netbox/netbox/scripts/netbox_ssl_scripts.py
from netbox_ssl.scripts import MonitoredEndpointPoll
```

!!! warning "Requires v1.3.1 or newer"
    In v1.3.0 this import raised `ImportError` because the class was never
    re-exported from the package
    ([#163](https://github.com/ctrl-alt-automate/netbox-ssl/issues/163)).

## Step 3 — Schedule the poll

Open **Customization → Scripts → Monitored Endpoint Poll** and schedule it. Daily
is a sensible default; hourly is reasonable if you rotate certificates often.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `tenant` | Tenant | none | Restrict the run to a single tenant |
| `dry_run` | Boolean | `false` | Count what would be polled without writing |

Each run performs a TLS handshake per endpoint and then:

1. **Links** the endpoint to the matching `Certificate`, importing it if the
   plugin has not seen it before
2. **Records** the certificate in the endpoint's history (`first_seen` /
   `last_seen`)
3. **Detects rotation** when the served certificate differs from the previous one
4. **Retires the renewed certificate**: the predecessor becomes **Replaced** and
   its successor takes over its assignments — see
   [What happens when a certificate is renewed](#what-happens-when-a-certificate-is-renewed)
5. **Updates** `status`, `last_checked`, `last_seen`, and `last_error`

## Step 4 — Read the results

| Status | Meaning |
|--------|---------|
| **Pending** | Never polled — the script has not run (see Step 2) |
| **OK** | Handshake succeeded and the chain verified |
| **Untrusted** | A certificate was served, but its chain did not verify |
| **Unreachable** | No usable certificate could be retrieved; see `last_error` |

The endpoint detail page shows the current certificate plus the full history of
every certificate that endpoint has served, which is what makes rotation visible
after the fact.

## What happens when a certificate is renewed

A renewal performed outside NetBox — certbot, an ACME client on a load balancer,
a hosting provider — reaches the plugin as an endpoint that suddenly presents a
different certificate. The poll then runs the same **Janus renewal** as the
manual import workflow, so you do not end up with the old and the new
certificate both **Active**:

- the predecessor's status becomes **Replaced** and it links to its successor
- the successor receives a copy of the predecessor's **assignments** (the
  predecessor keeps its own, as a record)
- operator-maintained metadata carries over: **private key location**, the
  **renewal note**, the **tenant**, and — when the predecessor is an ACME
  certificate — the ACME provider, account e-mail, challenge type, server URL,
  auto-renewal flag and renewal days. A value already set on the successor is
  never overwritten.
- the successor gets a **Renewed** entry on its Lifecycle tab naming the
  predecessor
- NetBox raises an *Object updated* event for the predecessor (its status
  changes to Replaced), so an Event Rule on certificates sees the renewal

A **Replaced** certificate no longer raises expiry alerts, so the poll only
retires a predecessor when it is sure. All of the following must hold:

| Condition | Why |
|-----------|-----|
| The poll verified the endpoint's chain (status **OK**, not **Untrusted**) | Retiring a certificate changes your inventory on the word of a remote host, so that host has to be authenticated. Anyone on the network path can answer with a self-signed certificate for the right name. |
| This endpoint was itself seen serving the predecessor | The certificate chosen on the endpoint form is user input, not evidence; only a poll that saw the endpoint serve a certificate makes it a predecessor |
| The certificate now served is **Active** | A revoked or already replaced certificate is not a successor |
| The predecessor is **Active** or **Expired** | Revoked, archived and replaced certificates were already dealt with |
| The predecessor was issued **earlier** | Falling back to an older certificate is a rollback, not a renewal |
| Both certificates share a name (CN or SAN) | Otherwise the host now answers with an unrelated certificate — that is drift |
| The two certificates are not in different tenants | A renewal never crosses a tenant boundary |
| No other monitored endpoint still serves the predecessor | It is still in service somewhere; it is retired once the last endpoint has rotated |

When a condition is not met the poll still records the rotation; it just leaves
both certificates as they are.

!!! note "Rotations from v1.3.0 – v1.4.0 are repaired automatically"
    Those versions detected a rotation but never retired the predecessor
    ([#184](https://github.com/ctrl-alt-automate/netbox-ssl/issues/184)). The
    check covers every certificate in the endpoint's history, not just the last
    one, so the first poll after upgrading marks those leftovers **Replaced**.

!!! warning "Several nodes behind one name, each with its own certificate"
    If a load-balanced name alternates between nodes that hold *different*
    certificates, the poll sees a rotation whenever it reaches another node and
    keeps only the most recently issued certificate **Active**. Monitor each
    node through its own URL (or its own SNI) so every certificate has an
    endpoint of its own.

## Step 5 — Alert on changes (optional)

Polling fires plugin events that you can hook up to NetBox **Event Rules** to
drive a webhook or a script:

| Event | Fired when |
|-------|------------|
| `endpoint_cert_rotated` | The served certificate changed since the last poll |
| `endpoint_untrusted_cert` | The chain failed to verify |
| `endpoint_unreachable` | The endpoint could not be reached at all |

See [Webhooks](../reference/webhooks.md) for payload templates.

## Configuration

Endpoints resolving to private IP ranges are refused by default — the same
SSRF protection used by [URL import](url-import.md). To monitor internal
endpoints, opt in explicitly:

```python
PLUGINS_CONFIG = {
    "netbox_ssl": {
        "url_import_private_cidr_allowlist": ["10.0.0.0/8", "192.168.10.0/24"],
    },
}
```

## Troubleshooting

!!! question "All my endpoints are stuck on Pending"
    The poll script has never run. Confirm `MonitoredEndpointPoll` appears under
    **Customization → Scripts**; if it does not, revisit Step 2 and check the
    NetBox log for an `ImportError` from your wrapper module. On v1.3.0 the
    import fails by design of the bug — upgrade to v1.3.1+.

!!! question "An internal endpoint reports Unreachable"
    Private addresses are blocked unless allowlisted. Add the range to
    `url_import_private_cidr_allowlist` and re-run the script.

!!! question "The endpoint shows Untrusted but the browser is happy"
    The plugin verifies against the system trust store of the NetBox host, which
    may not contain your internal root CA. Install the root in that trust store,
    or accept **Untrusted** as the expected state for that endpoint.

!!! question "After a renewal the old and the new certificate are both Active"
    On v1.3.0 – v1.4.0 that was a bug
    ([#184](https://github.com/ctrl-alt-automate/netbox-ssl/issues/184)); upgrade
    and run the poll once. If it still happens, one of the conditions under
    [What happens when a certificate is renewed](#what-happens-when-a-certificate-is-renewed)
    is not met. The two most common ones: another monitored endpoint still
    serves the old certificate, or the endpoint is **Untrusted** — a certificate
    from an internal CA is only recognised as a renewal once that CA's root is
    in the trust store of the NetBox host.

!!! question "A renewal reminder quotes an old certificate"
    Reminders read the certificate the endpoint is currently linked to. If the
    poll is not running, that link is stale
    ([#161](https://github.com/ctrl-alt-automate/netbox-ssl/issues/161)) —
    schedule the poll and the reminder will follow the live certificate.

## API

```http
GET  /api/plugins/ssl/monitored-endpoints/
POST /api/plugins/ssl/monitored-endpoints/
```

See the [API reference](../reference/api.md) for the full schema.
