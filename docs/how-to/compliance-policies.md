# How-to: Define and Enforce Compliance Policies

Compliance policies let you codify rules about which certificates are acceptable
in your environment — minimum key strength, approved algorithms, maximum validity
duration, approved CAs — and get a single score showing how well your inventory
meets them.

## When to use this

- You want to enforce "no RSA keys under 2048 bits" organisation-wide
- You're subject to PCI-DSS, ISO 27001, or similar and need auditable evidence
- You want to track compliance drift over time (trend chart)

## Built-in policy types

| Policy type | Checks |
|-------------|--------|
| **Minimum key size** | `key_size >= N` per algorithm |
| **Approved algorithm** | `algorithm in {list}` |
| **Maximum validity days** | `(valid_to - valid_from) <= N` |
| **Approved CA** | `issuer` matches one of the approved CAs |
| **SHA-256 fingerprint required** | Certificate has `fingerprint_sha256` set |

Each policy is defined as a database record and runs against every Active
certificate on demand or on schedule.

## Step 1 — Create a policy

Navigate to **Admin → NetBox SSL → Compliance Policies → + Add**.

Example: "No RSA keys below 2048 bits"

- **Name:** `RSA min key size 2048`
- **Policy type:** `Minimum key size`
- **Algorithm:** `rsa`
- **Minimum value:** `2048`
- **Severity:** `Error` (Error, Warning, or Info)
- **Enabled:** ✓

Save. The policy is now part of your compliance ruleset.

## Step 2 — Scope with tags (v0.9+)

By default, policies apply to every Active certificate. To scope to a subset:

1. Add a NetBox tag to the policy (e.g., `production`)
2. Only certificates with **all** the policy's tags will be checked

Example: a policy tagged with both `production` and `internet-facing` only
applies to certificates that have **both** those tags.

An empty `tag_filter` means "apply to everything" (the default).

## Step 3 — Run a compliance check

Three ways to trigger a check:

### On-demand, single certificate

From the certificate detail page: click **Check Compliance** in the action dropdown.
You'll see per-policy pass/fail immediately.

### On-demand, bulk

`POST /api/plugins/netbox-ssl/certificates/compliance-check/` with a list of
certificate IDs. Returns per-cert per-policy results.

### Scheduled

Schedule the `CertificateComplianceCheck` script (Admin → Scripts) to run daily
or weekly. Results are stored per run, enabling the trend chart.

## Step 4 — View the compliance report

Navigate to **Plugins → SSL Certificates → Compliance Report**.

The report shows:

- **Overall score** (percentage of checks passing across your inventory)
- **Breakdown by policy** (which policies have the most failures)
- **90-day trend chart** (is compliance improving or drifting?)
- **Top failing certificates** (ranked by number of failed policies)

## Step 5 — Export results

Two export formats supported:

- **CSV** — machine-readable, good for feeding into BI tools
- **JSON** — preserves full structure including per-policy details

`GET /api/plugins/netbox-ssl/certificates/compliance-report/?format=csv` returns
the CSV export with the fields allowlisted by the exporter.

## Troubleshooting

!!! question "Score shows 100% but I know some certs fail"
    Check that the policies are `Enabled` and their `tag_filter` doesn't scope
    them out of your inventory. Also verify the last run of the compliance check
    script — stale results linger until a new run overwrites them.

!!! question "Trend chart is empty"
    The trend requires at least two runs of the scheduled compliance check script
    with results ~24 hours apart. A single on-demand run doesn't populate the
    trend.

!!! question "I want a custom policy type"
    Currently, the five built-in types cover most cases. Custom logic requires a
    plugin extension — open a feature request if you have a specific need.

## Going further

- [Reference: Data Models](../reference/data-models.md) — `CompliancePolicy` and
  `ComplianceResult` schema
- [How-to: Bulk Operations](bulk-import.md) — combine bulk import with compliance
  check for migration validation
