# Tutorial 2: The Janus Renewal Workflow

!!! note "Audience and outcome"
    **You are:** a NetBox admin who has a certificate approaching expiry and a
    replacement ready.
    **You will:** renew the certificate in NetBox SSL, watch all assignments transfer
    to the new one, and archive the old one — in a single atomic step.
    **Time:** ~10 minutes.

## Prerequisites

- Completed [Tutorial 1 — First Import](01-first-import.md)
- An existing certificate in NetBox SSL with at least one assignment
- A replacement certificate in PEM format (same Common Name as the existing one)

## Why "Janus"?

Janus is the Roman god of doorways and transitions. In this plugin, every renewal
is a transition between two certificates — the outgoing one looks back, the incoming
one looks forward, and NetBox SSL makes that transition atomic.

Concretely: instead of "edit the old cert to point at the new data" (which would
destroy audit trail and make rollback painful), NetBox SSL **creates a new record**
and **archives the old one**, copying all assignments over in one database
transaction.

## Step 1 — Start from an existing certificate

Open the certificate you imported in Tutorial 1. Note its:

- Common Name
- Current `valid_to` date
- Number of assignments (shown in the Assignments tab)

## Step 2 — Import the replacement

Click the **Import** button in the main nav. Paste the replacement certificate's
PEM content.

The moment you paste, NetBox SSL parses the new certificate and checks the Common
Name against existing records. If it finds a match with an Active certificate, a
**renewal comparison dialog** appears.

## Step 3 — Review the Janus comparison

The dialog shows a side-by-side table:

| Field | Current | New |
|-------|---------|-----|
| Serial number | `01:23:AB:...` | `AB:CD:EF:...` |
| Valid from | (current date) | (new date) |
| Valid to | (current expiry) | (new expiry, later) |
| Key algorithm | RSA 2048 | RSA 2048 (matches) |
| Assignments | 3 assignments | (will be transferred) |

Below the table, you'll see:

- **Option: Renew & Transfer** — transfer all assignments to the new cert, archive
  the old one (recommended — this is the Janus workflow)
- **Option: Add as New** — skip the transfer, keep both certificates active (only
  useful if you truly want two parallel certs)

## Step 4 — Pick "Renew & Transfer"

Click the **Renew & Transfer** button. Everything that follows happens inside one
database transaction:

1. The new certificate record is created with status `Active`.
2. Every `CertificateAssignment` pointing at the old cert is re-pointed at the new
   cert.
3. The old certificate's status is set to `Replaced`.
4. A lifecycle event is logged on both certificates: `renewed` on the old,
   `activated` on the new, linking them via `related_certificate`.

If anything fails mid-transaction (unlikely but possible on DB contention), the
whole operation rolls back. You never end up in a half-renewed state.

## Step 5 — Verify the outcome

Navigate back to the old certificate:

- Status: `Replaced`
- Assignments: 0 (they've moved)
- Notes: renewal event visible in the changelog

Navigate to the new certificate:

- Status: `Active`
- Assignments: (same N as before the renewal)
- Lifecycle tab: shows an `activated` event with a link to the old certificate

## What just happened

The atomicity guarantee matters:

- **Audit trail preserved**: the old cert stays in the database, with its full
  history. Rolling back a renewal is possible in principle (revert the `Replaced`
  status, re-point the assignments).
- **No broken assignments**: at no point during the transition do assignments
  point at a dead record. They are moved, not dropped + recreated.
- **Fingerprint uniqueness upheld**: the `fingerprint_sha256` field is unique per
  certificate, so accidentally importing the same new cert twice is caught by
  the database.

## Troubleshooting

!!! question "The renewal dialog did not appear — it saved as a new cert"
    NetBox SSL only triggers the Janus dialog when the new certificate's Common
    Name matches an existing **Active** certificate. If the old cert is already
    `Expired` or `Replaced`, no dialog. If the CN differs (e.g., wildcard
    changes), no dialog.

!!! question "Assignments did not transfer"
    This is rare — typically a database transaction race. The transaction should
    have rolled back cleanly. Check the lifecycle events on both certificates for
    what landed, and reach out on GitHub issues with the audit trail if the state
    looks inconsistent.

!!! question "I want to revert a renewal"
    In the Admin UI: flip the old cert's status from `Replaced` back to `Active`,
    then in the assignments list re-point each affected assignment. Or restore
    from a database snapshot if you have one.

## Next steps

- [Tutorial 3 — Expiry Monitoring](03-expiry-monitoring.md) — get notified
  proactively so renewals happen on time
- [How-to: ACME Auto-Renewal](../how-to/acme-auto-renewal.md) — automate the
  renewal detection for ACME-managed certificates
- [Explanation: Janus Workflow](../explanation/janus-workflow.md) — why we chose
  replace-and-archive over in-place updates
