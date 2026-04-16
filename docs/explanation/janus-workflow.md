# The Janus Workflow

"Janus" is the Roman god of doorways and transitions. In NetBox SSL, every
certificate guards a doorway (a service endpoint, a device interface), and
every renewal is a transition. This document explains **why** the plugin
models renewals as "replace and archive" rather than "edit in place" — and
what trade-offs that choice carries.

## The problem

Certificates expire. When a team renews one, the natural data model question is:

> "Do I update the existing record with the new certificate's attributes, or
> create a new record and archive the old one?"

The difference sounds trivial. It isn't.

## Option A: Edit in place

A naive design updates the existing row. The row's ID stays stable — so
assignments continue to work — but:

- **Audit trail destroyed.** The row now shows the new serial number, new
  `valid_to`, new fingerprint. The only memory of the old certificate lives in
  NetBox's per-row changelog, if you remember to read it.
- **Rollback is painful.** If the new certificate is bad (wrong CN, missing
  SAN, different issuer), reverting means recovering old values from the
  changelog or a backup. No first-class "undo".
- **Historical analytics break.** "How often do we renew this certificate?"
  becomes unanswerable without trawling through changelog entries.

## Option B: Replace and archive (the Janus approach)

NetBox SSL creates a **new row** for the new certificate, copies all assignments
from the old row to the new one, and marks the old row's status as `Replaced`.
Both certificates remain in the database, linked by a `related_certificate` FK
on the lifecycle event.

Benefits:

- **Audit trail preserved.** The old certificate's full history stays intact —
  when it was imported, which SANs it had, which assignments, every status
  transition. You can answer "what was our TLS posture on 2024-06-15?".
- **Rollback is obvious.** If the new certificate is wrong, flip its status to
  `Replaced`, flip the old one back to `Active`, and re-point assignments. The
  data is still there.
- **Renewal analytics are trivial.** Every renewal produces a lifecycle event
  linking old and new. "Show me all renewals in Q3" is one query.
- **Historical reconstruction.** For compliance auditors: "show the certificate
  that was on our payment endpoint on 2024-06-15" is a timestamp range query,
  not an archaeology expedition.

## The atomicity guarantee

The single database transaction that performs a renewal:

1. Creates the new `Certificate` row
2. Re-points every `CertificateAssignment` row from the old cert to the new one
3. Sets the old cert's status to `Replaced`
4. Creates two `CertificateLifecycleEvent` rows (one `renewed` on the old, one
   `activated` on the new) with `related_certificate` linking them

If any step fails — database contention, validation error, disk full — the
whole transaction rolls back. You never end up with:

- Assignments pointing at a non-existent certificate
- Both certificates `Active` (ambiguous which should be used)
- Old cert `Replaced` but assignments still on it (orphaned)

## Trade-offs

The Janus approach isn't free:

- **Storage footprint**: every renewal doubles the row count for that
  certificate's history. With 200-certificate inventories renewing annually,
  that's manageable (200 rows per year of history). With 10,000-cert
  inventories on 60-day ACME cycles, the `Certificate` table grows quickly.
  Mitigated by the **auto-archive policy** (v0.8), which archives `Replaced`
  rows older than a configurable threshold.
- **Query complexity**: "the current certificate for this service" requires
  a filter on `status=Active`. Not hard, but easy to forget. The assignment
  layer handles this for you in the UI; API consumers need to be mindful.
- **Uniqueness discipline**: `fingerprint_sha256` is unique per certificate.
  If you accidentally import the same PEM twice, the second import fails with
  a clear error — but this requires discipline from the caller.

## Edge cases the plugin doesn't auto-handle

- **Wildcard CN changes.** If you renew `*.example.com` with a certificate
  whose CN changes to `api.example.com`, the Common Name match fails and
  you'll see a standard import rather than the Janus dialog. The plugin
  plays it safe — a different CN means a different certificate.
- **Simultaneous renewals.** If two admins trigger renewals for the same
  cert at the same time, the database transaction serialisation ensures one
  wins and the other sees the resulting state. No merge logic needed — the
  loser just sees that the cert already has a newer successor.
- **Multi-step migrations.** Some organisations swap CA mid-renewal (e.g.,
  Let's Encrypt → Google Trust Services). Because the issuer changes, the
  Janus dialog still fires (CN match is what matters), so the workflow still
  applies. The `related_certificate` chain preserves the lineage.

## Why the name "Janus"?

The god Janus had two faces — one looking to the past, one to the future.
Every certificate in a renewal has the same property: the outgoing one still
looks back at the services it has guarded, while the incoming one looks
forward. For a brief moment they coexist, related but distinct. That's
exactly the state the plugin's data model represents.

(And the name is short, googleable, and the plugin's internal code name
before v1.0 — so it stuck.)
