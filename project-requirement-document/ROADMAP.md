# NetBox SSL — Roadmap

**Status:** Living document
**Last reviewed:** 2026-04-21
**Plugin version at publication:** v1.0.1
**Owner:** NetBox SSL team (see `CONTRIBUTING.md`)

> This roadmap sketches what *may* come after v1.0.0. It is deliberately
> vague on timing: a solo or small-team project misses hard dates more
> often than it hits them, and Now/Next/Later is an honest taxonomy.
>
> For current product specification, see [PRD.md](PRD.md). For shipped
> work, see [CHANGELOG.md](../CHANGELOG.md).

---

## 1. Metadata

**Governance:** Reviewed per release cycle; annually pruned of stale
`Later` and `Deferred` items (every April).

**Change log of this document:**

| Date | Change |
|------|--------|
| 2026-04-17 | Initial roadmap post-v1.0 GA. |
| 2026-04-21 | Post-v1.0.1 review. Promoted **AWS ACM** and **Azure Key Vault** read-only adapters from Later (§5.4, §5.5) to Next (now §4.1, §4.2). Demoted **DigiCert CertCentral Adapter** from Next (§4.2) to Later (§5.5), narrowed scope to a GenericRESTAdapter preset + how-to guide because a reliable first-party adapter requires a live DigiCert account the maintainer does not hold. Renumbered §4.3 Vault → §4.3 (unchanged), Performance Scaling Pass → §4.4. |

---

## 2. How to Read This Roadmap

No hard dates. Items live in one of five buckets:

| Bucket | Meaning | Matches GitHub milestone? |
|--------|---------|---------------------------|
| **Now** | In active development | Open milestone |
| **Next** | Committed, scoped, not yet started | Backlog with label |
| **Later** | Under consideration | Open issue, no milestone |
| **Deferred** | Considered, not pursued for now | Closed as "wontfix for v1.x" |
| **Rejected** | Actively not building, with rationale | Closed with the reasoning preserved |

Items move between buckets as priorities shift. A feature in Later may
become Next (or Rejected), never "missed deadline" — only "different
priority now".

**Every Now item requires a reference issue.** Next and Later items
should have reference issues when they become committed.

---

## 3. Now — In Active Development

*Empty at v1.0.0 ship. Items appear here when an issue is assigned a
milestone and work has started.*

---

## 4. Next — Committed, Scoped, Not Yet Started

### 4.1 AWS ACM Read-Only Adapter

**Goal.** Add a first-party External Source adapter for AWS Certificate
Manager. Reads certificate metadata only, never private keys (ACM does
not expose them).

**Scope boundary.** Same as the existing Lemur adapter: read-only,
HTTPS-only outbound calls, credentials by reference (env vars or an
IAM role attached to the NetBox host). The adapter joins the registry
alongside `LemurAdapter` and `GenericRESTAdapter`.

**Reference issue.** [#100](https://github.com/ctrl-alt-automate/netbox-ssl/issues/100).
**Blocking dependency.** [#99](https://github.com/ctrl-alt-automate/netbox-ssl/issues/99)
(RFC: Multi-credential auth pattern) — AWS needs `access_key_id` +
`secret_access_key` at minimum, which the single-string credential
reference cannot currently express.

### 4.2 Azure Key Vault Read-Only Adapter

**Goal.** Add a first-party External Source adapter for Azure Key
Vault. Reads certificate metadata (`cer` bytes only), never private
key material.

**Scope boundary.** Read-only. Uses the Azure SDK to call only the
`certificates` API — explicitly never `get_key`, `get_secret`,
`backup_certificate`, or any export path that would touch private-key
material. The adapter duplicates the plugin-level `_PROHIBITED_MAPPING_KEYS`
guard with an adapter-level assertion.

**Reference issue.** [#101](https://github.com/ctrl-alt-automate/netbox-ssl/issues/101).
**Blocking dependency.** [#99](https://github.com/ctrl-alt-automate/netbox-ssl/issues/99)
(RFC: Multi-credential auth pattern) — Azure needs `tenant_id` +
`client_id` + `client_secret` at minimum, or a Managed Identity path.

### 4.3 Vault Read-Only Integration

**Goal.** Resolve `private_key_location` breadcrumbs against a HashiCorp
Vault instance to confirm the key is where the operator says it is,
without retrieving the key material itself.

**Scope boundary.** The plugin performs only existence checks (e.g., a
`LIST` or `HEAD` against the path). The plugin never reads key contents,
even if Vault permissions would allow it — enforced in code, mirroring
the PEM parser's private-key rejection.

**Reference issue.** To be filed.

### 4.4 Performance Scaling Pass (> 10 000 Certificates)

**Goal.** Validate and tune plugin behaviour at 10 000 and 50 000
certificates. Profile slow queries, tune index usage, add benchmark
assertions to CI.

**Scope boundary.** No architectural changes — this is tuning, not
redesign. If a redesign turns out to be needed, it gets promoted to a
design spec and a separate plan.

**Reference issue.** To be filed.

---

## 5. Later — Under Consideration

### 5.1 Git-backed Audit Trail

Export certificate state to a Git repository for version control outside
NetBox. Aligns with the passive philosophy (read-only export, no active
control).

### 5.2 Certificate Transparency Log Monitoring

Use Certificate Transparency logs to detect certificates issued for the
organisation's domains outside the tracked inventory. Passive monitoring
of public data — aligns with the principle.

### 5.3 SLA Tracking

Define SLAs per tenant or CA ("renewal must land within X days of
warning"). Purely administrative — tracks the human workflow, does not
automate it.

### 5.4 Scan-Result Ingestion

Import output from `nmap`, `sslyze`, or similar passive scanners. Dedupes
against the existing inventory and flags discrepancies. The scanner
remains the active component; the plugin ingests the results.

### 5.5 DigiCert CertCentral via GenericREST Preset

Originally scoped as a first-party adapter (ex-§4.2 in the 2026-04-17
roadmap). Demoted on 2026-04-21 because reliable development without a
live DigiCert account is not feasible — the adapter could be written
against published schemas, but real-world auth quirks, undocumented
fields, pagination edge cases, and error-response formats cannot be
verified without live access.

**Revised scope.** Ship a documented `GenericRESTAdapter` **preset** for
DigiCert CertCentral instead of a dedicated adapter class: a YAML/JSON
configuration fragment in `docs/how-to/` that operators with an account
can drop into their `ExternalSource.field_mapping`. Community members
with accounts validate and refine the preset; fewer lines of code,
same operational outcome.

**Promotion path back to Next.** If a maintainer gains a live DigiCert
account, or a community contributor commits to long-term adapter
maintenance with their account, promote to Next with an ADR-worthy
discussion of adapter-class vs. preset trade-off.

### 5.6 Multi-Language Documentation

Dutch translation of the docs site (currently English only). Possibly
other languages if contributors step up. The PRD itself stays English
as the canonical reference.

### 5.7 Per-Tenant Alerting Policies

Different expiry thresholds and notification channels for different
parts of the organisation. Currently thresholds are global.

---

## 6. Deferred — Considered, Not Pursued For Now

### 6.1 Multi-Instance Sync

Synchronising certificate data between NetBox deployments introduces
conflict resolution, ownership, and trust questions that exceed the
current scope. Revisit only if there is a clear operational case and a
design spec that addresses those questions.

### 6.2 AI-Powered Expiry Prediction

Machine-learning-driven predictions (e.g., "cert X is likely to be
renewed late based on historical patterns") are an interesting research
topic but not a short-term priority. The deterministic threshold model
is sufficient for the current audience.

### 6.3 Commercial PKI UI Embedding

Embedding CA-provider dashboards (e.g., DigiCert web UI, Venafi console)
inside NetBox. Marginal value over the external-source metadata sync
already in place, at significant UI complexity cost.

### 6.4 Certificate Graph Visualisation

Beyond the tree-shaped topology, show certificate relationships as a
graph (shared SANs, shared CAs, sibling services). Interesting idea;
the current topology view covers the primary need.

---

## 7. Rejected — Actively Not Building

These are not "yet to be reconsidered" — they conflict with a design
principle. Reconsideration requires a convincing argument that the
principle itself should change.

### 7.1 Active ACME Client

Violates ADR-01 (Passive over Active). The certificate issuance and
deployment domain is owned by specialised tooling (Certbot, acme.sh,
Caddy, Traefik, cert-manager). NetBox SSL observes and documents; it
does not run ACME.

### 7.2 Private Key Storage

Violates ADR-02 (No Private Key Storage). Even encrypted, keys in the
plugin database create a concentration of secrets inside a non-secrets-
manager system. Use a secrets manager (HashiCorp Vault, AWS Secrets
Manager, Azure Key Vault) and record the *location* in the plugin.

### 7.3 Automatic Certificate Deployment to Devices

Violates ADR-01 and expands the plugin's trust boundary to SSH keys,
kubeconfigs, and device credentials. Dedicated deployment tooling
(Ansible, Salt, Terraform, Kubernetes) owns this, and their access
models are built for it.

### 7.4 Active Network Scanning

Running outbound scans to discover certificates conflicts with passive
administration and introduces false-positive risk. Passive ingestion
from an existing scanner's output (see §5.6) is the correct pattern.

### 7.5 TLS Traffic Inspection or Interception

Categorically out of scope. The plugin never handles live traffic —
only certificate metadata.

### 7.6 Two-Way External-Source Sync

External sources are read-only by design (ADR-06). Pushing updates
upstream would require write credentials on the external system and
introduces conflict-resolution problems that specialised certificate
managers already solve.

---

## 8. Planned Breaking Changes (v2.0+)

SemVer requires that breaking changes land in a major release. This
section lists deprecations that will become removals.

### 8.1 Removal of `add_certificate` Permission Fallback

- **Deprecated in:** v1.0.0 (2026-04-16)
- **Removal target:** v2.0.0

Import endpoints currently accept either `import_certificate` (the
custom permission introduced in v0.9) or the legacy `add_certificate`
permission. The legacy fallback will be removed in v2.0.

**Operator action.** Assign `import_certificate` to the appropriate
roles before upgrading to v2.0. See
[permissions reference](https://ctrl-alt-automate.github.io/netbox-ssl/reference/permissions/).

---

## 9. Community Input

### 9.1 Proposing a Feature

Open a GitHub issue using the feature-request template:

https://github.com/ctrl-alt-automate/netbox-ssl/issues/new?template=feature_request.yml

Good feature requests include:

- A concrete use case ("team X needs to do Y")
- Why the existing capabilities are insufficient
- How the proposed feature fits the passive-administration principle
- Optional: a proof-of-concept or adapter stub

### 9.2 Track Record

Past community requests and how they were handled:

| Issue | Topic | Outcome |
|-------|-------|---------|
| #30 | Template packaging | Accepted as bug, fixed in v0.4.2 |
| #47 | Renewal reminders | Accepted as feature, shipped in v0.8 |
| #67 | `snapshot()` TypeError | Accepted as bug, fixed in v0.7.1 |
| #81 | Test refactoring | Accepted as chore, fixed 2026-03-23 |
| #84 | ARI monitoring | Accepted as feature, shipped in v0.9 |
| #85 | Assignment edit save | Accepted as bug, fixed in v0.8.1 |
| #86 | Assignment list FieldError | Accepted as bug, fixed in v0.8.1 |

---

## 10. Post-v2.0 Horizon

Directional bets, not commitments:

- **Compliance-as-code** — policy definitions in a standard format
  (Rego / OPA) rather than per-policy-type rows in a table.
- **Delta-based external-source sync** — most adapters currently fetch
  full lists on every run; incremental sync reduces API quota and
  improves latency.
- **Certificate relationship graph** — a graph-shaped view across the
  inventory (shared SANs, shared CAs, sibling services).
- **First-party integrations with infrastructure-as-code platforms** —
  Terraform data sources for read-only consumption of certificate
  metadata from the plugin.
- **Standalone container deployment** — a lightweight runner that
  presents the plugin as a stand-alone web app for non-NetBox users.
  *(Explicit caveat: this would compete with the NetBox-native
  principle; only pursued if there is clear demand.)*

None of the above is committed. The Horizon section exists for
visibility so that contributors thinking long-term know where the
product might go.
