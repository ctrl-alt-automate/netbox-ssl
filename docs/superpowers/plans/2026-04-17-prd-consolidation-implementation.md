# PRD Consolidation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace two legacy Dutch PRDs with a canonical English `PRD.md` (product charter) and `ROADMAP.md` (forward-looking), archiving the originals under `project-requirement-document/archive/`.

**Architecture:** All work is Markdown in a single directory. Feature branch `chore/prd-consolidation` off `dev`. Commits are logically grouped per deliverable. PR flow mirrors the v1.0 release pattern (CI + Gemini → admin-merge to dev, then dev → main, no tag).

**Tech Stack:** Markdown, `git mv` for history preservation, MkDocs (strict build check only — PRD/ROADMAP stay outside the site).

---

## Spec Reference

This plan implements: `docs/superpowers/specs/2026-04-17-prd-consolidation-design.md`

## File Structure

### Created

```
project-requirement-document/PRD.md                              # Product Charter, ~500 lines
project-requirement-document/ROADMAP.md                          # Forward-looking, ~250 lines
project-requirement-document/archive/README.md                   # ~40 lines
```

### Moved (git mv, history preserved)

```
project-requirement-document/Product Requirements Document.md
    → project-requirement-document/archive/2026-01-17-prd-v1-mvp.md

project-requirement-document/PRD v2 - Roadmap & Next Phases.md
    → project-requirement-document/archive/2026-03-09-prd-v2-roadmap.md
```

### Unchanged

- `docs/` — the MkDocs site stays as-is; the PRD references it
- `README.md`, `CHANGELOG.md`, `COMPATIBILITY.md` — untouched
- Plugin code — untouched

---

## Phase 1 — Archive legacy PRDs

### Task 1: Create archive folder and move legacy PRDs

**Files:**
- Create: `project-requirement-document/archive/README.md`
- Move: legacy PRDs into `archive/`

- [ ] **Step 1: Create archive directory**

```bash
mkdir -p project-requirement-document/archive/
```

- [ ] **Step 2: Move legacy PRDs with git mv (preserves history)**

```bash
git mv "project-requirement-document/Product Requirements Document.md" \
       "project-requirement-document/archive/2026-01-17-prd-v1-mvp.md"

git mv "project-requirement-document/PRD v2 - Roadmap & Next Phases.md" \
       "project-requirement-document/archive/2026-03-09-prd-v2-roadmap.md"
```

- [ ] **Step 3: Verify moves via git status**

Run: `git status`
Expected: two `renamed:` entries, no unmerged content.

- [ ] **Step 4: Write `archive/README.md`**

Exact content (40 lines):

```markdown
# Archived Product Requirements Documents

This folder holds historical PRDs preserved for provenance. **They are out
of date.** For current specification, see:

- [PRD.md](../PRD.md) — canonical product charter
- [ROADMAP.md](../ROADMAP.md) — forward-looking plans

## Index

| File | Date | Role | Status at write time |
|------|------|------|----------------------|
| [2026-01-17-prd-v1-mvp.md](2026-01-17-prd-v1-mvp.md) | 2026-01-17 | MVP scope spec | Pre-implementation (v0.x) |
| [2026-03-09-prd-v2-roadmap.md](2026-03-09-prd-v2-roadmap.md) | 2026-03-09 | Roadmap v0.6 → v1.0 | Mid-implementation |

## Why archive, not delete?

- **Rationale preservation** — architectural decisions are first
  articulated here; the current PRD references them.
- **Historical provenance** — audit questions about decision origin can
  be answered from this folder.
- **Honest evolution** — shows how thinking developed; useful for
  contributors learning why the product looks the way it does.

## Should I read these?

No, unless you need a historical perspective. Current-product content
lives in `PRD.md` or the
[documentation site](https://ctrl-alt-automate.github.io/netbox-ssl/).

Both documents are in Dutch — the original working language of the
project. The canonical `PRD.md` is in English for community accessibility.
```

- [ ] **Step 5: Commit Phase 1**

```bash
git add -A project-requirement-document/
git commit -m "docs: archive legacy PRDs under project-requirement-document/archive/

Move 'Product Requirements Document.md' and 'PRD v2 - Roadmap & Next
Phases.md' into a dated archive/ folder, preserving git history via
git mv. Add archive/README.md pointing readers at the canonical
PRD.md and ROADMAP.md (to be added in subsequent commits)."
```

---

## Phase 2 — Write `PRD.md` (Product Charter)

### Task 2: Write the new product charter

**Files:**
- Create: `project-requirement-document/PRD.md`

Target length: **~500 lines** of Markdown. Charter-style: compact, referential,
authoritative on the *why*. No duplication of content that already lives in
`docs/`.

The charter is written **section by section**. Each sub-task below produces
one section. Commit once after all sections land (Step 11).

- [ ] **Step 1: Write section 1 — Metadata**

At the top of `PRD.md`, add the metadata block:

```markdown
# NetBox SSL — Product Requirements Document

**Project code:** JANUS
**Applies to plugin version:** v1.0.x
**Status:** Canonical — replaces legacy PRDs in `archive/`
**Maintainer:** NetBox SSL team (see `CONTRIBUTING.md`)
**Last updated:** 2026-04-17
**Language:** English (Dutch originals preserved under `archive/`)

> This document is the canonical product specification for NetBox SSL. It
> describes the product as built at v1.0.0 GA, the design principles that
> govern ongoing work, and the architectural decisions behind key trade-offs.
>
> For step-by-step usage and API reference, see the
> [documentation site](https://ctrl-alt-automate.github.io/netbox-ssl/).
> For forward-looking plans, see [ROADMAP.md](ROADMAP.md).

---
```

- [ ] **Step 2: Write section 2 — Executive Summary**

Target: ~200 words. Structure: one paragraph on what it is, one on target
audience, one on what distinguishes it.

Use this opening (verbatim):

```markdown
## 2. Executive Summary

NetBox SSL is a plugin that turns [NetBox](https://github.com/netbox-community/netbox)
into a single source of truth for TLS/SSL certificate inventory. It imports
certificates from PEM, parses every X.509 attribute, links certificates to the
services, devices, and virtual machines that present them, and surfaces
expiry risk before it becomes outage risk.

The product is aimed at infrastructure and security teams already running
NetBox who want certificate visibility without adopting a separate PKI
platform. It is useful for compliance evidence, renewal coordination, and
blast-radius analysis when a CA is deprecated or compromised.

What distinguishes NetBox SSL from alternatives: it is **passive by design**.
It observes and documents; it does not issue, deploy, or rotate certificates.
Private keys are never stored — only public metadata and operator-provided
location hints (e.g., a Vault path). The plugin's value is visibility and
audit trail, deliberately leaving issuance and deployment to the specialised
tooling that already owns those responsibilities.
```

- [ ] **Step 3: Write section 3 — Product Vision & Design Principles**

Target: ~80 lines. Five sub-sections, each ~15 lines:

- 3.1 Passive Administration — quote from legacy PRD v1 §2.2 in English
- 3.2 No Private Keys, Ever — quote the "honeypot" rationale from v1 §3.1.2
- 3.3 Audit Trail Is Sacred — rationale for replace-and-archive from v1 §4.2.1
- 3.4 NetBox-Native — reuse NetBox's auth, permissions, changelog; no standalone DB/UI
- 3.5 Community-First — Apache 2.0, public PyPI, versioned docs, contribution guide

Each sub-section: *principle statement* (1 line, bold) + *why* (1 paragraph) +
*how it manifests* (1 paragraph).

Example for 3.1 (use as template for the others):

```markdown
### 3.1 Passive Administration

**Principle:** NetBox SSL observes and documents the certificate landscape.
It does not issue, deploy, rotate, or revoke certificates.

**Why.** The plugin runs inside the NetBox process. Giving that process the
permissions needed to *act* on certificates (SSH keys for deployment, CA API
credentials, kubeconfig, secrets manager write access) expands NetBox's
blast radius far beyond its intended role as an inventory. Active tools have
different failure modes — stuck renewals, partial deployments, production
outages — and belong in dedicated platforms (Certbot, cert-manager, ACME
clients) that have access control shaped for that work.

**How it manifests.** The plugin has no outbound credentials for CAs or
devices. The only outbound calls are HTTPS reads of certificate metadata
(ACME renewal information, external inventory sources) under shared SSRF
controls. Deployment remains the job of whatever already owned it.
```

- [ ] **Step 4: Write section 4 — Scope**

Target: ~60 lines. Three subsections:

- 4.1 In Scope — table: feature → status (✓ shipped in v1.0)
- 4.2 Out of Scope — table: feature → rationale
- 4.3 Explicit Non-Goals — bulleted list with one-sentence rationale each

Example table for 4.1 (expand with full v1.0 feature set):

```markdown
### 4.1 In Scope

| Capability | Status |
|------------|:------:|
| Smart Paste Import (PEM with private-key rejection) | ✓ v0.1 |
| Multi-target Assignments (Service, Device, VM via GenericForeignKey) | ✓ v0.2 |
| Janus Renewal Workflow (replace & archive, atomic) | ✓ v0.2 |
| Dashboard expiry widget + analytics dashboard | ✓ v0.5, v0.7 |
| Certificate Authority auto-detection | ✓ v0.4 |
| Chain validation (capped depth) | ✓ v0.5 |
| Compliance policies (tag-scoped from v0.9) | ✓ v0.5, v0.9 |
| CSR tracking | ✓ v0.4 |
| ACME certificate monitoring (15+ providers) | ✓ v0.5 |
| Bulk CSV/JSON/PEM import + bulk operations | ✓ v0.5, v0.8 |
| Multi-format export (CSV, JSON, YAML, PEM) | ✓ v0.5 |
| REST API (15+ actions) + GraphQL | ✓ v0.5 |
| Event/webhook integration via NetBox Event Rules | ✓ v0.6 |
| Scheduled expiry scan (idempotent) | ✓ v0.6 |
| Compliance trend charts + export | ✓ v0.7 |
| Certificate topology map | ✓ v0.7 |
| Lifecycle tracking (state transitions + timeline) | ✓ v0.8 |
| Auto-archive of expired certificates | ✓ v0.8 |
| External Source sync (Lemur, Generic REST) | ✓ v0.8 |
| Granular custom permissions | ✓ v0.9 |
| Performance indexes + lazy PEM loading | ✓ v0.9 |
| DER + PKCS#7 import, diff API, scheduled export | ✓ v0.9 |
| Custom fields + tag-based filtering | ✓ v0.9 |
| ARI monitoring (RFC 9773) | ✓ v0.9 |
| Versioned MkDocs Material documentation site | ✓ v1.0 |
| Load testing suite (Locust) | ✓ v1.0 |
```

For 4.2 (Out of Scope), reuse the table from legacy PRD v1 §2.1, translated
to English, with an added *Why* column:

| Capability | Why out of scope |
|------------|------------------|
| Active deployment of keys to servers | Would require SSH/device credentials — violates passive administration |
| Storage of private keys | Creates a honeypot; private key storage belongs in dedicated secrets managers |
| Full PKI management (issuance, CA operations) | Specialised tools exist; NetBox's strength is documentation |
| Active network scanning | Requires outbound credentials and a different trust model |
| CA API integrations (Let's Encrypt client, DigiCert issuance) | Belongs in ACME clients and certificate managers — we sync from them read-only instead |

For 4.3 (Explicit Non-Goals):

- Never become an ACME client (Certbot / acme.sh own this)
- Never broker CA issuance
- Never push TLS config to load balancers or appliances
- Never decrypt TLS traffic
- Never run outbound scans for discovery
- Never store credentials for external systems as plaintext in the database
  (use `env:VAR_NAME` references only)

- [ ] **Step 5: Write section 5 — Architectural Decision Records (ADRs)**

Target: ~200 lines. Seven ADRs. Format for each (~30 lines):

```markdown
### 5.X ADR-0X: <Title>

**Status:** Accepted <YYYY-MM-DD>
**Context.** <1 paragraph — what problem did we face?>
**Decision.** <1 paragraph — what did we decide?>
**Consequences.** <1 paragraph — what changes because of this?>
**Alternatives considered.** <bullet list of 1-3 alternatives with reason they lost>
```

ADRs to include (content source in parens):

- 5.1 ADR-01: Passive over Active (legacy PRD v1 §2.2)
- 5.2 ADR-02: No Private Key Storage (legacy PRD v1 §3.1.2)
- 5.3 ADR-03: Replace & Archive (legacy PRD v1 §4.2.1, docs/explanation/janus-workflow.md)
- 5.4 ADR-04: Chain as Metadata, Not Entities (legacy PRD v1 §3.1.1)
- 5.5 ADR-05: GenericForeignKey for Assignments (legacy PRD v1 §3.2.1)
- 5.6 ADR-06: External Sources as Read-Only Sync (legacy PRD v2 §5.2.5)
- 5.7 ADR-07: Versioned Docs via MkDocs Material + mike (v1.0 implementation; docs/superpowers/specs/2026-04-16-v1.0-ga-release-design.md)

Example ADR (use as template):

```markdown
### 5.2 ADR-02: No Private Key Storage

**Status:** Accepted 2026-01-17. Reaffirmed at v1.0 GA (2026-04-16).

**Context.** Early design raised the option of storing encrypted private keys
alongside certificate metadata, so that NetBox SSL could offer "complete
asset management". Every data field stored in NetBox is accessible to
superusers and, via `.restrict()`, to scoped users. Private keys would make
the NetBox database a concentration of secrets.

**Decision.** The database stores no private keys, encrypted or otherwise.
The parser actively rejects PEM input containing any private-key header.
A free-text `private_key_location` field holds an operator-provided hint
(e.g., `vault://secret/tls/api.example.com`) pointing at the secrets
manager that *does* own the key.

**Consequences.** The NetBox database cannot be used to decrypt traffic,
impersonate endpoints, or forge certificates. The plugin avoids an entire
class of compliance obligations around key management. The trade-off is
that operators must run a separate secrets manager — which they typically
already do.

**Alternatives considered.**
- *Encrypted key storage with per-tenant keys.* Rejected: moves the secret
  one level, doesn't remove it.
- *Write-only API for private keys.* Rejected: still a honeypot from the
  perspective of anyone who compromises the NetBox host.
- *Optional per-install toggle.* Rejected: makes the security story
  conditional and undermines the "never a honeypot" guarantee.
```

- [ ] **Step 6: Write section 6 — Data Model Overview**

Target: ~60 lines. Three subsections:

- 6.1 Core entities (bulleted list with one-line descriptions)
- 6.2 Relationship diagram (Mermaid erDiagram — reuse from `docs/explanation/architecture.md`)
- 6.3 Field-level details (link to `docs/reference/data-models.md`)

Content for 6.1 (list):

```markdown
### 6.1 Core Entities

- **Certificate** — a unique X.509 certificate record; the library item
- **CertificateAssignment** — links a Certificate to a target via
  GenericForeignKey (Service, Device, VirtualMachine)
- **CertificateAuthority** — issuing CA record, with auto-detection from
  the issuer string
- **CertificateSigningRequest** — tracked CSR, optionally linked to the
  Certificate it produced
- **CertificateLifecycleEvent** — append-only log of status transitions,
  renewals, assignment changes
- **CertificateEventLog** — idempotency tracker for the expiry scan
  (prevents duplicate events within a cooldown window)
- **CompliancePolicy** / **ComplianceResult** — per-policy checks and
  their historical outcomes
- **ExternalSource** / **ExternalSourceSyncLog** — read-only sync to
  third-party certificate managers
```

For 6.2, paste the erDiagram block from `docs/explanation/architecture.md`
verbatim so the PRD is self-contained on domain structure.

For 6.3, a single line: `See [data models reference](https://ctrl-alt-automate.github.io/netbox-ssl/reference/data-models/) for field-level definitions.`

- [ ] **Step 7: Write section 7 — Core Workflows**

Target: ~60 lines. Five subsections, each ~10 lines:

- 7.1 Smart Paste Import — one paragraph summary + link to tutorial 01
- 7.2 Janus Renewal — one paragraph summary + link to tutorial 02
- 7.3 Expiry Monitoring — one paragraph summary + link to tutorial 03
- 7.4 External Source Sync — one paragraph summary + link to how-to
- 7.5 Bulk Operations — one paragraph summary + link to how-to

Example for 7.1:

```markdown
### 7.1 Smart Paste Import

Operator pastes raw PEM into a single text area. The backend rejects any
input containing a private key header, then uses the Python `cryptography`
library to extract CN, SANs, validity window, issuer, fingerprint,
algorithm, and key size. Duplicate detection is by `serial_number + issuer`.
Parsed metadata is presented in a preview before the record is created.

→ [Tutorial: Your First Certificate Import](https://ctrl-alt-automate.github.io/netbox-ssl/tutorials/01-first-import/)
```

- [ ] **Step 8: Write section 8 — Non-Functional Requirements**

Target: ~80 lines. Five subsections:

- 8.1 Security — list the layered controls (private-key rejection, PEM
  size cap, SSRF guards, permission model, CSV injection prevention,
  credential pattern `env:VAR_NAME`)
- 8.2 Performance — target SLOs (list p50/p95/p99 from load-testing doc),
  database indexes (9 indexes on Certificate in v0.9), lazy PEM loading
- 8.3 Compatibility — NetBox 4.4 & 4.5, Python 3.10–3.12, macOS/Linux
  dev environments
- 8.4 Observability — NetBox Event Rules, scheduled scan idempotency,
  structured lifecycle log
- 8.5 Deployability — pure `pip install`, no external services required,
  works within standard NetBox plugin loading

- [ ] **Step 9: Write section 9 — Success Metrics**

Target: ~40 lines. Table format:

```markdown
### 9.1 Adoption

| Metric | Current | Target |
|--------|---------|--------|
| PyPI package published | ✓ | — |
| PyPI downloads/month | Track post-v1.0 | >500 within 12 months |
| GitHub stars | Track | >50 within 12 months |
| GitHub forks | Track | >10 within 12 months |

### 9.2 Quality

| Metric | Current | Target |
|--------|---------|--------|
| Unit test coverage on utils | 72% | >= 70% gate |
| Integration tests in CI | ✓ (v4.4 + v4.5) | — |
| Bandit findings (high/medium) | 0 | 0 |
| Known CVEs in deps | 0 | 0 |
| Security review checklist | ✓ | Living |

### 9.3 Release cadence

| Metric | Current | Target |
|--------|---------|--------|
| Semver adherence | ✓ | — |
| CHANGELOG entries per release | ✓ | — |
| Time-to-patch a security issue | TBD | <= 14 days for high severity |

### 9.4 Community

| Metric | Current | Target |
|--------|---------|--------|
| External contributors | Tracked | >3 within 12 months |
| Issue turnaround (median) | Tracked | <= 5 business days |
| Labelled issues (good-first-issue) | ✓ | Keep >= 3 open |
```

- [ ] **Step 10: Write section 10 — Document Governance**

Target: ~40 lines. Three subsections:

```markdown
## 10. Document Governance

### 10.1 Update Triggers

| Trigger | Action |
|---------|--------|
| New minor release (v1.1, v1.2, …) | Review PRD: any ADR added? scope change? |
| New major release (v2.0, …) | Full review + version bump in metadata |
| New architectural decision | Add ADR to §5 + CHANGELOG entry |
| Docs site restructure | Update links in §6 and §7 |

### 10.2 Version Field Convention

The "Applies to plugin version" field in the metadata block tracks the
plugin version. No separate PRD semver — single source of truth is the
plugin version. "Last updated" is manually maintained.

### 10.3 Relationship to Other Documents

```
PRD.md (stable)           → why + principles + ADRs
ROADMAP.md (living)       → what comes next
CHANGELOG.md (append)     → what has shipped
docs/ (MkDocs site)       → how to use it
docs/superpowers/specs/   → brainstorm artefacts
```

Each layer has one purpose; overlap is the exception.

### 10.4 Document Changelog

| Date | Change |
|------|--------|
| 2026-04-17 | Initial consolidation from legacy PRDs v1.1 and v2.0 (now in `archive/`) |
```

- [ ] **Step 11: Final build and structural check**

Run: `wc -l project-requirement-document/PRD.md`
Expected: 400–600 lines (not a hard limit, just sanity).

Run: `grep -n "TBD\|TODO\|XXX" project-requirement-document/PRD.md`
Expected: empty output (no placeholders). Fix any hits before committing.

- [ ] **Step 12: Commit Phase 2**

```bash
git add project-requirement-document/PRD.md
git commit -m "docs: add canonical PRD.md (product charter)

Introduce a consolidated, English, charter-style Product Requirements
Document under project-requirement-document/PRD.md. The document
describes NetBox SSL v1.0 as-built, using Architecture Decision Records
(§5) as the authoritative log of design choices. Implementation details
are referenced to the docs site (ctrl-alt-automate.github.io/netbox-ssl)
rather than duplicated.

Legacy PRDs (v1.1 and v2.0, Dutch) are preserved under archive/ from
the previous commit."
```

---

## Phase 3 — Write `ROADMAP.md` (forward-looking)

### Task 3: Write the roadmap document

**Files:**
- Create: `project-requirement-document/ROADMAP.md`

Target length: **~250 lines**. Living document, Now/Next/Later/Deferred/Rejected
taxonomy. Populated at v1.0 ship.

- [ ] **Step 1: Write metadata + reading guide (§1 + §2)**

```markdown
# NetBox SSL — Roadmap

**Status:** Living document
**Last reviewed:** 2026-04-17
**Plugin version at publication:** v1.0.0
**Owner:** NetBox SSL team (see `CONTRIBUTING.md`)

> This roadmap sketches what *may* come after v1.0.0. It is deliberately
> vague on timing: a solo or small-team project misses hard dates more
> often than it hits them, and Now/Next/Later is an honest taxonomy.
>
> For current product specification, see [PRD.md](PRD.md). For shipped
> work, see [CHANGELOG.md](../CHANGELOG.md).

---

## 2. How to Read This Roadmap

No hard dates. Items live in one of five buckets:

| Bucket | Meaning | Matches GitHub Milestone? |
|--------|---------|---------------------------|
| **Now** | In active development | Open milestone |
| **Next** | Committed, scoped, not yet started | Backlog with label |
| **Later** | Under consideration | Open issue, no milestone |
| **Deferred** | Considered, not pursued for now | Closed as "wontfix for v1.x" |
| **Rejected** | Actively not building, with rationale | Closed with the reasoning preserved |

Items move between buckets as priorities shift. A feature in Later may
become Next (or Rejected), never "missed deadline" — only "different
priority now".
```

- [ ] **Step 2: Write Now (§3) — empty at ship**

```markdown
## 3. Now — In Active Development

*Empty at v1.0.0 ship. Items appear here when an issue is assigned a
milestone and work has started.*
```

- [ ] **Step 3: Write Next (§4) — initial candidates**

Populate with three concrete v1.1 candidates:

```markdown
## 4. Next — Committed, Scoped, Not Yet Started

### 4.1 Vault Read-Only Integration

**Goal:** Resolve `private_key_location` breadcrumbs against a HashiCorp
Vault instance to confirm the key is where it claims to be, without
retrieving the key material itself.

**Scope boundary.** We only `HEAD`-check (or list-check) the path. The
plugin never reads key contents, even if Vault permissions would allow
it — enforced in code, mirroring the PEM parser's private-key rejection.

**Reference issue.** To be filed.

### 4.2 DigiCert CertCentral Adapter

**Goal:** Add a first-party External Source adapter for DigiCert
CertCentral. Reads certificate metadata only, never private keys.

**Scope boundary.** Same as the existing Lemur adapter: read-only,
HTTPS-only, `env:VAR_NAME` credentials, no redirect following.

**Reference issue.** To be filed.

### 4.3 Performance Scaling Pass (> 10k Certificates)

**Goal:** Validate and tune plugin behaviour at 10,000 and 50,000
certificates. Profile slow queries, tune index usage, add benchmark
assertions to CI.

**Scope boundary.** No architectural changes — this is tuning, not
redesign. If a redesign turns out to be needed, it gets promoted to
a design spec and a separate plan.

**Reference issue.** To be filed.
```

- [ ] **Step 4: Write Later (§5) — 6 items from legacy v2 §8 + additions**

Pull content from the legacy PRD v2 §8 table and translate to English:

```markdown
## 5. Later — Under Consideration

### 5.1 Git-backed Audit Trail

Export certificate state to a Git repository for version control outside
NetBox. Fits the passive philosophy (read-only export, no active control).

### 5.2 CT Log Monitoring

Use Certificate Transparency logs to detect certificates issued for the
organisation's domains outside the tracked inventory. Passive monitoring
of public data — aligns with the principle.

### 5.3 SLA Tracking

Define SLAs per tenant or CA ("renewal must land within X days of
warning"). Purely administrative — tracks the human workflow, does not
automate it.

### 5.4 AWS ACM Read-Only Adapter

External Source adapter for AWS Certificate Manager. Read-only via
`list-certificates` / `describe-certificate`. Private keys never fetched,
even when IAM permissions would allow.

### 5.5 Azure Key Vault Read-Only Adapter

External Source adapter for Azure Key Vault certificates. Public metadata
only.

### 5.6 Scan Result Ingestion

Import output from `nmap`, `sslyze`, or similar passive scanners. Dedupes
against the existing inventory and flags discrepancies.

### 5.7 Multi-Language Docs

Dutch translation of the docs site (currently English only). Possibly
other languages if contributors step up. The PRD itself likely stays
English as the canonical reference.
```

- [ ] **Step 5: Write Deferred (§6)**

```markdown
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
inside NetBox. Provides marginal value over the external-source
metadata sync already in place, at the cost of significant UI complexity.
```

- [ ] **Step 6: Write Rejected (§7)**

```markdown
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
(Ansible, Salt, Terraform, custom CI) owns this, and their access
model is built for it.

### 7.4 Active Network Scanning

Running outbound scans to discover certificates conflicts with passive
administration and introduces false-positive risk. Passive ingestion
from an existing scanner's output (see §5.6) is the correct pattern.

### 7.5 TLS Traffic Inspection or MitM

Categorically out of scope. The plugin never handles traffic, only
metadata.
```

- [ ] **Step 7: Write Planned Breaking Changes (§8)**

```markdown
## 8. Planned Breaking Changes (v2.0+)

SemVer requires that breaking changes land in a major release. This
section lists deprecations that will become removals.

### 8.1 Removal of `add_certificate` Permission Fallback

**Deprecated in:** v1.0.0 (2026-04-16)
**Removal target:** v2.0.0

Import endpoints currently accept either `import_certificate` (the new
custom permission introduced in v0.9) or the legacy `add_certificate`
permission. The legacy fallback will be removed in v2.0.

**Operator action.** Assign `import_certificate` to the appropriate
roles before upgrading to v2.0. See
[permissions reference](https://ctrl-alt-automate.github.io/netbox-ssl/reference/permissions/).
```

- [ ] **Step 8: Write Community Input (§9) + Post-v2.0 Horizon (§10)**

```markdown
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

- `#67` (snapshot TypeError) — accepted as bug, fixed in v0.7.1
- `#47` (renewal reminders) — accepted as feature, shipped in v0.8
- `#84` (ARI monitoring) — accepted as feature, shipped in v0.9
- `#30` (template packaging) — accepted as bug, fixed in v0.4.2

---

## 10. Post-v2.0 Horizon

Directional bets, not commitments:

- **Graph-shaped inventory view** — beyond the tree-shaped topology,
  show certificate relationships as a graph (shared SANs, shared CAs,
  sibling services)
- **Compliance-as-code** — policy definitions in a standard format
  (Rego? OPA?) rather than per-policy-type rows in a table
- **Delta-based external-source sync** — most adapters currently fetch
  full lists; incremental sync reduces API quota and improves latency
- **Per-tenant alerting policies** — different expiry thresholds and
  notification channels for different parts of the organisation

None of the above is committed. The Horizon section exists for visibility
so that contributors thinking long-term know where the product might go.
```

- [ ] **Step 9: Verify no placeholders**

Run: `grep -n "TBD\|TODO\|XXX" project-requirement-document/ROADMAP.md`
Expected: two hits — both in Next section as "Reference issue. To be filed."
These are acceptable because they accurately describe pending work.

Run: `wc -l project-requirement-document/ROADMAP.md`
Expected: 200–300 lines.

- [ ] **Step 10: Commit Phase 3**

```bash
git add project-requirement-document/ROADMAP.md
git commit -m "docs: add ROADMAP.md forward-looking plan

Introduce a Now/Next/Later/Deferred/Rejected roadmap structure for
post-v1.0 work. Populated with three committed candidates (Vault
integration, DigiCert adapter, performance scaling pass), seven Later
items drawn from the legacy PRD v2 §8, and explicit Deferred/Rejected
sections that preserve the rationale for items the plugin will not
pursue."
```

---

## Phase 4 — Verification and quality gates

### Task 4: Run local quality checks

**Files:**
- (Read-only — verification only)

- [ ] **Step 1: Ruff + bandit (should be unchanged since we touched no Python)**

```bash
ruff check netbox_ssl/ tests/
ruff format --check netbox_ssl/ tests/
```

Expected: clean (no Python files were modified).

- [ ] **Step 2: MkDocs strict build still passes**

```bash
.venv-docs/bin/mkdocs build --strict 2>&1 | tail -3
```

Expected: "Documentation built in N seconds" with no warnings.

Rationale: the PRD/ROADMAP live outside `docs/` so they are not picked
up by MkDocs. The strict build must still pass — this confirms we
did not accidentally introduce a broken reference.

- [ ] **Step 3: Verify no in-repo references to the old PRD paths**

Run: `grep -rln "Product Requirements Document.md\|PRD v2 - Roadmap" . --exclude-dir=.git --exclude-dir=.venv-docs --exclude-dir=archive --exclude-dir=node_modules`
Expected: matches only in spec + plan files (`docs/superpowers/`).

Rationale: if any doc (README, contributing, etc.) still points at the
old paths, it breaks after the archive move. This grep surfaces them.

- [ ] **Step 4: Git log sanity check**

```bash
git log --oneline dev..HEAD
```

Expected (in order): Phase 1 commit, Phase 2 commit, Phase 3 commit.
Three logical commits total.

---

## Phase 5 — PR #1 (chore/prd-consolidation → dev)

### Task 5: Push branch and open PR

**Files:**
- (Remote actions only)

- [ ] **Step 1: Push branch**

```bash
git push -u origin chore/prd-consolidation
```

Expected: push succeeds, branch exists on GitHub.

- [ ] **Step 2: Open PR with detailed body**

```bash
gh pr create \
  --base dev \
  --head chore/prd-consolidation \
  --title "docs: consolidate legacy PRDs into canonical PRD.md + ROADMAP.md" \
  --body "$(cat <<'EOF'
## Summary

Replaces the two Dutch legacy PRDs in \`project-requirement-document/\`
with a canonical English product charter (\`PRD.md\`) and a living
forward-looking roadmap (\`ROADMAP.md\`). Originals are preserved under
\`archive/\` via \`git mv\` (history retained).

### What changed

- **New:** \`project-requirement-document/PRD.md\` — ~500-line charter-
  style PRD; ADR-based decision log; references docs site for detail
- **New:** \`project-requirement-document/ROADMAP.md\` — Now/Next/Later/
  Deferred/Rejected taxonomy; 3 committed Next items, 7 Later items,
  explicit Rejected list preserving rationale
- **New:** \`project-requirement-document/archive/README.md\` explaining
  why the legacy PRDs remain visible but non-authoritative
- **Moved:** \`Product Requirements Document.md\` →
  \`archive/2026-01-17-prd-v1-mvp.md\`
- **Moved:** \`PRD v2 - Roadmap & Next Phases.md\` →
  \`archive/2026-03-09-prd-v2-roadmap.md\`

### Why

Both legacy PRDs described planned work that has now shipped as v1.0.0.
A new reader could not distinguish planned from shipped content. The
canonical PRD describes the product as-built; the roadmap describes what
comes next. Archival preserves the original reasoning (useful for
audit provenance and contributor onboarding).

### Test plan

- [x] \`mkdocs build --strict\` clean (PRD and ROADMAP live outside the
      docs site, so no site impact)
- [x] \`ruff check\` clean (no Python changes)
- [x] \`grep\` for old filenames clean (no lingering references)
- [ ] CI green (lint, unit-tests, integration v4.4 + v4.5)
- [ ] Gemini code review addressed

### Spec artefacts

- Design: \`docs/superpowers/specs/2026-04-17-prd-consolidation-design.md\`
- Plan: \`docs/superpowers/plans/2026-04-17-prd-consolidation-implementation.md\`

### Post-merge actions

1. Merge this PR to \`dev\` with \`--admin --squash\` after CI + Gemini
2. Open PR \`dev → main\`, admin-merge after CI
3. **No tag, no PyPI publish** — documentation-only change; the next
   plugin release will pick these up from main naturally
EOF
)"
```

Expected: outputs the PR URL. Save it for subsequent steps.

### Task 6: Monitor CI on PR #1

- [ ] **Step 1: Watch CI to completion**

```bash
gh pr checks <N> --watch --interval 30
```

Expected: all 10 checks pass (lint, unit-tests 3.10/3.11/3.12, package-
check, build, integration v4.4 + v4.5, Playwright E2E, strict mkdocs).

### Task 7: Address Gemini code review

- [ ] **Step 1: Read the Gemini review**

```bash
gh pr view <N> --json reviews | jq -r '.reviews[] | select(.author.login == "gemini-code-assist") | .body'
gh api repos/ctrl-alt-automate/netbox-ssl/pulls/<N>/comments | jq -r '.[] | {path, line, body: .body[:300]}'
```

- [ ] **Step 2: Classify findings**

- *Serious* (fix before merge): factual error, contradiction with shipped
  behaviour, broken link, mis-attributed ADR
- *Minor* (fix if cheap; otherwise note in PR comment): phrasing,
  structural suggestion, stylistic preference

- [ ] **Step 3: Apply fixes if any**

For each serious finding:

```bash
# make the fix
git add project-requirement-document/...
git commit -m "fix: <gemini-finding-summary> (gemini review)"
git push
```

- [ ] **Step 4: Reply to review**

```bash
gh pr comment <N> --body "Thanks for the review. Addressed serious findings in <commit-shas>."
```

### Task 8: Admin-merge PR #1

- [ ] **Step 1: Final verification**

```bash
gh pr checks <N>           # expect all green
gh pr view <N> --json reviews  # expect Gemini COMMENTED
```

- [ ] **Step 2: Admin-merge with squash**

```bash
gh pr merge <N> --admin --squash --delete-branch
```

Expected: PR merged, branch deleted, CI on `dev` triggered.

- [ ] **Step 3: Sync local dev**

```bash
git checkout dev
git pull
```

---

## Phase 6 — PR #2 (dev → main)

### Task 9: Open PR #2

- [ ] **Step 1: Create PR**

```bash
gh pr create \
  --base main \
  --head dev \
  --title "docs: PRD consolidation for post-v1.0" \
  --body "$(cat <<'EOF'
Promotes the PRD consolidation (PR #<prev-N>) from \`dev\` to \`main\`.

Documentation-only change. No code, no migrations, no release bump. The
next plugin release will pick these up automatically.

### What's in this promotion

- Canonical \`PRD.md\` replacing the two legacy Dutch PRDs
- Forward-looking \`ROADMAP.md\`
- Archived originals under \`project-requirement-document/archive/\`
EOF
)"
```

### Task 10: Monitor + admin-merge PR #2

- [ ] **Step 1: Watch CI**

```bash
gh pr checks <N> --watch --interval 30
```

- [ ] **Step 2: Admin-merge**

```bash
gh pr merge <N> --admin --merge
```

Use `--merge` (not `--squash`) for dev→main so individual logical
commits stay visible on `main`'s history.

- [ ] **Step 3: Sync local main**

```bash
git checkout main
git pull
```

---

## Phase 7 — Post-merge

### Task 11: Update MEMORY.md

**Files:**
- Modify: `~/.claude/projects/<encoded-project-path>/memory/MEMORY.md`
  (the Claude Code auto-memory file for this project; its exact path is
  environment-dependent)

- [ ] **Step 1: Append PRD consolidation entry under Release History (or
    add a new "Documentation Milestones" section if the user prefers)**

Add entry:

```markdown
- 2026-04-17 — PRD consolidation: legacy v1.1 + v2.0 PRDs archived,
  canonical English PRD.md + forward-looking ROADMAP.md added under
  project-requirement-document/. No code changes; no release bump.
```

### Task 12: Final report

- [ ] **Step 1: Assemble status summary**

Include:

- Commit SHA on main
- PR URLs (PR #1, PR #2)
- Files added / renamed / removed
- Confirmation that no tag or PyPI publish was performed

- [ ] **Step 2: Report to user**

Short summary: "PRD consolidation landed. New canonical PRD.md and
ROADMAP.md live in project-requirement-document/; legacy PRDs in
archive/. No code changes, no release."

---

## Self-review checklist

- [x] **Spec coverage** — every section of the design spec maps to at
      least one task:
    - §1 (Problem) / §2 (Goals) / §3 (Deliverables) → covered by task
      structure overall
    - §4 (PRD.md ToC) → Task 2, steps 1–11
    - §5 (ROADMAP.md ToC) → Task 3, steps 1–10
    - §6 (Archival approach) → Task 1
    - §7 (Maintenance and governance) → included as §10 of PRD + §2 of
      roadmap reading guide
    - §8 (Execution flow) → Phases 5–7
    - §9 (Out-of-band notes) → reflected in task commits and PR body
- [x] **Placeholder scan** — no "TBD/TODO/XXX" in plan prose. The
      "Reference issue. To be filed." in ROADMAP §4 is intentional and
      described as acceptable in the verification task.
- [x] **Type consistency** — filenames, section numbers, and paths match
      across tasks.
- [x] **TDD** — docs-only work; verification is `mkdocs build --strict`
      and a grep sweep. No test-first flow is needed.
- [x] **Commit cadence** — one commit per phase (three total) plus any
      Gemini-fix commits; small and reviewable.
- [x] **Irreversibility** — no tag, no PyPI publish. Rollback is `git
      revert` on a documentation commit, cost near zero.
