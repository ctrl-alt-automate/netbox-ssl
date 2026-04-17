# PRD Consolidation — Design Spec

**Date:** 2026-04-17
**Author:** Elvis (via Claude Opus 4.7 brainstorm session)
**Status:** Approved — ready for implementation
**Context:** Post v1.0.0 GA release — consolidating legacy PRDs into an
up-to-date canonical product charter + forward-looking roadmap.

## 1. Problem

`project-requirement-document/` holds two PRDs:

- `Product Requirements Document.md` (2026-01-17, 206 lines) — MVP spec,
  written pre-implementation
- `PRD v2 - Roadmap & Next Phases.md` (2026-03-09, 485 lines) — roadmap
  covering v0.6 → v1.0, written mid-implementation

Both were written before v1.0.0 shipped (2026-04-16). Every feature in both
documents is now implemented. The PRDs are technically out of date the
moment the reader opens them: they describe future work that is already
past work.

Symptoms:

- A newcomer reading the PRDs cannot tell what is planned vs. shipped
- Architectural decisions (no private keys, replace-and-archive, passive
  administration) are scattered across both documents
- Post-v1.0 ideas live in a single section (PRD v2 §8) rather than a
  first-class roadmap
- Both documents are in Dutch while the rest of the repo (README, CHANGELOG,
  docs site, commits) is in English

## 2. Goals and non-goals

### In scope

- Consolidate the two PRDs into **one canonical product charter** (`PRD.md`)
  that describes NetBox SSL v1.0 as-built — principles, scope, architectural
  decisions, data model overview, core workflows, non-functional requirements
- Extract forward-looking content into a **separate roadmap**
  (`ROADMAP.md`) using a Now / Next / Later / Deferred / Rejected taxonomy
- **Archive** the two legacy PRDs under
  `project-requirement-document/archive/` with a README explaining why they
  remain visible but are no longer authoritative
- Write in **English** to match repo conventions

### Out of scope

- Rewriting the documentation site (`docs/`) — the charter links to it,
  does not duplicate it
- Content changes to `README.md`, `CHANGELOG.md`, `COMPATIBILITY.md`
- Plugin code changes
- Publishing the PRD/roadmap on PyPI or the docs site (stays as repo files)
- Non-English translations (may follow later as `PRD.nl.md` if needed)

## 3. Deliverables

```
project-requirement-document/
├── PRD.md                              # NEW — Product Charter (~350-500 lines)
├── ROADMAP.md                          # NEW — Post-v1.0 roadmap (~200-300 lines)
├── archive/                            # NEW — historical source documents
│   ├── README.md                       # why this folder exists
│   ├── 2026-01-17-prd-v1-mvp.md       # renamed: "Product Requirements Document.md"
│   └── 2026-03-09-prd-v2-roadmap.md   # renamed: "PRD v2 - Roadmap & Next Phases.md"
```

## 4. `PRD.md` — Product Charter structure

Charter-style: compact, referential, authoritative on "why" rather than
"how". Implementation details live in the docs site
(`docs/reference/`, `docs/explanation/`). The PRD references, never
duplicates.

### Table of contents

1. **Metadata**
   - Version / status / maintainer / last-updated
   - Relationship to legacy PRDs (link to `archive/`)

2. **Executive Summary** (~200 words)
   - What NetBox SSL is in one paragraph
   - Target audience
   - What distinguishes it from alternatives

3. **Product Vision & Design Principles**
   - 3.1 Passive Administration
   - 3.2 No Private Keys, Ever
   - 3.3 Audit Trail Is Sacred
   - 3.4 NetBox-Native (no standalone UI or database)
   - 3.5 Community-First

4. **Scope**
   - 4.1 In Scope (feature table)
   - 4.2 Out of Scope (feature table with rationale)
   - 4.3 Explicit Non-Goals (ACME client, CT monitoring, device push, …)

5. **Architectural Decisions (ADR log)**
   - 5.1 ADR-01: Passive over Active
   - 5.2 ADR-02: No Private Key Storage
   - 5.3 ADR-03: Replace & Archive (Janus Workflow)
   - 5.4 ADR-04: Chain as Metadata, Not Entities
   - 5.5 ADR-05: GenericForeignKey for Assignments
   - 5.6 ADR-06: External Sources as Read-Only Sync
   - 5.7 ADR-07: Versioned Docs via MkDocs Material + mike
   - Each ADR: ~40–80 lines. Format: *Context* / *Decision* /
     *Consequences* / *Alternatives considered* / *Status*

6. **Data Model Overview**
   - 6.1 Core entities (Certificate, CertificateAssignment,
     CertificateAuthority, ExternalSource, CertificateLifecycleEvent, …)
   - 6.2 Relationship diagram (compact Mermaid) or explicit link to
     `docs/explanation/architecture.md`
   - 6.3 Field-level details → link to `docs/reference/data-models.md`

7. **Core Workflows**
   - 7.1 Smart Paste Import (summary, link to tutorial 01)
   - 7.2 Janus Renewal (summary, link to tutorial 02)
   - 7.3 Expiry Monitoring (summary, link to tutorial 03)
   - 7.4 External Source Sync (summary, link to how-to)
   - 7.5 Bulk Operations (summary, link to how-to)

8. **Non-Functional Requirements**
   - 8.1 Security (private-key rejection, SSRF guards, permission model,
     CSV injection prevention)
   - 8.2 Performance (target SLOs, indexes, lazy loading)
   - 8.3 Compatibility (NetBox N / N-1, Python 3.10–3.12)
   - 8.4 Observability (events, webhooks, logging)
   - 8.5 Deployability (pip install; no external services required)

9. **Success Metrics**
   - 9.1 Adoption (PyPI downloads, GitHub stars)
   - 9.2 Quality (test coverage, security findings, CVE count)
   - 9.3 Release cadence (semver adherence, time-to-patch)
   - 9.4 Community (contributors, issue turnaround)

10. **Document Governance**
    - How and when this PRD is updated
    - Change log of the PRD itself
    - Relationship to `ROADMAP.md`

### Content NOT in the PRD (lives in docs)

- Step-by-step installation / configuration → `docs/operations/`
- API endpoint reference → `docs/reference/api.md`
- Field-level schema → `docs/reference/data-models.md`
- Contributor patterns → `docs/development/contributing.md`

### Why the ADR section is central

The legacy PRDs scattered architectural decisions across prose in v1 and
inline decisions in v2 roadmap sections. Grouping them as discrete ADRs
makes the PRD a referenceable document ("see ADR-03") rather than a
narrative. ADR-style sections are also easier to audit and to extend as
new decisions land.

## 5. `ROADMAP.md` — Forward-looking structure

Living document, updated more often than `PRD.md`. Format oriented towards
maintainer-level upkeep — no hard dates, explicit status taxonomy.

### Table of contents

1. **Metadata**
   - Status: Living document
   - Last-reviewed date
   - Approval / update process

2. **How to Read This Roadmap**
   - Disclaimer: no hard dates
   - Status taxonomy (Now / Next / Later / Deferred / Rejected)
   - Relationship to GitHub Milestones

3. **Now — In Active Development**
   - Items with an open issue and assigned milestone
   - Empty at v1.0.0 ship (or contains small v1.0.x polish items)

4. **Next — Committed, Scoped, Not Yet Started**
   - v1.1 candidates, each with goal / scope boundaries / reference issue

5. **Later — Under Consideration**
   - Ideas from legacy PRD v2 §8
   - Community-suggested features tagged "maybe"
   - Not locked in — can be promoted to Next or rejected

6. **Deferred — Considered, Not Pursued For Now**
   - Explicitly rejected for v1.x, may revisit for v2.0
   - E.g., multi-instance sync (complexity)

7. **Rejected — Actively Not Building**
   - Permanently out-of-scope with rationale
   - E.g., active ACME client (violates passive administration)
   - E.g., private key storage (violates no-honeypot principle)

8. **Planned Breaking Changes (v2.0+)**
   - `add_certificate` permission fallback removal (deprecated v1.0)
   - Future deprecations
   - Timeline expressed in releases, not dates

9. **Community Input**
   - How to propose a feature (GitHub issue link)
   - Feature request justification template
   - Historical track record (proposals → accepted / deferred)

10. **Post-v2.0 Horizon**
    - Big directional bets, still vague
    - Not for commitment, only for visibility

### Populated state at v1.0.0 ship

| Section | Initial contents |
|---------|------------------|
| Now | Empty (v1.0.0 just shipped) |
| Next | DigiCert adapter, Vault integration, performance scaling |
| Later | 6 items from legacy PRD v2 §8 + community wishes |
| Deferred | Historical "never built" items (multi-instance sync) |
| Rejected | Fundamental no-goes (active ACME deployment, key storage) |
| Breaking Changes | `add_certificate` fallback removal in v2.0 |

### Why Now / Next / Later instead of release-based

- **Honest** — as a solo/small team you miss release dates. "v1.1 in Q3"
  becomes a stale promise; "Next" stays true
- **Easy to update** — items move between columns as priorities shift
- **No reputational damage** — deferring a Later item does not feel like
  slippage; un-shipping a "v1.1 feature" does
- **Matches GitHub Milestones** — Now = assigned milestone, Next = backlog
  with label, Later = open but no milestone

The explicit **Rejected** section is especially important: it prevents the
recurring "have you considered X?" conversation by making the reasoning
visible up front, while still inviting rebuttal ("convince us this is
different now").

## 6. Archival approach

### Steps

```bash
mkdir -p project-requirement-document/archive/

git mv "project-requirement-document/Product Requirements Document.md" \
       "project-requirement-document/archive/2026-01-17-prd-v1-mvp.md"

git mv "project-requirement-document/PRD v2 - Roadmap & Next Phases.md" \
       "project-requirement-document/archive/2026-03-09-prd-v2-roadmap.md"

# Then write archive/README.md
```

### `archive/README.md` content (~40 lines)

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
  articulated here; the current PRD references them
- **Historical provenance** — audit questions about decision origin can be
  answered from this folder
- **Honest evolution** — shows how thinking developed; useful for
  contributors learning "why the product looks the way it does"

## Should I read these?

No, unless you need a historical perspective. Current-product content
lives in `PRD.md` or the
[documentation site](https://ctrl-alt-automate.github.io/netbox-ssl/).
```

### Naming rationale

- **Folder `archive/`** supplies the "these are old" context, removing the
  need for `_ARCHIVED` suffixes on filenames
- **`YYYY-MM-DD-<slug>.md`** makes chronological order explicit in
  directory listings
- **Keeping them in repo** (not moved to a branch/external location) means
  `ls` shows them to anyone exploring the folder

## 7. Maintenance and governance

### `PRD.md`

| Trigger | Action | Owner |
|---------|--------|-------|
| New minor release (v1.1, v1.2, …) | Review PRD: new ADRs? scope change? | Maintainer |
| New major release (v2.0, …) | Full review + version bump in metadata | Maintainer |
| Breaking architectural decision | Add new ADR + CHANGELOG entry | Author of the change |
| Docs site restructure | Update links in §6 and §7 | Maintainer |

- **Version field** in `PRD.md` metadata tracks plugin version
  (`PRD applies to: v1.0.x`)
- **No separate PRD semver** — single source of truth is plugin version
- **"Last updated" date** in metadata, manually updated with each change
- **Document changelog** (ToC §10) lists PRD revisions:
  `2026-04-17: Initial consolidation from v1 + v2 PRDs`

### `ROADMAP.md`

| Trigger | Action | Owner |
|---------|--------|-------|
| Start of a release cycle | Move items Later → Next | Maintainer |
| Item merged as feature | Remove from Now, log in CHANGELOG | Maintainer |
| Community feature request | Triage → Now / Next / Later / Deferred / Rejected | Maintainer |
| Annual review (every April) | Prune stale Later / Deferred items | Maintainer |

- **No dates promised** — only "Now = in current release cycle"
- **Each section sorted by priority**, highest urgency first
- **Issue links mandatory** for items in Now (no tracking otherwise)

### Future design-level brainstorms

- Individual design specs continue to live in `docs/superpowers/specs/`
  (the default brainstorming output location)
- Large new features: spec in `docs/superpowers/specs/` →
  summary entry in `ROADMAP.md` → after ship: ADR in `PRD.md` and
  feature doc in `docs/`
- A hypothetical "PRD v3" is only warranted by a fundamental re-scope
  (major rewrite, rename, pivot). In that case: archive current `PRD.md`
  under `archive/` and write a new `PRD.md`

### Document relationship

```
PRD.md (stable)           → why + principles + ADRs
ROADMAP.md (living)       → what comes next
CHANGELOG.md (append)     → what has shipped
docs/ (MkDocs site)       → how to use it
docs/superpowers/specs/   → brainstorm artefacts
```

Each layer has one purpose; overlap is the exception, not the rule.

## 8. Execution flow

### Phase A — Local work (autonomous)

1. Create feature branch `chore/prd-consolidation` from `dev`
2. Archive legacy PRDs via `git mv` + write `archive/README.md`
3. Write `PRD.md` following the ToC in §4
4. Write `ROADMAP.md` following the ToC in §5
5. Commit logically (e.g., one commit per deliverable)

### Phase B — PR to dev

1. Push branch, open PR against `dev`
2. Wait for CI green + Gemini review
3. Address findings, admin-merge with `--squash`

### Phase C — PR to main

1. Open PR `dev → main`
2. Wait for CI + Gemini
3. Admin-merge with `--merge`

No tag or PyPI publish — PRD/roadmap changes do not warrant a release
bump. The next release that touches plugin code will include these docs
by virtue of `main` being the release source.

### Phase D — Post-merge

1. Delete the feature branch
2. Record change in `MEMORY.md`: "v1.0 PRDs consolidated 2026-04-17"

### Autonomy stop conditions

- Gemini flags a policy conflict (e.g., principle stated in PRD
  contradicts `docs/explanation/security-model.md`) — halt, surface
- Content-filter strike (as seen during v1.0 build) — halt, split the
  work into smaller chunks, continue

## 9. Out-of-band notes

- Target date: **2026-04-17** (today, same-session completion expected)
- Language: **English** (repo convention)
- The existing folder name `project-requirement-document/` is preserved
  (singular, slightly awkward, but well-established; renaming adds churn
  without value)
- Total net additions: ~600–800 lines of markdown across four new files,
  no line removals (archive preserves originals verbatim)
