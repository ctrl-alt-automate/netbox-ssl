# Design: Website-centric certificate monitoring (#149)

- **Issue:** [#149](https://github.com/ctrl-alt-automate/netbox-ssl/issues/149) — "website-centric view" (reported by @SerhiiZahuba; mislabeled `bug`, it is an enhancement)
- **Date:** 2026-06-20
- **Status:** Approved — ready for implementation plan
- **Target release:** v1.3 (new minor; milestone justified — one issue spanning many components, the v1.2/#106 pattern)
- **Author:** maintainer + Claude (brainstorming session)

## 1. Problem

An operator runs many internal/external sites (`hr.example.com`, `it.example.com`,
`portal.example.com`, …) but reuses only a handful of certificates (often
wildcards) across them. They want a **website-centric** view, not a
certificate-centric one:

1. Maintain a list of websites/URLs.
2. Automatically retrieve and track the certificate each site presents.
3. Show certificate expiry per website.
4. Alert when a website's certificate is approaching expiry.
5. See which websites are affected by the same certificate.

Today the plugin is certificate-centric. The certificate↔URL relationship is a
single `discovered_via_url` string field on `Certificate` (added by #106), which
**cannot represent many URLs sharing one certificate** — exactly the reporter's
case. A first-class "monitored endpoint" entity is required.

This is passive administration (inventory/monitoring). Importing a certificate
observed at a URL is consistent with the charter (#106 already does it one-shot);
the new element is a **persistent, re-polled endpoint**.

## 2. Goals / Non-goals

**Goals (the MVP chosen in brainstorming)**

- A `MonitoredEndpoint` model: a URL whose presented certificate is tracked over
  time, with rotation history.
- A re-poll NetBox Script that re-scrapes endpoints on a NetBox schedule,
  reusing #106's TLS scraper and security model.
- On rotation, auto-import the newly presented certificate (reusing #106's
  parse + serial/issuer dedup) and re-point the endpoint, recording history.
- Website-centric list/detail views and a "which sites share this certificate"
  view (the reverse of #148's assignments).
- Per-endpoint NetBox events (unreachable, cert-rotated, untrusted-cert) via the
  existing v0.6 event/webhook machinery. Expiry alerts continue to come from the
  existing expiry-scan on the linked certificate.
- Provisioning: manual CRUD, bulk CSV (reuse #106's parser), and auto-create
  from the #106 URL-import flow.

**Non-goals (YAGNI / deferred, mirroring #106's deferrals)**

- Per-endpoint check intervals / a bespoke scheduler (re-poll is one
  NetBox-scheduled Script for all endpoints).
- Per-endpoint alert thresholds or recipients.
- IPv6, STARTTLS, non-HTTPS protocols.
- Active deployment of certificates (the plugin stays passive).

## 3. Background: reusable building blocks (#106, v0.6)

| Component | Where | Reuse for #149 |
|-----------|-------|----------------|
| `scrape_tls_certificate(...)` → PEM | `utils/tls_scraper.py` | The poll's network call (HTTPS-only, DNS-rebinding defense, timeout/size caps). |
| URL validation (private-IP block + CIDR allowlist) | `utils/url_validation.py` | Re-validate every endpoint URL before each poll. |
| CSV URL parser | `utils/url_bulk_parser.py` | Bulk endpoint provisioning. |
| One-shot scrape→parse→import-or-match | `views/url_import.py:_process_row` | **Extract to a shared service** used by both #106 and the #149 poll. |
| `CertificateURLScan` / `CertificateExpiryScan` Scripts | `scripts/url_scan.py`, `scripts/expiry_scan.py` | Template for the re-poll Script (`ObjectVar` tenant filter, `dry_run`, summary logging). |
| Event helpers + types | `utils/events.py` (`EVENT_CERTIFICATE_*`, `fire_certificate_event`) | Add `EVENT_ENDPOINT_*` + a `fire_endpoint_event` sibling using the same Event Rules delivery. |
| `discovered_via_url`, `last_seen_at` | `models/certificates.py` | Updated by the shared import service (unchanged behavior for #106). |

## 4. Data model

One additive migration. No changes to existing models.

### 4.1 `MonitoredEndpoint(NetBoxModel)`

| Field | Type | Notes |
|-------|------|-------|
| `name` | CharField | Human label (e.g. "HR portal"). |
| `url` | CharField | `https://host:port` form; host/port derived via `url_validation`. HTTPS-only. |
| `sni` | CharField, blank | Optional SNI override; defaults to the URL host. |
| `certificate` | FK → `Certificate`, null | The certificate currently presented (null until the first successful poll). `on_delete=SET_NULL`. |
| `assigned_object` | GenericForeignKey, null | Optional Device/VM/Service this site runs on — **same pattern as `CertificateAssignment`** (`assigned_object_type` + `assigned_object_id`, allowlist `device`/`virtualmachine`/`service`). |
| `tenant` | FK → `tenancy.Tenant`, null | Optional. |
| `status` | CharField (choices) | `pending` (never polled) / `ok` / `unreachable` / `untrusted`. Rotation is captured as an event + a history row, **not** a status — a reachable, trusted endpoint stays `ok` even right after it rotated. |
| `last_checked` | DateTimeField, null | Last poll attempt. |
| `last_seen` | DateTimeField, null | Last successful scrape. |
| `last_error` | TextField, blank | Last failure detail (internal; UI shows a generic status). |

Inherits `NetBoxModel` → custom fields, tags, changelog, journaling. Standard
list/detail/edit/delete generic views.

### 4.2 `MonitoredEndpointCertificate(models.Model)` — rotation history

| Field | Type | Notes |
|-------|------|-------|
| `endpoint` | FK → `MonitoredEndpoint`, CASCADE | |
| `certificate` | FK → `Certificate`, CASCADE | |
| `first_seen` | DateTimeField | When this endpoint first presented this cert. |
| `last_seen` | DateTimeField | Updated each poll while still presenting it. |

`UniqueConstraint(endpoint, certificate)`. The endpoint's *current* cert is the
history row with the latest `last_seen`; the timeline of rows is the rotation
history. A plain `models.Model` (not `NetBoxModel`) — it is an internal audit
record, not a user-managed object.

### 4.3 "Which sites share a certificate"

`MonitoredEndpoint.objects.filter(certificate=X)`. Surfaced as a **Monitored
Endpoints** tab on the certificate detail page (the reverse of #148's
assignments tab) and as a filter on the endpoint list.

## 5. Services

### 5.1 Shared import/link service — `utils/url_cert_import.py` (refactor + extend)

Extract the inline import-or-match logic from `UrlImportView._process_row` into:

```python
@dataclass(frozen=True)
class ImportOutcome:
    certificate: "Certificate"
    created: bool          # True = newly imported, False = matched existing
    rotated: bool          # True = the URL now presents a different cert than before

def scrape_and_import(
    url: str, *, allowlist, tenant=None, verify_chain: bool = True,
) -> ImportOutcome: ...
```

Behavior (identical to today's #106 path, now shared): validate URL → scrape via
`tls_scraper` → parse → dedup by `(serial_number, issuer)` → update
`last_seen_at`/`discovered_via_url` on match, or create on miss. `UrlImportView`
and the #106 `CertificateURLScan` script are refactored to call this — **#106
behavior must be unchanged** (covered by existing tests + new parity tests).

### 5.2 Endpoint poll service — `utils/endpoint_monitor.py`

```python
@dataclass(frozen=True)
class PollResult:
    endpoint: "MonitoredEndpoint"
    status: str            # ok / unreachable / untrusted / changed
    rotated: bool
    events_fired: tuple[str, ...]

def poll_endpoint(endpoint, *, allowlist) -> PollResult: ...
```

Per endpoint, atomically: call `scrape_and_import` → link the resulting cert to
the endpoint → update `status`/`last_checked`/`last_seen` → upsert the rotation
history (on a cert change: bump the old row's `last_seen`, create/refresh the new
row, fire `endpoint_cert_rotated`; `status` stays `ok` if the new cert is
reachable and trusted) → on
`TLSScrapeError` set `unreachable` + `last_error`, fire `endpoint_unreachable` →
on untrusted/self-signed result set `untrusted`, fire `endpoint_untrusted_cert`.

### 5.3 Re-poll Script — `scripts/endpoint_monitor.py`

`MonitoredEndpointPoll(Script)` mirroring `CertificateExpiryScan`: `ObjectVar`
tenant filter, `dry_run` BooleanVar, iterate `.restrict`ed endpoints, call
`poll_endpoint`, log a per-status summary. Scheduled via NetBox's job scheduler
(no bespoke scheduler). Registered via `SCRIPTS_ROOT` like the other bundled
scripts (see [[netbox-plugin-scripts-loading]]).

## 6. Events

Add to `utils/events.py`: `EVENT_ENDPOINT_UNREACHABLE`,
`EVENT_ENDPOINT_CERT_ROTATED`, `EVENT_ENDPOINT_UNTRUSTED_CERT`, plus
`fire_endpoint_event(endpoint, event_type, **payload)` delivering through the
same NetBox Event Rules mechanism as `fire_certificate_event`. Expiry alerting
is unchanged — the linked certificate flows through the existing expiry-scan.

## 7. Provisioning

- **Manual:** `MonitoredEndpoint` generic CRUD views.
- **Bulk CSV:** reuse `url_bulk_parser`/`url_validation`; CSV columns
  `url`,`name`,`device`/`virtual_machine`/`service`,`tenant`,`sni`. A bulk-add
  flow (or a Script) creates endpoints.
- **Auto-create from #106:** the #106 URL-import flow upserts a
  `MonitoredEndpoint` for each imported URL row (the user explicitly chose this).
  Implemented as a hook the URL-import path calls after a successful import; the
  shared service (5.1) stays free of endpoint concerns so it has one
  responsibility. Whether to additionally gate it behind a plugin setting is a
  planning detail (§13).

## 8. Views (website-centric)

- **Endpoint list** — filterable by `status`, `certificate`, `tenant`; columns
  include the linked cert's `days_remaining` (expiry-per-site, reusing
  `Certificate.days_remaining`).
- **Endpoint detail** — current cert, status, last_checked/last_seen, and a
  **rotation history** tab (the `MonitoredEndpointCertificate` rows).
- **Certificate detail** — new **Monitored Endpoints** tab listing endpoints
  whose `certificate` is this cert.
- All custom views: `LoginRequiredMixin` first, `.restrict()` on every queryset.

## 9. Security (reuse #106 + v0.7.5)

- Every poll re-validates the URL (DNS can change) and scrapes via `tls_scraper`:
  HTTPS-only, private/loopback blocked unless allowlisted via
  `PLUGINS_CONFIG["netbox_ssl"]["url_import_private_cidr_allowlist"]`,
  DNS-rebinding defense (connect to the validated IP, no re-resolve), hard
  timeout/size caps, no redirects.
- Self-signed/untrusted chains are recorded with `status="untrusted"` and never
  auto-trusted.
- v0.7.5: `LoginRequiredMixin`, `.restrict()`, perm-gated writes on all custom
  views and the script; generic error messages, `last_error` logged internally.

## 10. Migrations

One additive migration creating `MonitoredEndpoint` +
`MonitoredEndpointCertificate`. No existing-model changes → no data migration.
Generated via real `makemigrations` (NetBox needs `DEVELOPER=True`); grep the new
migration against the `NetBoxModel` parent for `custom_field_data`/`tags`
(see [[feedback-netboxmodel-migration-drift]]).

## 11. Testing plan

- **Shared import service:** create-on-miss, match-on-existing, `rotated` flag;
  parity tests proving #106's URL-import behavior is unchanged after the refactor.
- **Poll service:** ok / unreachable / untrusted / rotated paths, history upsert,
  correct events fired (scraper mocked — no real network).
- **Model:** endpoint↔cert link, `SET_NULL` on cert delete, history unique
  constraint, "which sites share a cert" query.
- **Script:** dry-run vs commit, tenant filter, summary counts.
- **Views:** list filters, detail + rotation tab, certificate's Monitored
  Endpoints tab, auth/`.restrict()`.
- **CSV/auto-create:** parser reuse, auto-create upsert from the #106 flow.
- Conventions: `@pytest.mark.django_db`, in-container run (copy `tests/` **and**
  `pytest.ini` to `/tmp/plugin_tests/`).

## 12. Decomposition (implementation plan will be multi-task)

One spec → one plan, but the plan splits into tasks with internal dependencies:
1. Models + migration.
2. Shared import-service refactor (extract from #106, parity-tested).
3. Endpoint poll service + endpoint events.
4. Re-poll Script.
5. Provisioning: CRUD + bulk CSV + #106 auto-create hook.
6. Views (endpoint list/detail + rotation tab + certificate Monitored-Endpoints tab).

Larger than #148 — a v1.3 minor.

## 13. Open questions

None blocking. During planning, confirm whether the #106 auto-create hook should
be unconditional or gated by a plugin setting (default proposed: on for the
URL-import path, since the user explicitly asked for it).

## 14. References

- #106 URL import: `utils/tls_scraper.py`, `utils/url_validation.py`,
  `utils/url_bulk_parser.py`, `views/url_import.py`, `scripts/url_scan.py`.
- Event system (v0.6): `utils/events.py`.
- Reverse-relationship precedent: #148 assignments tab.
- Security rules: `CLAUDE.md` §"Security Rules (v0.7.5)".
