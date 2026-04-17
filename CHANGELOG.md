# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-04-16

**GA Release** — NetBox SSL is now Generally Available. Full documentation at
https://ctrl-alt-automate.github.io/netbox-ssl/.

### Added

- **MkDocs Material documentation site** ([#57](https://github.com/ctrl-alt-automate/netbox-ssl/issues/57)):
  versioned via [mike](https://github.com/jimporter/mike), searchable, hosted on
  GitHub Pages. Diátaxis-hybrid layout with tutorials, how-to guides, reference,
  operations, development, and explanation sections.
- **Tutorials** ([#57](https://github.com/ctrl-alt-automate/netbox-ssl/issues/57)):
  Your First Certificate Import, The Janus Renewal Workflow, Expiry Monitoring
  with Events and Webhooks.
- **How-to guides** ([#57](https://github.com/ctrl-alt-automate/netbox-ssl/issues/57)):
  Bulk Import, ACME-Managed Certificate Tracking, Compliance Policies, External
  Source Ingestion, ARI Monitoring (RFC 9773).
- **Explanation docs** ([#57](https://github.com/ctrl-alt-automate/netbox-ssl/issues/57)):
  Architecture with Mermaid diagrams, Janus workflow design rationale,
  Security model explained.
- **Versioning policy** (`docs/development/versioning.md`) ([#59](https://github.com/ctrl-alt-automate/netbox-ssl/issues/59)):
  semver commitment, deprecation windows, NetBox compatibility policy.
- **Detailed contributing guide** (`docs/development/contributing.md`) ([#57](https://github.com/ctrl-alt-automate/netbox-ssl/issues/57)):
  dev setup, testing pyramid, code style, commit conventions, PR process,
  release process for maintainers.
- **Load testing suite** (`tests/load/locustfile.py`, `tests/load/seed_data.py`,
  `docs/operations/load-testing.md`) ([#60](https://github.com/ctrl-alt-automate/netbox-ssl/issues/60)):
  Locust scenarios for list/filter/import/diff endpoints with documented SLOs
  and capacity-planning tips.
- **`docs-ci.yml`** GitHub Actions workflow: `mkdocs build --strict` on every
  PR that touches `docs/`, `mkdocs.yml`, or the workflow itself.
- **`docs.yml`** GitHub Actions workflow: versioned docs deploy to GitHub Pages
  on tagged releases (via mike). Uses GitHub ref env vars — no injection risk.

### Changed

- Documentation restructured using the Diátaxis framework. Existing bookmarks
  to `docs/<name>.md` should move to the canonical site URLs (e.g.,
  `docs/installation.md` → `operations/installation.md`,
  `docs/api.md` → `reference/api.md`). `docs/usage.md` split into
  `how-to/bulk-import.md` and `how-to/acme-auto-renewal.md`.
- `docs/security-review.md` moved to `docs/development/security-review.md`.
- `[project.urls].Documentation` now points at the GH Pages site.
- README links to the documentation site; offline copies remain in `docs/`.

### Deprecated

- The `add_certificate` permission fallback for import endpoints (introduced
  in v0.9.0 for backward compatibility) will be **removed in v2.0.0**.
  Removal is a breaking change, so per SemVer it lands in a major release.
  Assign the `import_certificate` custom permission explicitly before
  upgrading to v2.0.
  See [permissions reference](https://ctrl-alt-automate.github.io/netbox-ssl/reference/permissions/).

### Security

- Bandit clean on release baseline (0 high, 0 medium findings — see
  [security review](https://ctrl-alt-automate.github.io/netbox-ssl/development/security-review/)).
- `pip-audit` clean on declared dependencies at release time.
- Unit test coverage for `netbox_ssl/utils/` at **72%** with CI gate at
  **70%** — higher layers (models, views, scripts) are covered by Docker
  integration tests in CI. The 70% gate is enforced via `.coveragerc`
  `fail_under` on every PR.

### Migration from v0.9.x

**No breaking changes. No new database migrations.** Rollback is a simple
`pip install netbox-ssl==0.9.0`. Documentation URLs have moved — see the
[upgrading guide](https://ctrl-alt-automate.github.io/netbox-ssl/operations/upgrading/).

## [0.9.0] - 2026-04-08

### Added

- **Custom Fields & Tags** ([#54](https://github.com/ctrl-alt-automate/netbox-ssl/issues/54)):
  - Tag-based compliance policy scoping via `tag_filter` M2M field on CompliancePolicy
  - Policies with tags only apply to certificates with ALL specified tags (empty = apply to all)
  - Custom field values included in JSON/YAML exports via `custom_fields` field
  - CSV exports flatten custom fields as `cf_` prefixed columns

- **Granular Permissions** ([#51](https://github.com/ctrl-alt-automate/netbox-ssl/issues/51)):
  - Custom permissions: `import_certificate`, `renew_certificate`, `bulk_operations`, `manage_compliance`
  - All bulk endpoints require `bulk_operations` + operation-specific permission
  - Backward-compatible fallback: `import_certificate` OR `add_certificate` accepted (deprecated in v1.0)
  - Permission documentation at `docs/permissions.md`

- **Performance Optimization** ([#52](https://github.com/ctrl-alt-automate/netbox-ssl/issues/52)):
  - 9 database indexes on Certificate: common_name, status, valid_to, issuer, algorithm, tenant, fingerprint, (status+valid_to), (is_acme+acme_auto_renewal)
  - Conditional field deferral: pem_content, issuer_chain, chain_validation_message deferred on list views
  - Plugin settings: `lazy_load_pem_content` (default: True), `performance_prefetch_limit`

- **Import/Export Extensions** ([#53](https://github.com/ctrl-alt-automate/netbox-ssl/issues/53)):
  - DER format certificate import with automatic PEM conversion
  - PKCS#7 (.p7b) container import — extracts all certificates from chain bundles
  - Format auto-detection: `parse_auto()` identifies PEM, DER, PKCS#7 automatically
  - `POST /import-file/` API endpoint with multipart file upload
  - `POST /diff/` API endpoint to compare two export snapshots (added/removed/changed)
  - Export with full assignment details (device/service type, id, name)
  - `ScheduledCertificateExport` NetBox Script for periodic report generation

- **ACME Renewal Information (ARI) Monitoring** ([#84](https://github.com/ctrl-alt-automate/netbox-ssl/issues/84)):
  - RFC 9773 support: poll CA-recommended renewal windows for ACME certificates
  - New fields: `ari_cert_id`, `ari_suggested_start`, `ari_suggested_end`, `ari_explanation_url`, `ari_last_checked`, `ari_retry_after`
  - `CertificateARIPoll` NetBox Script with tenant filter, dry-run, Retry-After respect
  - ARI CertID builder: `base64url(AKI).base64url(serial)` per RFC 9773
  - ACME directory discovery for Let's Encrypt and Google Trust Services
  - Event firing on unexpected renewal window shift (possible revocation signal)
  - REST API and GraphQL exposure of all ARI fields + computed `ari_window_active`, `ari_status`
  - `has_ari` filter on Certificate filterset

### Changed

- Shared SSRF protection: `url_validation.py` module reused by ARI and External Source Framework
- Parser refactored: `parse()` delegates to `_build_parsed()` — single code path for metadata extraction
- `requests>=2.28.0` added as explicit dependency

### Migration Notes

- **5 new migrations** (0015–0019): tag_filter, custom permissions, performance indexes, ARI fields, merge
- **Permissions**: Existing users with `add_certificate` retain import access via backward-compatible fallback. Assign new custom permissions (`import_certificate`, `renew_certificate`, `bulk_operations`, `manage_compliance`) for granular control. The `add_certificate` fallback will be removed in v1.0.
- No data migration required — all new fields have safe defaults

## [0.8.1] - 2026-04-08

### Fixed

- **Assignment edit does not save** ([#85](https://github.com/ctrl-alt-automate/netbox-ssl/issues/85)):
  - Form `clean()` now allows editing assignments without re-selecting the target device/VM/service
  - Form `save()` preserves existing `assigned_object_type` and `assigned_object_id` when target is unchanged
  - Duplicate check only runs when the assignment target is actually changing

- **Assignment list FieldError** ([#86](https://github.com/ctrl-alt-automate/netbox-ssl/issues/86)):
  - Added `orderable=False` to the `assigned_object` table column to prevent django-tables2 from attempting `order_by()` on a `GenericForeignKey`, which does not support reverse queries

## [0.7.0] - 2026-03-12

### Added

- **Certificate Analytics Dashboard** ([#44](https://github.com/ctrl-alt-automate/netbox-ssl/issues/44)):
  - Summary cards with MDI icons: active certificates, unassigned, avg days remaining, ACME managed
  - Certificate status distribution chart (Bootstrap CSS classes, dark mode compatible)
  - Key algorithm distribution chart
  - Expiry forecast (12 months) with contextual colors (red/yellow/blue per time horizon)
  - CA distribution and ACME distribution charts
  - Empty states with action links
  - Tenant filter support

- **Compliance Report View** ([#45](https://github.com/ctrl-alt-automate/netbox-ssl/issues/45)):
  - Score overview card with shield icon and progress bar indicator
  - Failures by severity and policy type breakdowns
  - Compliance trend chart (90 days) from snapshots
  - CSV and JSON export buttons
  - Tenant filter support

- **Certificate Map** ([#46](https://github.com/ctrl-alt-automate/netbox-ssl/issues/46)):
  - Visual topology: Tenant → Device/VM → Service → Certificate
  - Color-coded expiry status legend (green/yellow/red)
  - HTMX lazy loading per tenant for performance
  - Parent device/VM name shown for service assignments
  - Orphan certificates grouped as "Unassigned Certificates"
  - Summary cards: tenant groups, devices/services, certificate assignments

- **UI/UX Polish** ([#65](https://github.com/ctrl-alt-automate/netbox-ssl/issues/65)):
  - Certificate detail: tabbed layout for SANs, Assignments, History
  - Certificate panel: `{% badge %}` template tag for status display
  - MDI icons on all summary cards across all dashboard pages
  - Charts use Bootstrap CSS classes instead of hardcoded hex colors (dark mode compatible)
  - New `charts.css` with reusable chart utility classes
  - Empty states with icons and action links on all pages

### Fixed

- Compliance score CSS `conic-gradient` not rendering with Bootstrap CSS variables ([#65](https://github.com/ctrl-alt-automate/netbox-ssl/issues/65))
- Django l10n locale formatting breaking CSS `calc()` expressions (comma vs period)
- Certificate map HTMX loading spinner stuck for tenants with `id=None`
- Fresh install Django system check messages improved ([#63](https://github.com/ctrl-alt-automate/netbox-ssl/issues/63))

### Changed

- Compliance report score card redesigned from donut ring to consistent card layout with progress bar
- Forecast chart bars use contextual colors per time horizon instead of uniform yellow
- Topology views refactored with shared `_parse_map_filters()` helper (DRY)
- Updated documentation for all v0.7.0 features
- Updated compatibility table to v0.7.x

## [0.6.0] - 2026-03-09

### Added

- **NetBox Event Rules Integration** ([#41](https://github.com/ctrl-alt-automate/netbox-ssl/issues/41)):
  - Certificate status transitions (expired, revoked, replaced) are logged with enriched context
  - Renewal events include old certificate reference and assignment transfer count
  - Event payloads contain: certificate ID, common_name, days_remaining, status, assigned objects
  - Documentation with Slack, Microsoft Teams, and PagerDuty webhook examples

- **Scheduled Certificate Expiry Scan** ([#42](https://github.com/ctrl-alt-automate/netbox-ssl/issues/42)):
  - New `CertificateExpiryScan` NetBox Script for periodic expiry scanning
  - Configurable thresholds via `expiry_scan_thresholds` setting (default: 14, 30, 60, 90 days)
  - Idempotent: cooldown window prevents duplicate events (default: 24 hours)
  - New `CertificateEventLog` model for tracking fired events and audit trail
  - Per-tenant filtering support
  - Dry-run mode for testing without firing events
  - Automatic cleanup of old event log entries (90 days)
  - Plugin settings: `expiry_scan_thresholds`, `expiry_scan_cooldown_hours`

- **Certificate Changelog Enrichment** ([#43](https://github.com/ctrl-alt-automate/netbox-ssl/issues/43)):
  - Changelog snapshots include computed fields: `days_remaining`, `expiry_status`, `assignment_count`
  - Status transitions produce clear "before → after" diffs in the changelog
  - Renewal events create enriched changelog entries for both old and new certificates
  - Assignment changes (add/remove) update the parent certificate's changelog

## [0.5.1] - 2026-03-09

### Fixed

- Removed dead `$tenant` query_params from assignment form fields
- Added missing Issues and Changelog URLs to pyproject.toml
- Added dev optional-dependencies for contributor setup
- Updated CHANGELOG for v0.5.0 release
- CI now tests against Python 3.10, 3.11, and 3.12
- Added undeclared plugin settings to `default_settings`: `max_export_size`, `bulk_validate_max_batch_size`, `bulk_compliance_max_batch_size`, `bulk_detect_max_batch_size`

## [0.5.0] - 2026-03-09

### Added

- **Email Notifications** for certificate expiry reports:
  - HTML + plain-text email templates
  - Configurable recipients, subject prefix
  - Triggered by Certificate Expiry Notification script
  - Plugin settings: `notification_email_enabled`, `notification_email_recipients`, `notification_email_subject_prefix`

- **Bulk CSV/JSON Import** for certificate metadata:
  - Web UI with two-step preview/confirm workflow
  - Auto-detection of CSV vs JSON format
  - Row-level validation with error reporting
  - `POST /certificates/bulk-data-import/` API endpoint
  - File upload support (max 5 MB)
  - Duplicate detection with skip option

- **ACME Certificate Monitoring** improvements:
  - Auto-detection of ACME providers from issuer field
  - Support for 7+ providers (Let's Encrypt, ZeroSSL, Buypass, Google, Sectigo, DigiCert)
  - Renewal status tracking (ok, due, expired, manual)
  - `send_email` and `email_recipients` options on expiry notification script

### Fixed

- `total_alerts` undefined bug in expiry notification script
- Security fixes from code review: permission checks, tenant IDOR protection, upload size limits
- Test isolation: `find_spec` guard in all test files to prevent mocking real NetBox in Docker

### Changed

- Updated documentation for all v0.5.0 features
- Updated compatibility table to v0.5.x

## [0.4.1] - 2026-02-10

### Fixed

- Migration conflict between ACME tracking and chain validation branches causing fresh installs to fail

## [0.4.0] - 2026-02-10

### Added

- **Janus Renewal Workflow UI** ([#27](https://github.com/ctrl-alt-automate/netbox-ssl/issues/27)):
  - Complete renewal confirmation page with side-by-side certificate comparison
  - Formatted validity dates (no more raw ISO strings)
  - Assignment transfer preview table showing type, target, primary status, and notes
  - "Renew This Certificate" button on certificate detail page (active/expired only)
  - Renewal context banner on import page when initiated from detail page
  - Input validation on renewal query parameters

### Changed

- Project status upgraded from Alpha to **Beta**

### Previously Added

- **Certificate Chain Validation** ([#16](https://github.com/ctrl-alt-automate/netbox-ssl/issues/16)):
  - New `ChainValidator` utility for validating certificate chains
  - Verifies chain completeness and signature validity
  - Checks certificate validity periods (not expired, not yet valid)
  - Detects self-signed certificates
  - New Certificate fields: `chain_status`, `chain_validation_message`, `chain_validated_at`, `chain_depth`
  - REST API endpoints:
    - `POST /certificates/{id}/validate-chain/` - Single certificate validation
    - `POST /certificates/bulk-validate-chain/` - Bulk validation
  - Computed properties: `chain_is_valid`, `chain_needs_validation`
  - Unit tests for chain validation

- **Data Export Formats** ([#15](https://github.com/ctrl-alt-automate/netbox-ssl/issues/15)):
  - Multi-format certificate export: CSV, JSON, YAML, PEM
  - Bulk export endpoint: `GET/POST /api/plugins/netbox-ssl/certificates/export/`
  - Single certificate export: `GET /api/plugins/netbox-ssl/certificates/{id}/export/`
  - Configurable field selection for exports
  - Support for filtering exports via query parameters
  - PEM bundle export with optional certificate chain
  - JSON/YAML export with optional PEM content inclusion
  - Configurable max export size via `max_export_size` plugin setting
  - Sanitized filenames using certificate common name

- **Compliance Reporting** ([#14](https://github.com/ctrl-alt-automate/netbox-ssl/issues/14)):
  - New CompliancePolicy model for defining compliance rules
  - New ComplianceCheck model for storing check results
  - 10 built-in policy types:
    - `min_key_size` - Minimum key size requirement
    - `max_validity_days` - Maximum certificate validity period
    - `algorithm_allowed` - Allowed algorithms whitelist
    - `algorithm_forbidden` - Forbidden algorithms blacklist
    - `expiry_warning` - Expiry warning threshold
    - `chain_required` - Certificate chain requirement
    - `san_required` - SAN requirement
    - `wildcard_forbidden` - Wildcard certificate prohibition
    - `issuer_allowed` - Allowed issuers whitelist
    - `issuer_forbidden` - Forbidden issuers blacklist
  - Severity levels: critical, warning, info
  - Compliance score calculation (percentage of passing checks)
  - Tenant-scoped policies support
  - REST API endpoints:
    - `POST /certificates/{id}/compliance-check/` - Single certificate check
    - `POST /certificates/bulk-compliance-check/` - Bulk compliance check
    - CRUD endpoints for CompliancePolicy and ComplianceCheck
  - ComplianceChecker utility for running policy evaluations
  - Full documentation for compliance reporting in data-models.md and api.md

- **Certificate Authority Tracking** ([#13](https://github.com/ctrl-alt-automate/netbox-ssl/issues/13)):
  - New `CertificateAuthority` model for tracking CAs
  - CA types: Public, Internal/Private, ACME/Let's Encrypt
  - Auto-detection of issuing CA based on issuer patterns
  - `issuing_ca` foreign key on Certificate model
  - Pre-defined list of common CAs (DigiCert, Let's Encrypt, Sectigo, etc.)
  - Full REST API and GraphQL support for CAs
  - CA management views (list, detail, add, edit, delete)
  - Filter certificates by issuing CA
  - Navigation menu item under "Management" group

- **Certificate Signing Request (CSR) Tracking** ([#12](https://github.com/ctrl-alt-automate/netbox-ssl/issues/12)):
  - New `CertificateSigningRequest` model for tracking pending certificate requests
  - Full subject field support: CN, O, OU, L, ST, C
  - Subject Alternative Names (SANs) parsing from CSR extensions
  - Key information extraction: algorithm and key size
  - SHA256 fingerprint calculation for duplicate detection
  - Status tracking: Pending, Approved, Rejected, Issued, Expired
  - Link to resulting certificate when issued
  - Smart Paste import via web UI
  - REST API endpoints: CRUD + `/csrs/import/`
  - GraphQL query support
  - Multi-tenancy support

## [0.3.0] - 2025-01-20

### Added

- **Bulk Certificate Import API** ([#9](https://github.com/ctrl-alt-automate/netbox-ssl/issues/9)):
  - `POST /api/plugins/netbox-ssl/certificates/bulk-import/` endpoint
  - Accepts JSON array of certificate objects
  - Atomic transactions (all-or-nothing import)
  - Validation before creation
  - Maximum batch size configurable via `bulk_import_max_batch_size` setting (default: 100)
  - Detailed error reporting with failed certificate indices
  - Test fixtures with 15 sample certificates

### Added

- **ACME Certificate Tracking** ([#11](https://github.com/ctrl-alt-automate/netbox-ssl/issues/11)):
  - New fields for tracking ACME-issued certificates (Let's Encrypt, ZeroSSL, etc.)
  - `is_acme` - Boolean flag for ACME certificates
  - `acme_provider` - Provider identification (letsencrypt, zerossl, buypass, google, digicert, sectigo)
  - `acme_account_email` - Email associated with ACME account
  - `acme_challenge_type` - Challenge type used (http-01, dns-01, tls-alpn-01)
  - `acme_server_url` - ACME server directory URL
  - `acme_auto_renewal` - Whether auto-renewal is configured
  - `acme_last_renewed` - Last renewal timestamp
  - `acme_renewal_days` - Days before expiry to attempt renewal
  - Computed properties: `acme_renewal_due`, `acme_renewal_status`
  - Auto-detection method `auto_detect_acme()` to identify ACME certificates from issuer
  - REST API endpoints:
    - `POST /certificates/{id}/detect-acme/` - Single certificate ACME detection
    - `POST /certificates/bulk-detect-acme/` - Bulk ACME detection
  - API filters for ACME fields (`is_acme`, `acme_provider`, `acme_auto_renewal`)
  - Full documentation for ACME tracking in data-models.md and api.md

## [0.2.0] - 2025-01-20

### Added

- **REST API Import Endpoint** ([#2](https://github.com/ctrl-alt-automate/netbox-ssl/issues/2)):
  - `POST /api/plugins/netbox-ssl/certificates/import/` endpoint
  - PEM certificate parsing with automatic metadata extraction
  - Private key detection and rejection for security
  - Duplicate certificate detection (serial + issuer)
  - Optional tenant assignment during import

- **GIN Index for SANs Field** ([#3](https://github.com/ctrl-alt-automate/netbox-ssl/issues/3)):
  - PostgreSQL GIN index on Certificate.sans field
  - Optimized array containment queries (`sans__contains`)
  - Uses `AddIndexConcurrently` for zero-downtime deployment

- **Certificate Expiry Notification Script** ([#4](https://github.com/ctrl-alt-automate/netbox-ssl/issues/4)):
  - Custom script for automated expiry monitoring
  - Configurable warning/critical day thresholds
  - Optional tenant filtering
  - Structured JSON output for webhook integration
  - Documentation with scheduling examples (NetBox Jobs, cron)

### Changed

- Improved database query performance for certificate categorization

## [0.1.0] - 2025-01-19

Initial release of NetBox SSL Plugin.

### Added

- **Certificate Model** with full X.509 metadata support:
  - Common Name, Serial Number, SHA256 Fingerprint
  - Issuer and Issuer Chain (full certificate chain storage)
  - Validity period (valid_from, valid_to)
  - Subject Alternative Names (SANs)
  - Key algorithm (RSA, ECDSA, Ed25519) and key size
  - Status tracking (Active, Expired, Replaced, Revoked)
  - Private key location hint (breadcrumb, no actual key storage)
  - Tenant assignment for multi-tenancy support

- **Certificate Assignment Model** for linking certificates to NetBox objects:
  - GenericForeignKey support for Device, Virtual Machine, and Service
  - Primary certificate flag
  - Assignment notes

- **Smart Paste Import** for PEM certificates:
  - Automatic parsing of certificate metadata using Python `cryptography` library
  - Certificate chain extraction (leaf + intermediates)
  - **Security**: Private key detection and rejection
  - Duplicate detection based on fingerprint

- **User Interface**:
  - Certificate list view with filtering and search
  - Certificate detail view with all metadata
  - Certificate add/edit forms
  - Certificate import form (Smart Paste)
  - Assignment list and detail views
  - Navigation menu integration

- **Dashboard Widget**:
  - Certificate expiry status overview
  - Categories: Expired, Critical (<14 days), Warning (<30 days), Orphan (no assignments)
  - Configurable thresholds via plugin settings

- **Template Extensions**:
  - Certificate panel on Device detail pages
  - Certificate panel on Virtual Machine detail pages
  - Certificate panel on Service detail pages

- **REST API**:
  - Full CRUD endpoints for Certificates
  - Full CRUD endpoints for Certificate Assignments
  - Filtering and search support

- **GraphQL Support**:
  - Certificate and CertificateAssignment types
  - Query support with filtering

- **Django System Checks**:
  - Model validation checks
  - URL configuration checks
  - Template existence checks
  - Security configuration checks
  - Database table checks
  - Plugin health check (`manage.py check --tag netbox_ssl`)

### Compatibility

- NetBox 4.4.0 - 4.5.x
- Python 3.10+

[Unreleased]: https://github.com/ctrl-alt-automate/netbox-ssl/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/ctrl-alt-automate/netbox-ssl/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/ctrl-alt-automate/netbox-ssl/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/ctrl-alt-automate/netbox-ssl/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/ctrl-alt-automate/netbox-ssl/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/ctrl-alt-automate/netbox-ssl/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/ctrl-alt-automate/netbox-ssl/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/ctrl-alt-automate/netbox-ssl/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ctrl-alt-automate/netbox-ssl/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ctrl-alt-automate/netbox-ssl/releases/tag/v0.1.0
