# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.6.0]: https://github.com/ctrl-alt-automate/netbox-ssl/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/ctrl-alt-automate/netbox-ssl/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/ctrl-alt-automate/netbox-ssl/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/ctrl-alt-automate/netbox-ssl/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/ctrl-alt-automate/netbox-ssl/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/ctrl-alt-automate/netbox-ssl/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ctrl-alt-automate/netbox-ssl/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ctrl-alt-automate/netbox-ssl/releases/tag/v0.1.0
