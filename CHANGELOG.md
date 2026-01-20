# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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

[Unreleased]: https://github.com/ctrl-alt-automate/netbox-ssl/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/ctrl-alt-automate/netbox-ssl/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ctrl-alt-automate/netbox-ssl/releases/tag/v0.1.0
