# Security Review

This document describes the security measures implemented in NetBox SSL and serves as a review checklist for auditing the plugin's security posture.

## Core Security Principles

1. **No private key storage** — The plugin explicitly rejects any input containing private keys. Only public certificate metadata is stored.
2. **Passive administration** — The plugin monitors and inventories certificates. It never deploys, renews, or manages certificates actively.
3. **Defense in depth** — Multiple layers of validation on all input paths.

## Security Checklist

### Input Validation

| Check | Status | Implementation |
|-------|--------|----------------|
| Private key rejection | Implemented | Broad regex in `utils/parser.py` — detects RSA, EC, generic PRIVATE KEY headers |
| PEM input size limit | Implemented | `MAX_PEM_INPUT_BYTES = 65536` enforced on all import paths |
| Certificate format validation | Implemented | `cryptography` library X.509 parsing with error handling |
| CSV formula injection prevention | Implemented | `_sanitize_csv_value()` in `utils/export.py` — prefixes `=+-@\t\r` characters |
| Export field allowlist | Implemented | `ALLOWED_FIELDS` frozenset in `utils/export.py` — blocks arbitrary `getattr()` |
| Chain validation depth limit | Implemented | `MAX_CHAIN_DEPTH = 10` in `utils/chain_validator.py` |

### SSRF Protection

| Check | Status | Implementation |
|-------|--------|----------------|
| HTTPS-only enforcement | Implemented | `utils/url_validation.py` — shared across ARI and External Source |
| Private IP blocking | Implemented | Checks literal IPs and DNS-resolved addresses |
| Loopback blocking | Implemented | Blocks `localhost`, `127.0.0.1`, `::1`, link-local addresses |
| DNS resolution validation | Implemented | Resolves hostname and checks all returned IPs |
| No redirect following | Implemented | `allow_redirects=False` on outbound requests |

### Authentication & Authorization

| Check | Status | Implementation |
|-------|--------|----------------|
| LoginRequiredMixin on custom views | Implemented | All non-model views require authentication |
| `.restrict()` on all querysets | Implemented | Enforces NetBox ObjectPermission constraints |
| `has_perm()` on all POST endpoints | Implemented | Every `@action` has explicit permission check |
| Custom permissions | Implemented | `import_certificate`, `renew_certificate`, `bulk_operations`, `manage_compliance` |
| Credential protection | Implemented | `write_only=True` on serializers, omitted from GraphQL |

### Data Protection

| Check | Status | Implementation |
|-------|--------|----------------|
| No secrets in error messages | Implemented | Generic error responses, internal logging only |
| No private keys in database | Enforced | Parser rejects before any database write |
| Credential resolution | Implemented | `env:VAR_NAME` pattern — no plaintext in database |
| GraphQL field restriction | Implemented | Explicit field lists, never `fields="__all__"` |

### CI/CD Security

| Check | Status | Implementation |
|-------|--------|----------------|
| Ruff linting | Enabled | Runs on every push/PR |
| Bandit SAST scanning | Enabled | Static analysis for common Python security issues |
| Multi-version testing | Enabled | Python 3.10/3.11/3.12, NetBox 4.4/4.5 |
| Dependabot | Enabled | Automated dependency updates and security alerts |
| Secret scanning | Enabled | GitHub secret scanning + push protection |

## Previous Security Hardening

- **v0.7.5** (10 findings fixed): LoginRequiredMixin, GraphQL `.restrict()`, API permissions, PEM size limits, error sanitization, CSV injection prevention
- **v0.8.0** (34 findings fixed): SSRF protection, credential exposure prevention, atomic transactions, private key guard on sync engine
- **v0.9.0**: Shared SSRF util, backward-compatible permissions, ARI HTTPS-only polling
