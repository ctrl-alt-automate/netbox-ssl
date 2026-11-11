# Compatibility Matrix

This document tracks compatibility between NetBox SSL plugin versions and NetBox releases.

## Current

| Plugin Version | NetBox Version | Python Version | Status |
|:--------------:|:--------------:|:--------------:|:------:|
| 1.4.x          | 4.7.x          | 3.12 - 3.14   | Supported |
| 1.4.x          | 4.6.x          | 3.10 - 3.12   | Primary |
| 1.4.x          | 4.5.x          | 3.10 - 3.12   | Supported |
| 1.4.x          | 4.4.x          | 3.10 - 3.12   | Supported |
| 1.3.x          | 4.6.x          | 3.10 - 3.12   | Primary |
| 1.3.x          | 4.5.x          | 3.10 - 3.12   | Supported |
| 1.3.x          | 4.4.x          | 3.10 - 3.12   | Supported |
| 1.2.x          | 4.6.x          | 3.10 - 3.12   | Supported |
| 1.2.x          | 4.5.x          | 3.10 - 3.12   | Supported |
| 1.2.x          | 4.4.x          | 3.10 - 3.12   | Supported |
| 1.1.x          | 4.6.x          | 3.10 - 3.12   | Supported |
| 1.1.x          | 4.5.x          | 3.10 - 3.12   | Supported |
| 1.1.x          | 4.4.x          | 3.10 - 3.12   | Supported |
| 1.0.x          | 4.5.x          | 3.10 - 3.12   | Supported |
| 1.0.x          | 4.4.x          | 3.10 - 3.12   | Supported |
| 0.9.x          | 4.5.x          | 3.10 - 3.12   | Supported |
| 0.9.x          | 4.4.x          | 3.10 - 3.12   | Supported |

## End of Life

| Plugin Version | NetBox Version | Notes |
|:--------------:|:--------------:|:------|
| 0.8.x          | 4.5.x / 4.4.x | Upgrade to 1.0.x recommended |
| 0.7.x          | 4.5.x / 4.4.x | Upgrade to 1.0.x recommended |
| 0.6.x          | 4.5.x / 4.4.x | Upgrade to 1.0.x recommended |
| 0.5.x          | 4.5.x / 4.4.x | Upgrade to 1.0.x recommended |
| any            | 4.3.x or older | Unsupported |

## Version Policy

- **Primary**: Actively developed and tested in CI
- **Supported**: Tested in CI, receives bug fixes
- **End of Life**: No longer tested or maintained

The Python column is the range that NetBox release itself supports. The plugin
is exercised more widely than any single row: the unit suite runs on Python
3.10 through 3.14, and each integration lane runs whatever interpreter that
NetBox release ships (3.12 through 4.6, 3.14 on 4.7). The plugin's own floor is
Python 3.10 (`requires-python`); in practice the NetBox release you run decides.

A newly released NetBox minor enters as **Supported** — covered by the full CI
integration matrix — and is promoted to **Primary** once it has carried a plugin
release. NetBox 4.7 was released 2026-09-02 and is Supported as of plugin 1.4.

### NetBox 4.7 notes

NetBox 4.7 carries a large set of breaking changes, none of which the plugin
depends on:

| 4.7 change | Impact on netbox-ssl |
|------------|----------------------|
| `ipam.Service.protocol` / `.ports` replaced by `port_mappings` | None — the plugin references `Service` only as an assignment target and never reads its port fields |
| `EMAIL_*` settings superseded by `MAILERS`; `get_connection()` with an explicit backend raises `RuntimeError` | None — expiry mail uses `EmailMultiAlternatives(...).send()` with no explicit backend |
| django-tables2 v3.0 drops `RelatedLinkColumn` and renames the `querystring` tag | None — neither is used |
| `registry['models']` and `registry['denormalized_fields']` removed | None — the plugin's `registry` is its own adapter dict |
| django-mptt replaced by `ltree`; `NestedGroupModel` deprecated | None — no hierarchical models |
| PostgreSQL 15+ and Redis 6+ now required | Infrastructure only; the bundled compose stack already runs PostgreSQL 18 and Valkey 9 |

#### Patch releases 4.7.1 – 4.7.5

Reviewed and tested through **4.7.5** (released 2026-11-10; Django 6.1.3,
Python 3.14): the full integration suite, the REST API tests, the Playwright
browser tests, the system checks, OpenAPI schema generation with
`--fail-on-warn` and the migration-drift check all pass unchanged. The
upstream changes that touch areas the plugin uses:

| Patch | Change | Impact on netbox-ssl |
|-------|--------|----------------------|
| 4.7.1 | Custom scripts run through the REST API now resolve object IDs to model instances and validate the submitted data | None — the same form the UI has always passed, which is what the bundled scripts are written for |
| 4.7.4 | 64-bit integer fields are `BigInt` in GraphQL and `int64` in the OpenAPI schema | None — the plugin's schema still generates warning-free |
| 4.7.4 | Concurrent REST API updates to one object no longer overwrite each other | None — the plugin's serializers use the standard update path |
| 4.7.4 | Event data and webhook payloads gain `object_change_ids` | None — additive; the plugin's own event payloads are unchanged |
| 4.7.5 | Add and edit forms disable their submit button after the first click | None — the browser suite (import, Janus renewal, URL import) passes unchanged |

Each plugin release is tested against all supported NetBox versions via GitHub
Actions CI. Every integration lane follows the floating image tag of its minor
(`v4.7`, `v4.6`, …), so it always runs the newest patch release, and the matrix
re-runs weekly on `dev` to catch an upstream patch that breaks the plugin.

### Optional extras

The Azure Key Vault External Source adapter requires the optional `azure`
extra (`pip install netbox-ssl[azure]`); without it the plugin works
normally and `azure_kv` is simply not offered as a source type. See the
[Azure Key Vault how-to](docs/how-to/azure-key-vault-sync.md).

## Upgrade Path

For upgrade instructions, see [docs/operations/upgrading.md](docs/operations/upgrading.md).
