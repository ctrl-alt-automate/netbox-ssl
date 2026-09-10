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

The Python column is the range actually exercised: the unit suite runs 3.10,
3.11 and 3.12, and each integration lane runs whatever interpreter that NetBox
release ships (3.12 through 4.6, 3.14 on 4.7). The plugin's own floor is Python
3.10 (`requires-python`); in practice the NetBox release you run decides.

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

Each plugin release is tested against all supported NetBox versions via GitHub Actions CI.

## Upgrade Path

For upgrade instructions, see [docs/operations/upgrading.md](docs/operations/upgrading.md).
