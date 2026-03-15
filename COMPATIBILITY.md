# Compatibility Matrix

This document tracks compatibility between NetBox SSL plugin versions and NetBox releases.

## Current

| Plugin Version | NetBox Version | Python Version | Status |
|:--------------:|:--------------:|:--------------:|:------:|
| 0.7.x          | 4.5.x          | 3.10 - 3.12   | Primary |
| 0.7.x          | 4.4.x          | 3.10 - 3.12   | Supported |
| 0.6.x          | 4.5.x          | 3.10 - 3.12   | Supported |
| 0.6.x          | 4.4.x          | 3.10 - 3.12   | Supported |

## End of Life

| Plugin Version | NetBox Version | Notes |
|:--------------:|:--------------:|:------|
| 0.5.x          | 4.5.x          | Upgrade to 0.7.x recommended |
| 0.5.x          | 4.4.x          | Upgrade to 0.7.x recommended |
| 0.4.x          | 4.4.x          | Upgrade to 0.7.x recommended |
| 0.3.x          | 4.4.x          | Upgrade to 0.7.x recommended |
| any            | 4.3.x or older | Unsupported |

## Version Policy

- **Primary**: Actively developed and tested in CI
- **Supported**: Tested in CI, receives bug fixes
- **End of Life**: No longer tested or maintained

Each plugin release is tested against all supported NetBox versions via GitHub Actions CI.
