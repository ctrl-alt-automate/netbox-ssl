# Versioning Policy

NetBox SSL follows [Semantic Versioning 2.0.0](https://semver.org/).

## Version format

Versions have the form `MAJOR.MINOR.PATCH`:

- **MAJOR** — incremented for backward-incompatible changes
- **MINOR** — incremented for backward-compatible new features
- **PATCH** — incremented for backward-compatible bug fixes

Pre-release versions use suffixes: `1.1.0-rc.1`, `1.1.0-beta.1`. These are not
considered stable and are only pushed to PyPI as pre-releases.

## What counts as a breaking change?

We bump MAJOR when **any** of these happen:

- An API endpoint is removed or its response shape changes incompatibly
- A model field is removed without a backward-compatible migration
- A permission check is narrowed so that existing users lose access
- A configuration key is renamed without an alias
- Python or NetBox minimum version requirements increase

Examples from history:

- Removal of the `add_certificate` fallback **is** a breaking change under
  SemVer. It was deprecated in v1.0.0 and will be removed in a future MAJOR
  release (e.g., v2.0.0). We do not remove deprecated behaviour in MINOR
  releases.

## What does **not** count as breaking

Confusingly, some changes feel disruptive but are not breaking under the
semver contract:

- A new migration (with default values that preserve existing behaviour)
- A new model field (with a safe default)
- A new API endpoint or new fields on an existing response
- A new optional configuration key
- Stricter input validation that rejects previously-accepted malformed input

These go into MINOR releases.

## Bug fixes

Pure fixes go into PATCH. Examples:

- `0.7.1` fixed a `TypeError` on certificate edit
- `0.8.1` fixed assignment edit and list ordering

Bug-fix releases are always safe to adopt — no new functionality, just
correctness improvements on the existing contract.

## Deprecation policy

We don't remove things without warning.

1. When we decide a feature will be removed, the current MINOR release marks
   it `Deprecated` in CHANGELOG and adds a runtime warning (DeprecationWarning
   or an API response header) where practical.
2. The feature continues to work for **at least one more MINOR release**.
3. Removal happens in the MINOR after that, or in the next MAJOR — whichever
   makes sense.

Example timeline:

- v0.9.0: introduces `import_certificate` custom permission; `add_certificate`
  fallback works
- v1.0.0: fallback is `Deprecated` (marked in CHANGELOG, noted in upgrade docs)
- v2.0.0 (future MAJOR): fallback removed — callers must have
  `import_certificate`. Because this is backwards-incompatible, SemVer requires
  a MAJOR bump.

## NetBox compatibility

The plugin supports:

- **Primary**: the current NetBox stable (actively developed against, all CI
  jobs run)
- **Supported**: the previous NetBox minor (bug fixes and security, CI runs)
- **End of life**: anything older (no CI, no guarantees)

A new NetBox major (e.g., NetBox 5.0) triggers:

1. A plugin MINOR that expands `max_version` to include the new release
2. New CI jobs running against both versions
3. Documentation update (COMPATIBILITY.md)

If the new NetBox major requires breaking changes in the plugin (e.g., a
removed NetBox API we depend on), we may cut a plugin MAJOR instead.

## Python compatibility

The plugin supports Python 3.10, 3.11, and 3.12 in v1.0. Python version
support is reviewed annually:

- Drop a Python version when NetBox itself drops it, or when the ecosystem
  (Django, cryptography) does
- Adding a new Python version is a MINOR change
- Dropping is a MAJOR change (affects deployment pipelines)

## Release cadence

- **Patch**: as needed, typically within a week of a confirmed regression
- **Minor**: quarterly target, feature-driven (not calendar-forced)
- **Major**: when a deprecation removal or NetBox major warrants it

## Long-term support

We commit to security-patch the **current major** for at least 12 months
after the next major releases. In practice, v1.0.x will receive security
patches until at least 12 months after v2.0.0 ships.

## Pre-release software

v0.x releases predate v1.0 GA. They are historical — new deployments should
start on v1.0 or later. Upgrades from v0.9 to v1.0 have no breaking changes
and no required migrations.

## Questions

Open a GitHub issue with the `versioning` label if something about the policy
isn't clear or doesn't fit your scenario.
