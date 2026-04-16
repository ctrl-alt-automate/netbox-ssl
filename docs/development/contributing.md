# Contributing to NetBox SSL

Thank you for considering a contribution! This guide covers everything you need
to know to propose changes, whether a bug fix, a new feature, or documentation.

## Before you start

- Read the [Code of Conduct](https://github.com/ctrl-alt-automate/netbox-ssl/blob/main/CODE_OF_CONDUCT.md)
- Check the [issue tracker](https://github.com/ctrl-alt-automate/netbox-ssl/issues)
  to see if someone else is already working on the same thing
- For non-trivial changes, **open an issue first** to discuss the approach —
  saves time for everyone

## Development environment

The recommended setup uses Nix + direnv + uv for reproducible local development,
with Docker Compose for the NetBox runtime.

### Nix + direnv (recommended)

The repo includes a `flake.nix` that pins Python 3.12, uv, PostgreSQL client,
Redis, Docker Compose, and pre-commit. With Nix and direnv installed:

```bash
git clone https://github.com/ctrl-alt-automate/netbox-ssl.git
cd netbox-ssl
direnv allow
```

`direnv` loads the Nix environment automatically each time you cd into the
directory.

### Alternative: pip + venv

```bash
git clone https://github.com/ctrl-alt-automate/netbox-ssl.git
cd netbox-ssl
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,docs]"
```

### Docker NetBox

The plugin needs a running NetBox to test UI + API changes:

```bash
docker-compose up -d
# NetBox is now available at http://localhost:8000 (admin/admin)
# The plugin is mounted into the container for hot-reload
```

## Running tests

The project has four test flavours, distinguished by pytest markers:

```bash
# Unit tests — fast, no NetBox required
pytest tests/ -m unit -v

# API integration tests — require running NetBox + token
NETBOX_TOKEN="nbt_xxx.yyy" pytest tests/ -m api -v

# Browser tests — require running NetBox + Playwright
pytest tests/ -m browser -v

# Load tests — require running NetBox, not run in CI
cd tests/load && NETBOX_TOKEN="nbt_..." locust -f locustfile.py --host=http://localhost:8000
```

The unified runner wraps all of these:

```bash
python scripts/run_tests.py --quick      # unit + parser only
python scripts/run_tests.py --coverage   # with coverage report
```

Coverage must stay at or above **80%** — CI enforces this.

## Code style

We use [Ruff](https://github.com/astral-sh/ruff) for linting and formatting:

```bash
ruff check netbox_ssl/ tests/      # lint
ruff format netbox_ssl/ tests/     # format
```

CI runs both. If `ruff format --check` fails, run `ruff format` locally and
commit the result.

Additional style conventions:

- Python: PEP 8, 120-character line length, type annotations on public functions
- Tests: pytest-style, markers for categorisation (`@pytest.mark.unit` etc.)
- Docstrings: Google style when helpful; keep them short
- Comments: only when the *why* is non-obvious; prefer good names over comments

## Commit conventions

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>: <short description>

<optional body with more detail, why the change matters,
relevant issue numbers, etc.>
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `ci`, `perf`.

Commits are written in English. Signed commits are appreciated but not required.

## Pull request process

1. **Branch from `dev`, not `main`.** `main` tracks the latest release;
   `dev` is where unreleased work accumulates.
2. **Make focused commits.** Each commit should be one logical change that
   could be reverted independently.
3. **Keep the diff focused.** Don't reformat unrelated code in the same PR.
4. **Update tests.** New features need new tests. Bug fixes need regression tests.
5. **Update docs.** User-facing changes need `docs/` updates. Behaviour changes
   need a `CHANGELOG.md` entry.
6. **Open the PR against `dev`.** Fill in the PR template.
7. **Address review feedback.** Use `fixup!` commits during review; the
   maintainer will squash-merge when ready.

The automated checks on PR are:

- Ruff (lint + format)
- Unit tests on Python 3.10, 3.11, 3.12
- Package check (wheel inclusion)
- Integration tests on NetBox 4.4 and 4.5
- MkDocs strict build (on docs-touching PRs)
- Gemini code review (automatic, informational)

All must pass before merge.

## Review SLA

Maintainers review PRs on a best-effort basis — typically within 5 business
days. For urgent security issues, see [SECURITY.md](https://github.com/ctrl-alt-automate/netbox-ssl/blob/main/SECURITY.md).

## Issue labels

- `good-first-issue` — approachable for new contributors
- `help-wanted` — maintainers welcome external contributions
- `bug` / `enhancement` / `documentation` — issue type
- `needs-triage` — not yet categorised by a maintainer

## Release process (for maintainers)

1. Create `release/vX.Y.Z` branch from `dev`
2. Bump version in `pyproject.toml` and `netbox_ssl/__init__.py`
3. Add CHANGELOG `[X.Y.Z]` section with Added/Changed/Deprecated/Security
4. Update COMPATIBILITY.md if NetBox support matrix changes
5. Open PR `release/vX.Y.Z → dev`, admin-merge after CI + Gemini review
6. Open PR `dev → main`, admin-merge after CI
7. Tag `vX.Y.Z` on `main` (signed annotated: `git tag -s vX.Y.Z`)
8. Push tag → triggers `publish.yml` (PyPI) and `docs.yml` (GH Pages)
9. Close the milestone's issues with link to the release

See [versioning.md](versioning.md) for the semver policy.

## Questions?

Open a [GitHub Discussion](https://github.com/ctrl-alt-automate/netbox-ssl/discussions)
or ping the maintainers on an existing issue. We're happy to help.
