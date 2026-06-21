## Description

<!-- Brief description of the changes -->

## Related Issue

Closes #

## Type of Change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Documentation update
- [ ] Refactoring (no functional changes)
- [ ] CI/CD or tooling change

## Checklist

- [ ] Code follows the project's style guidelines (`ruff check` passes)
- [ ] Formatting is correct (`ruff format --check` passes)
- [ ] Tests added/updated for the changes
- [ ] All existing tests still pass
- [ ] Documentation updated (if applicable)
- [ ] CHANGELOG.md updated (for user-facing changes)
- [ ] Commit messages follow conventional commit format

## Definition of Done — conditional checks

<!--
Tick only the blocks that apply to your change. Each guards a bug class that
has shipped before because the lenient local NetBox version hid it. See the
"Definition of Done" section in docs/development/contributing.md for the why
behind each item.
-->

**Added or changed a model:**

- [ ] New `NetBoxModel` has a REST serializer **+ viewset + router registration** — NetBox serializes a model for change-log events on save, so a missing serializer raises `SerializerNotFound` (hard 500 on NetBox 4.4). The `test_netboxmodel_completeness` gate enforces this.
- [ ] Ran `makemigrations --check`: no un-generated migrations, and the new migration carries `custom_field_data` + `tags` if the model inherits `NetBoxModel`.

**Added or changed an API serializer / filterset:**

- [ ] `manage.py spectacular --validate` produces a warning-free schema on NetBox 4.6 (a `ChoiceSet.CHOICES` 3-tuple fed to a filter crashes `/api/schema/`).

**Added a test file:**

- [ ] It collects under the host lane — `pytest tests/ -p no:django --collect-only` succeeds — with no module-scope model import and no module-level `skip` that would silently hide a real failure.

**Added or changed a NetBox Script:**

- [ ] `ObjectVar(model=...)` is given the model **class**, not a dotted string, and the script is reachable from the configured `SCRIPTS_ROOT` wrapper.

**Changed user-facing copy or support metadata:**

- [ ] The NetBox support matrix matches across `README.md`, `COMPATIBILITY.md`, and the `pyproject.toml` classifiers.

## Test Plan

<!-- How can reviewers verify this change? -->
