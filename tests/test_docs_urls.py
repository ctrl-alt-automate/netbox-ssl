"""Regression guard: documented plugin URLs must match the real ``base_url``.

NetBox mounts a plugin under its ``PluginConfig.base_url``, not under its
package or distribution name. This plugin sets ``base_url = "ssl"``, so its
routes live at ``/plugins/ssl/`` and ``/api/plugins/ssl/`` -- **not** at
``/plugins/netbox-ssl/``.

The published documentation nevertheless used the distribution name in 54
places, so effectively every copy-pasteable API example in the docs returned
404 (issue #165). Nothing caught it because the docs are prose: no test, no
link checker, and no CI step ever compared them against the plugin config.

These guards parse ``base_url`` straight out of ``netbox_ssl/__init__.py`` with
AST (the host unit lane cannot import the plugin, which needs NetBox) and assert
the docs agree. If ``base_url`` is ever changed, these tests fail and point at
every document that needs updating.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from .conftest import get_plugin_source_dir

# Slugs that legitimately belong to something other than this plugin's routes.
# "plugins/development" is part of the upstream NetBox documentation URL
# https://docs.netbox.dev/en/stable/plugins/development/.
_EXTERNAL_SLUGS = {"development"}

# docs/superpowers/ holds historical specs and plans; it is excluded from the
# MkDocs build (`exclude_docs` in mkdocs.yml), so it is not user-facing.
_UNPUBLISHED_DIRS = {"superpowers"}

_API_ROUTE = re.compile(r"api/plugins/([A-Za-z0-9_-]+)")


def _plugin_base_url() -> str:
    """Return ``PluginConfig.base_url`` parsed out of ``netbox_ssl/__init__.py``."""
    source = (get_plugin_source_dir() / "__init__.py").read_text()
    tree = ast.parse(source, filename="__init__.py")
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "base_url" for target in node.targets)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            return node.value.value
    raise AssertionError("base_url not found in netbox_ssl/__init__.py")


def _published_docs() -> list[Path]:
    """Return every user-facing Markdown file, or an empty list if docs/ is absent."""
    repo_root = get_plugin_source_dir().parent
    docs_dir = repo_root / "docs"
    if not docs_dir.is_dir():
        return []

    files = [p for p in docs_dir.rglob("*.md") if not _UNPUBLISHED_DIRS.intersection(p.parts)]
    readme = repo_root / "README.md"
    if readme.is_file():
        files.append(readme)
    return sorted(files)


@pytest.mark.unit
def test_documented_api_routes_use_the_plugin_base_url() -> None:
    """Every ``api/plugins/<slug>`` in the docs must use the real base_url (issue #165)."""
    docs = _published_docs()
    if not docs:
        pytest.skip("docs/ not available (in-container runs copy only tests/)")

    base_url = _plugin_base_url()
    wrong: list[str] = []

    for path in docs:
        for line_no, line in enumerate(path.read_text().splitlines(), start=1):
            for slug in _API_ROUTE.findall(line):
                if slug != base_url and slug not in _EXTERNAL_SLUGS:
                    wrong.append(f"{path}:{line_no} uses api/plugins/{slug}")

    assert not wrong, (
        f"The plugin is mounted at api/plugins/{base_url}/ (PluginConfig.base_url = "
        f"{base_url!r}), so these documented endpoints 404 for every reader:\n  " + "\n  ".join(wrong)
    )


@pytest.mark.unit
def test_docs_never_use_the_distribution_name_as_a_url_slug() -> None:
    """The PyPI name ``netbox-ssl`` is not a URL slug -- catch the #165 mistake by name."""
    docs = _published_docs()
    if not docs:
        pytest.skip("docs/ not available (in-container runs copy only tests/)")

    offenders = [
        f"{path}:{line_no}"
        for path in docs
        for line_no, line in enumerate(path.read_text().splitlines(), start=1)
        if "plugins/netbox-ssl" in line
    ]

    assert not offenders, (
        "`netbox-ssl` is the distribution name, not the URL slug -- the plugin is "
        "mounted at /plugins/ssl/ and /api/plugins/ssl/ (issue #165):\n  " + "\n  ".join(offenders)
    )
