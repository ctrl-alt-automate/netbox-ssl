"""Regression guard: every bundled Script must be exported from the package.

NetBox does not auto-discover plugin-bundled scripts. Users expose them with a
wrapper module in ``SCRIPTS_ROOT`` that does ``from netbox_ssl.scripts import
<ClassName>`` (see ``docs/reference/scripts.md``). That documented entry point
is the *package*, so a ``Script`` subclass that is never re-exported from
``netbox_ssl/scripts/__init__.py`` cannot be registered at all -- the import
raises ``ImportError`` and the whole wrapper module fails to load.

That is exactly what happened to ``MonitoredEndpointPoll`` in v1.3.0 (issue
#163): the module ``scripts/endpoint_monitor.py`` shipped, but the class was
missing from ``__init__.py``, so website-centric monitoring (#149) could never
run and endpoints stayed on ``Pending`` forever -- which in turn made renewal
reminders report stale certificate data (issue #161).

The unit tests missed it because they import the *submodule*
(``from netbox_ssl.scripts.endpoint_monitor import MonitoredEndpointPoll``)
rather than the package, so they exercised a different door than the one the
documentation tells users to open.

This guard is AST-based so it runs in the host unit lane, where NetBox (and
therefore ``extras.scripts.Script``) is not importable.
"""

from __future__ import annotations

import ast

import pytest

from .conftest import get_plugin_source_dir

_SCRIPT_BASE_NAMES = {"Script", "BaseScript"}


def _script_classes(source: str, filename: str) -> list[str]:
    """Return the names of top-level ``Script`` subclasses defined in ``source``."""
    tree = ast.parse(source, filename=filename)
    return [
        node.name
        for node in tree.body
        if isinstance(node, ast.ClassDef)
        and any(
            (base.attr if isinstance(base, ast.Attribute) else getattr(base, "id", None)) in _SCRIPT_BASE_NAMES
            for base in node.bases
        )
    ]


def _package_exports(source: str, filename: str) -> tuple[set[str], set[str]]:
    """Return ``(imported_names, dunder_all_names)`` declared in ``__init__.py``."""
    tree = ast.parse(source, filename=filename)

    imported: set[str] = set()
    exported: set[str] = set()

    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            imported.update(alias.asname or alias.name for alias in node.names)
        elif (
            isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "__all__" for target in node.targets)
            and isinstance(node.value, ast.List | ast.Tuple)
        ):
            exported.update(
                element.value
                for element in node.value.elts
                if isinstance(element, ast.Constant) and isinstance(element.value, str)
            )

    return imported, exported


@pytest.mark.unit
def test_every_bundled_script_is_exported_from_the_package() -> None:
    """Each Script subclass must be importable from ``netbox_ssl.scripts`` (issue #163)."""
    scripts_dir = get_plugin_source_dir() / "scripts"
    assert scripts_dir.is_dir(), f"scripts dir not found: {scripts_dir}"

    init_file = scripts_dir / "__init__.py"
    imported, exported = _package_exports(init_file.read_text(), init_file.name)

    missing: list[str] = []
    for py_file in sorted(scripts_dir.glob("*.py")):
        if py_file.name == "__init__.py":
            continue
        for class_name in _script_classes(py_file.read_text(), py_file.name):
            if class_name not in imported:
                missing.append(f"{class_name} ({py_file.name}) is not imported in scripts/__init__.py")
            if class_name not in exported:
                missing.append(f"{class_name} ({py_file.name}) is not listed in scripts/__init__.py __all__")

    assert not missing, (
        "Bundled NetBox Scripts are unreachable through the documented entry point "
        "`from netbox_ssl.scripts import <ClassName>`, so users cannot register them "
        "in SCRIPTS_ROOT:\n  " + "\n  ".join(missing)
    )


@pytest.mark.unit
def test_documented_scripts_match_the_package_exports() -> None:
    """``docs/reference/scripts.md`` must list exactly the exported scripts (issue #163)."""
    scripts_dir = get_plugin_source_dir() / "scripts"
    init_file = scripts_dir / "__init__.py"
    _, exported = _package_exports(init_file.read_text(), init_file.name)

    docs_file = get_plugin_source_dir().parent / "docs" / "reference" / "scripts.md"
    if not docs_file.is_file():
        pytest.skip("docs/ not available (in-container runs copy only tests/)")

    documented = {name for name in exported if name in docs_file.read_text()}
    undocumented = sorted(exported - documented)

    assert not undocumented, (
        "These scripts are exported from netbox_ssl.scripts but never mentioned in "
        "docs/reference/scripts.md, so users will not know to register them:\n  " + "\n  ".join(undocumented)
    )
