"""Regression guard for ``ObjectVar`` usage in bundled NetBox Scripts.

NetBox's ``ObjectVar`` requires ``model`` to be a model **class** — its
``__init__`` immediately calls ``model.objects.all()``. Passing a dotted
string (e.g. ``ObjectVar(model="tenancy.Tenant")``) raises
``AttributeError: 'str' object has no attribute 'objects'`` at class-body
evaluation time, which makes the whole script module fail to import — so the
script can never be registered or run in NetBox (issue #143).

This stayed hidden because NetBox never imports plugin-bundled scripts at
startup, and the script unit tests skip themselves when the import fails
(``script_available()`` swallows the error). This AST guard fails fast on any
``ObjectVar``/``MultiObjectVar`` call whose ``model`` is a string literal,
under any Python/Django version (the host unit lane does not run real NetBox).
"""

from __future__ import annotations

import ast

import pytest

from .conftest import get_plugin_source_dir

_OBJECT_VAR_NAMES = {"ObjectVar", "MultiObjectVar"}


def _string_model_violations(source: str, filename: str) -> list[str]:
    """Return ``"file:line"`` for every ObjectVar called with a string model."""
    tree = ast.parse(source, filename=filename)
    violations: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
        if name not in _OBJECT_VAR_NAMES:
            continue
        for kw in node.keywords:
            if kw.arg == "model" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                violations.append(f"{filename}:{kw.value.lineno}")
    return violations


@pytest.mark.unit
def test_objectvar_model_is_a_class_not_a_string() -> None:
    """No bundled script may pass a string to ObjectVar(model=...) (issue #143)."""
    scripts_dir = get_plugin_source_dir() / "scripts"
    assert scripts_dir.is_dir(), f"scripts dir not found: {scripts_dir}"

    all_violations: list[str] = []
    for py_file in sorted(scripts_dir.glob("*.py")):
        all_violations.extend(_string_model_violations(py_file.read_text(), py_file.name))

    assert not all_violations, (
        "ObjectVar(model=...) was given a string instead of a model class. NetBox "
        "calls model.objects.all(), so the script fails to import and cannot be "
        "registered. Import the model and pass the class (e.g. model=Tenant):\n  " + "\n  ".join(all_violations)
    )
