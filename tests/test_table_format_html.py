"""Regression guard for Django 6.0 ``format_html`` usage in table modules.

Django 6.0 (shipped with NetBox 4.6) made ``format_html()`` raise
``TypeError: args or kwargs must be provided.`` when called with only a
literal format string and no interpolation arguments.  Earlier Django
versions merely emitted a ``RemovedInDjango60Warning``.

Several table ``render_*`` methods rendered static badges via
``format_html("<span ...>...</span>")`` with no args, which crashed the
list view as soon as a row needed rendering (issue #137: the Certificate
Authorities list page threw a 500 once at least one CA existed).

The correct tool for trusted *static* HTML is ``mark_safe``;
``format_html`` is only for interpolating values with escaping.  This test
fails if any ``format_html`` call in the tables package is missing
interpolation arguments, catching the regression under any Python/Django
version (the host unit lane does not run Django 6.0).
"""

from __future__ import annotations

import ast

import pytest

from .conftest import get_plugin_source_dir


def _format_html_violations(source: str, filename: str) -> list[str]:
    """Return ``"file:line"`` for every arg-less ``format_html`` call."""
    tree = ast.parse(source, filename=filename)
    violations: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
        if name != "format_html":
            continue
        # format_html(format_string, *args, **kwargs) needs at least one
        # interpolation argument beyond the format string itself.
        if len(node.args) < 2 and not node.keywords:
            violations.append(f"{filename}:{node.lineno}")
    return violations


@pytest.mark.unit
def test_no_argless_format_html_in_tables() -> None:
    """No table render method may call ``format_html`` without args (Django 6.0)."""
    tables_dir = get_plugin_source_dir() / "tables"
    assert tables_dir.is_dir(), f"tables dir not found: {tables_dir}"

    all_violations: list[str] = []
    for py_file in sorted(tables_dir.glob("*.py")):
        all_violations.extend(_format_html_violations(py_file.read_text(), py_file.name))

    assert not all_violations, (
        "format_html() called without interpolation args (raises TypeError on "
        "Django 6.0 / NetBox 4.6). Use mark_safe() for static HTML instead:\n  " + "\n  ".join(all_violations)
    )
