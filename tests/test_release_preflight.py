"""Unit tests for the pre-cut release-rehearsal checker (scripts/release_preflight.py).

Each check guards a release-critical invariant that has broken a past release:
version drift, a missing dated CHANGELOG section, a stale NetBox support matrix
(#110-adjacent README badge), the publish gate budget (#141/#142), and the
gh-pages serialization guard (#110). The parsers are pure (text in, data out)
so they test with small fixtures; a handful of smoke tests run the real checks
against this repo's actual files to catch drift.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_preflight():
    """Load scripts/release_preflight.py by path (it lives outside any package)."""
    path = _REPO_ROOT / "scripts" / "release_preflight.py"
    spec = importlib.util.spec_from_file_location("release_preflight", path)
    module = importlib.util.module_from_spec(spec)
    # Register before exec: Python 3.12's @dataclass resolves cls.__module__ via
    # sys.modules, which raises AttributeError if the module isn't registered.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


rp = _load_preflight()


# --------------------------------------------------------------------------- #
# Fixtures — minimal slices of each real file format                           #
# --------------------------------------------------------------------------- #

PYPROJECT = """\
[build-system]
requires = ["setuptools>=61.0"]

[project]
name = "netbox-ssl"
version = "1.3.0"
description = "x"
"""

INIT = '''\
"""docstring"""
from netbox.plugins import PluginConfig

__version__ = "1.3.0"


class NetBoxSSLConfig(PluginConfig):
    version = __version__
    min_version = "4.4.0"
    max_version = "4.6.99"
'''

CHANGELOG = """\
# Changelog

## [Unreleased]

### Added

- nothing yet

## [1.3.0] - 2026-06-21

### Added

- the thing

## [1.2.2] - 2026-06-05

### Fixed

- a bug
"""

README_OK = """\
<a href="x"><img src="https://img.shields.io/badge/NetBox-4.4%20%7C%204.5%20%7C%204.6-blue.svg" alt="NetBox"></a>

| 4.6.x | 1.2.x | Primary |
| 4.5.x | 1.2.x | Supported |
| 4.4.x | 1.2.x | Supported |
| 4.3.x and older | — | Unsupported |
"""

# Badge says 4.4 | 4.5 (missing 4.6) but the table below DOES mention 4.6 — a
# whole-document token scan would pass; only a badge-specific parser catches it.
README_STALE_BADGE = """\
<a href="x"><img src="https://img.shields.io/badge/NetBox-4.4%20%7C%204.5-blue.svg" alt="NetBox"></a>

| 4.6.x | 1.2.x | Primary |
| 4.5.x | 1.2.x | Supported |
| 4.4.x | 1.2.x | Supported |
"""

COMPAT_OK = """\
| Plugin Version | NetBox Version | Status |
| 1.2.x | 4.6.x | Primary |
| 1.2.x | 4.5.x | Supported |
| 1.2.x | 4.4.x | Supported |
| any | 4.3.x or older | Unsupported |
"""

COMPAT_MISSING_46 = """\
| 1.2.x | 4.5.x | Supported |
| 1.2.x | 4.4.x | Supported |
"""

PUBLISH_OK = """\
jobs:
  verify-ci:
    steps:
      - run: |
          for i in $(seq 1 90); do
            status=$(gh run list ...)
            sleep 20
          done
"""

PUBLISH_SHORT = """\
          for i in $(seq 1 30); do
            sleep 20
          done
"""

DOCS_OK = """\
name: Docs Deploy
concurrency:
  group: gh-pages-deploy
  cancel-in-progress: false
"""

DOCS_NO_GUARD = """\
name: Docs Deploy
jobs:
  deploy:
    runs-on: ubuntu-latest
"""

DOCS_CANCEL_TRUE = """\
concurrency:
  group: gh-pages-deploy
  cancel-in-progress: true
"""


# --------------------------------------------------------------------------- #
# Pure parsers                                                                 #
# --------------------------------------------------------------------------- #


def test_extract_pyproject_version():
    assert rp.extract_pyproject_version(PYPROJECT) == "1.3.0"


def test_extract_init_version():
    assert rp.extract_init_version(INIT) == "1.3.0"


def test_changelog_release_versions_excludes_unreleased():
    versions = rp.changelog_release_versions(CHANGELOG)
    assert versions == {"1.3.0", "1.2.2"}
    assert "Unreleased" not in versions


def test_supported_netbox_minors_spans_min_to_max():
    assert rp.supported_netbox_minors(INIT) == {"4.4", "4.5", "4.6"}


def test_badge_netbox_minors_parses_url_encoded_pipe():
    assert rp.badge_netbox_minors(README_OK) == {"4.4", "4.5", "4.6"}
    assert rp.badge_netbox_minors(README_STALE_BADGE) == {"4.4", "4.5"}


def test_netbox_minors_mentioned():
    assert {"4.4", "4.5", "4.6"} <= rp.netbox_minors_mentioned(COMPAT_OK)
    assert "4.6" not in rp.netbox_minors_mentioned(COMPAT_MISSING_46)


def test_gate_budget_seconds():
    assert rp.gate_budget_seconds(PUBLISH_OK) == 1800
    assert rp.gate_budget_seconds(PUBLISH_SHORT) == 600
    assert rp.gate_budget_seconds("no loop here") is None


def test_docs_has_serialization_guard():
    assert rp.docs_has_serialization_guard(DOCS_OK) is True
    assert rp.docs_has_serialization_guard(DOCS_NO_GUARD) is False
    assert rp.docs_has_serialization_guard(DOCS_CANCEL_TRUE) is False


# --------------------------------------------------------------------------- #
# Checks (return a CheckResult)                                                #
# --------------------------------------------------------------------------- #


def test_check_version_consistency_pass():
    r = rp.check_version_consistency("1.3.0", PYPROJECT, INIT)
    assert r.passed is True


def test_check_version_consistency_detects_target_mismatch():
    r = rp.check_version_consistency("1.4.0", PYPROJECT, INIT)
    assert r.passed is False
    assert "1.4.0" in r.detail


def test_check_version_consistency_detects_file_drift():
    drifted_init = INIT.replace("1.3.0", "1.2.9")
    r = rp.check_version_consistency("1.3.0", PYPROJECT, drifted_init)
    assert r.passed is False


def test_check_changelog_has_release_pass():
    assert rp.check_changelog_has_release("1.3.0", CHANGELOG).passed is True


def test_check_changelog_has_release_fail_when_missing():
    r = rp.check_changelog_has_release("1.4.0", CHANGELOG)
    assert r.passed is False
    assert "1.4.0" in r.detail


def test_check_netbox_support_matrix_pass():
    r = rp.check_netbox_support_matrix(INIT, README_OK, COMPAT_OK)
    assert r.passed is True


def test_check_netbox_support_matrix_catches_stale_badge():
    r = rp.check_netbox_support_matrix(INIT, README_STALE_BADGE, COMPAT_OK)
    assert r.passed is False
    assert "badge" in r.detail.lower()


def test_check_netbox_support_matrix_catches_missing_version():
    r = rp.check_netbox_support_matrix(INIT, README_OK, COMPAT_MISSING_46)
    assert r.passed is False
    assert "4.6" in r.detail


def test_check_publish_gate_budget_pass():
    assert rp.check_publish_gate_budget(PUBLISH_OK).passed is True


def test_check_publish_gate_budget_fail_when_too_short():
    r = rp.check_publish_gate_budget(PUBLISH_SHORT)
    assert r.passed is False
    assert "600" in r.detail


def test_check_docs_serialization_guard_pass():
    assert rp.check_docs_serialization_guard(DOCS_OK).passed is True


def test_check_docs_serialization_guard_fail():
    assert rp.check_docs_serialization_guard(DOCS_NO_GUARD).passed is False


# --------------------------------------------------------------------------- #
# Orchestration                                                               #
# --------------------------------------------------------------------------- #


def test_run_all_checks_returns_one_result_per_check():
    results = rp.run_all_checks(_REPO_ROOT, "1.2.2")
    assert len(results) >= 5
    assert all(isinstance(r, rp.CheckResult) for r in results)


# --------------------------------------------------------------------------- #
# Smoke tests against this repo's REAL files — guard against drift             #
# --------------------------------------------------------------------------- #


def test_real_repo_version_files_agree():
    pyproject = (_REPO_ROOT / "pyproject.toml").read_text()
    init = (_REPO_ROOT / "netbox_ssl" / "__init__.py").read_text()
    assert rp.extract_pyproject_version(pyproject) == rp.extract_init_version(init)


def test_real_repo_support_matrix_is_consistent():
    init = (_REPO_ROOT / "netbox_ssl" / "__init__.py").read_text()
    readme = (_REPO_ROOT / "README.md").read_text()
    compat = (_REPO_ROOT / "COMPATIBILITY.md").read_text()
    r = rp.check_netbox_support_matrix(init, readme, compat)
    assert r.passed is True, r.detail


def test_real_repo_publish_gate_budget_is_sufficient():
    publish = (_REPO_ROOT / ".github" / "workflows" / "publish.yml").read_text()
    assert rp.check_publish_gate_budget(publish).passed is True


def test_real_repo_docs_has_serialization_guard():
    docs = (_REPO_ROOT / ".github" / "workflows" / "docs.yml").read_text()
    assert rp.check_docs_serialization_guard(docs).passed is True
