#!/usr/bin/env python3
"""Pre-cut release rehearsal for the NetBox SSL plugin.

Run this BEFORE tagging a release. It asserts the release-critical invariants
that have each broken a past release, by *inspecting files only* — no network,
no container, no ``netbox_ssl`` import — so it runs anywhere in well under a
second:

  - **version drift** between ``pyproject.toml`` and ``netbox_ssl/__init__.py``
  - **CHANGELOG** missing a dated ``## [X.Y.Z] - YYYY-MM-DD`` section for the
    release you are about to cut
  - **NetBox support matrix** stale across the PluginConfig ``min_version`` /
    ``max_version``, the README badge + table, and ``COMPATIBILITY.md``
    (a stale README badge shipped in v1.2.x)
  - **publish gate budget** — the ``verify-ci`` poll loop in ``publish.yml`` must
    outlast the integration matrix, or the tag-push Publish run times out before
    CI goes green (#141 / #142)
  - **gh-pages serialization guard** — ``docs.yml`` must keep its ``concurrency``
    group with ``cancel-in-progress: false`` or the release docs deploy races
    the main-push deploy (#110)

Usage::

    python scripts/release_preflight.py 1.3.0
    python scripts/release_preflight.py 1.3.0 --repo-root /path/to/repo

Exits 0 if every check passes, 1 if any fail.
"""

from __future__ import annotations

import argparse
import re
import sys
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

# The publish.yml verify-ci gate must poll for at least this long. The slowest
# integration job (NetBox 4.4) has been observed at ~16.5 min; 25 min leaves
# margin without waiting absurdly long. See #141 / #142.
MIN_GATE_SECONDS = 1500


@dataclass(frozen=True)
class CheckResult:
    """Outcome of a single preflight check."""

    name: str
    passed: bool
    detail: str


# --------------------------------------------------------------------------- #
# Pure parsers — text in, data out, no I/O                                     #
# --------------------------------------------------------------------------- #


def extract_pyproject_version(text: str) -> str | None:
    """Return the ``[project] version`` string from pyproject.toml, or None."""
    match = re.search(r"""(?m)^version\s*=\s*["']([^"']+)["']""", text)
    return match.group(1) if match else None


def extract_init_version(text: str) -> str | None:
    """Return ``__version__`` from netbox_ssl/__init__.py, or None."""
    match = re.search(r"""(?m)^__version__\s*=\s*["']([^"']+)["']""", text)
    return match.group(1) if match else None


def changelog_release_versions(text: str) -> set[str]:
    """Return every dated ``## [X.Y.Z] - YYYY-MM-DD`` version (excludes Unreleased)."""
    return set(re.findall(r"(?m)^##\s*\[(\d+\.\d+\.\d+)\]\s*-\s*\d{4}-\d{2}-\d{2}", text))


def supported_netbox_minors(init_text: str) -> set[str]:
    """Derive the supported ``major.minor`` NetBox versions from PluginConfig.

    Reads ``min_version`` / ``max_version`` and expands the inclusive range of
    minors (e.g. 4.4.0 .. 4.6.99 -> {"4.4", "4.5", "4.6"}).
    """
    lo = re.search(r"""min_version\s*=\s*["'](\d+)\.(\d+)""", init_text)
    hi = re.search(r"""max_version\s*=\s*["'](\d+)\.(\d+)""", init_text)
    if not lo or not hi:
        return set()
    major = int(lo.group(1))
    lo_minor, hi_minor = int(lo.group(2)), int(hi.group(2))
    return {f"{major}.{minor}" for minor in range(lo_minor, hi_minor + 1)}


def badge_netbox_minors(readme_text: str) -> set[str]:
    """Extract the NetBox minors from the README shields.io badge.

    The badge label is URL-encoded (``4.4%20%7C%204.5`` = ``4.4 | 4.5``). A
    whole-document version scan would miss a stale badge when the table below it
    is current, so this parser is intentionally badge-specific.
    """
    match = re.search(r"badge/NetBox-(.+?)-[a-z]+\.svg", readme_text)
    if not match:
        return set()
    decoded = urllib.parse.unquote(match.group(1))
    return {f"4.{minor}" for minor in re.findall(r"4\.(\d+)", decoded)}


def netbox_minors_mentioned(text: str) -> set[str]:
    """Return every ``4.x`` NetBox minor mentioned anywhere in the text."""
    return {f"4.{minor}" for minor in re.findall(r"4\.(\d+)", text)}


def gate_budget_seconds(publish_yml_text: str) -> int | None:
    """Compute the verify-ci poll budget (``seq 1 N`` x ``sleep M``) in seconds."""
    seq = re.search(r"seq\s+1\s+(\d+)", publish_yml_text)
    sleep = re.search(r"sleep\s+(\d+)", publish_yml_text)
    if not seq or not sleep:
        return None
    return int(seq.group(1)) * int(sleep.group(1))


def docs_has_serialization_guard(docs_yml_text: str) -> bool:
    """True iff docs.yml keeps a concurrency group with cancel-in-progress:false."""
    has_group = "concurrency:" in docs_yml_text
    keeps_runs = bool(re.search(r"cancel-in-progress:\s*false", docs_yml_text))
    return has_group and keeps_runs


# --------------------------------------------------------------------------- #
# Checks — return a CheckResult                                                #
# --------------------------------------------------------------------------- #


def check_version_consistency(target: str, pyproject_text: str, init_text: str) -> CheckResult:
    pyproject_version = extract_pyproject_version(pyproject_text)
    init_version = extract_init_version(init_text)
    passed = pyproject_version == init_version == target
    if passed:
        detail = f"pyproject.toml, __init__.py and the target all read {target}"
    else:
        detail = (
            f"version mismatch — target={target}, pyproject.toml={pyproject_version}, "
            f"__init__.py={init_version} (all three must match)"
        )
    return CheckResult("version consistency", passed, detail)


def check_changelog_has_release(target: str, changelog_text: str) -> CheckResult:
    versions = changelog_release_versions(changelog_text)
    passed = target in versions
    if passed:
        detail = f"CHANGELOG has a dated '## [{target}]' section"
    else:
        detail = (
            f"CHANGELOG has no dated '## [{target}] - YYYY-MM-DD' section "
            f"(move the Unreleased entries under it). Dated versions found: {sorted(versions)}"
        )
    return CheckResult("changelog release section", passed, detail)


def check_netbox_support_matrix(init_text: str, readme_text: str, compatibility_text: str) -> CheckResult:
    expected = supported_netbox_minors(init_text)
    problems: list[str] = []

    badge = badge_netbox_minors(readme_text)
    if badge != expected:
        problems.append(f"README badge advertises {sorted(badge)} but PluginConfig supports {sorted(expected)}")

    missing_readme = expected - netbox_minors_mentioned(readme_text)
    if missing_readme:
        problems.append(f"README never mentions {sorted(missing_readme)}")

    missing_compat = expected - netbox_minors_mentioned(compatibility_text)
    if missing_compat:
        problems.append(f"COMPATIBILITY.md never mentions {sorted(missing_compat)}")

    passed = not problems
    if passed:
        detail = f"NetBox {sorted(expected)} consistent across PluginConfig, README, and COMPATIBILITY.md"
    else:
        detail = "; ".join(problems)
    return CheckResult("netbox support matrix", passed, detail)


def check_publish_gate_budget(publish_yml_text: str, min_seconds: int = MIN_GATE_SECONDS) -> CheckResult:
    budget = gate_budget_seconds(publish_yml_text)
    if budget is None:
        return CheckResult(
            "publish gate budget",
            False,
            "could not find the verify-ci 'seq 1 N / sleep M' poll loop in publish.yml",
        )
    passed = budget >= min_seconds
    if passed:
        detail = f"verify-ci gate polls for {budget}s (>= {min_seconds}s required)"
    else:
        detail = (
            f"verify-ci gate polls only {budget}s; the integration matrix can take >16min, so the "
            f"tag-push Publish run will time out before CI goes green — raise it to >= {min_seconds}s "
            f"(see #141 / #142)"
        )
    return CheckResult("publish gate budget", passed, detail)


def check_docs_serialization_guard(docs_yml_text: str) -> CheckResult:
    passed = docs_has_serialization_guard(docs_yml_text)
    if passed:
        detail = "docs.yml keeps the gh-pages concurrency group with cancel-in-progress: false"
    else:
        detail = (
            "docs.yml is missing the gh-pages serialization guard (a concurrency group with "
            "cancel-in-progress: false); the tag-push docs deploy will race the main-push deploy "
            "(see #110)"
        )
    return CheckResult("docs gh-pages serialization guard", passed, detail)


# --------------------------------------------------------------------------- #
# Orchestration + CLI                                                          #
# --------------------------------------------------------------------------- #


def run_all_checks(repo_root: Path | str, target_version: str) -> list[CheckResult]:
    """Read the repo's release-critical files and run every check."""
    root = Path(repo_root)

    def read(*parts: str) -> str:
        return root.joinpath(*parts).read_text(encoding="utf-8")

    pyproject = read("pyproject.toml")
    init = read("netbox_ssl", "__init__.py")
    changelog = read("CHANGELOG.md")
    readme = read("README.md")
    compatibility = read("COMPATIBILITY.md")
    publish = read(".github", "workflows", "publish.yml")
    docs = read(".github", "workflows", "docs.yml")

    return [
        check_version_consistency(target_version, pyproject, init),
        check_changelog_has_release(target_version, changelog),
        check_netbox_support_matrix(init, readme, compatibility),
        check_publish_gate_budget(publish),
        check_docs_serialization_guard(docs),
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Pre-cut release rehearsal — assert release-critical invariants before tagging.",
    )
    parser.add_argument("target_version", help="The version about to be cut, e.g. 1.3.0")
    parser.add_argument(
        "--repo-root",
        default=str(Path(__file__).resolve().parent.parent),
        help="Repository root (defaults to the repo containing this script)",
    )
    args = parser.parse_args(argv)

    results = run_all_checks(Path(args.repo_root), args.target_version)

    print(f"Release preflight for v{args.target_version}")
    print("=" * 70)
    for result in results:
        marker = "PASS" if result.passed else "FAIL"
        print(f"[{marker}] {result.name}: {result.detail}")
    print("=" * 70)

    failures = [r for r in results if not r.passed]
    if failures:
        print(f"{len(failures)} of {len(results)} checks FAILED — fix before tagging.")
        return 1
    print(f"All {len(results)} checks passed — clear to cut v{args.target_version}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
