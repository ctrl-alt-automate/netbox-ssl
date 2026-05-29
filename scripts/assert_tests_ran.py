#!/usr/bin/env python3
"""Fail CI if a pytest JUnit XML shows zero tests, or any skipped/failed/errored.

Used by the integration job to guarantee the #111/#112 regression gates
actually EXECUTE. A ``@requires_netbox`` test that silently *skips* is not a
gate — a silent skip is exactly how the #111 schema crash stayed invisible in
CI. This turns "ran 0 / all skipped" into a hard failure.

Usage: python scripts/assert_tests_ran.py <junit-xml-path>
"""

import sys

# Prefer defusedxml (hardened against XXE / billion-laughs). The input here is
# our own pytest-generated JUnit XML (trusted), but use the safe parser when
# available and fall back to stdlib only if defusedxml is not installed.
try:
    from defusedxml import ElementTree as ET
except ImportError:  # pragma: no cover - defusedxml may be absent locally
    import xml.etree.ElementTree as ET


def main(path: str) -> int:
    root = ET.parse(path).getroot()
    suites = root.findall("testsuite") or [root]
    tests = sum(int(s.get("tests", 0)) for s in suites)
    skipped = sum(int(s.get("skipped", 0)) for s in suites)
    failures = sum(int(s.get("failures", 0)) for s in suites)
    errors = sum(int(s.get("errors", 0)) for s in suites)

    problems = []
    if tests == 0:
        problems.append("zero tests ran")
    if skipped:
        problems.append(f"{skipped} skipped (regression gates must run, not skip)")
    if failures:
        problems.append(f"{failures} failed")
    if errors:
        problems.append(f"{errors} errored")

    if problems:
        print("Regression gate check FAILED: " + "; ".join(problems), file=sys.stderr)
        return 1
    print(f"Regression gate check OK: {tests} tests ran; 0 skipped, 0 failed, 0 errored.")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: assert_tests_ran.py <junit-xml-path>", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
