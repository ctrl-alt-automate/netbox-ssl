#!/usr/bin/env python3
"""
Comprehensive test runner for NetBox SSL plugin.

This script provides a unified interface for running all types of tests:
1. Unit tests (pytest, no Django/database required)
2. Integration tests (pytest-django with database)
3. Browser tests (Playwright)
4. Smoke tests (HTTP checks against running instance)
5. Django system checks

Usage:
    python scripts/run_tests.py                    # Run all tests
    python scripts/run_tests.py --unit             # Unit tests only
    python scripts/run_tests.py --browser          # Browser tests only
    python scripts/run_tests.py --smoke            # Smoke tests only
    python scripts/run_tests.py --checks           # Django checks only
    python scripts/run_tests.py --coverage         # With coverage report
"""

import argparse
import subprocess
import sys
import os
from pathlib import Path


# Colors for terminal output
class Colors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"


def print_header(text):
    """Print a section header."""
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'=' * 60}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{text}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'=' * 60}{Colors.ENDC}\n")


def print_success(text):
    """Print success message."""
    print(f"{Colors.OKGREEN}✓ {text}{Colors.ENDC}")


def print_error(text):
    """Print error message."""
    print(f"{Colors.FAIL}✗ {text}{Colors.ENDC}")


def print_warning(text):
    """Print warning message."""
    print(f"{Colors.WARNING}⚠ {text}{Colors.ENDC}")


def print_info(text):
    """Print info message."""
    print(f"{Colors.OKCYAN}ℹ {text}{Colors.ENDC}")


def run_command(cmd, description, capture_output=False):
    """Run a shell command and report results."""
    print_info(f"Running: {description}")
    print(f"  Command: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=capture_output,
            text=True,
            cwd=Path(__file__).parent.parent,
        )

        if result.returncode == 0:
            print_success(f"{description} passed")
            return True
        else:
            print_error(f"{description} failed (exit code: {result.returncode})")
            if capture_output and result.stderr:
                print(result.stderr)
            return False

    except FileNotFoundError:
        print_error(f"Command not found: {cmd[0]}")
        return False
    except Exception as e:
        print_error(f"Error running {description}: {e}")
        return False


def run_unit_tests(coverage=False):
    """Run pytest unit tests."""
    print_header("Running Unit Tests (pytest)")

    cmd = ["python", "-m", "pytest", "tests/", "-v", "-m", "unit"]

    if coverage:
        cmd.extend(["--cov=netbox_ssl", "--cov-report=term-missing"])

    return run_command(cmd, "Unit tests")


def run_parser_tests():
    """Run parser-specific tests."""
    print_header("Running Parser Tests")

    cmd = ["python", "-m", "pytest", "tests/test_parser.py", "-v"]

    return run_command(cmd, "Parser tests")


def run_browser_tests():
    """Run Playwright browser tests."""
    print_header("Running Browser Tests (Playwright)")

    # Check if Playwright is available
    try:
        import playwright

        print_success("Playwright is installed")
    except ImportError:
        print_warning("Playwright not installed, skipping browser tests")
        print_info("Install with: pip install playwright && playwright install")
        return True  # Don't fail if not installed

    cmd = [
        "python",
        "-m",
        "pytest",
        "tests/test_browser.py",
        "-v",
        "-m",
        "browser",
        "--tb=short",
        "-p",
        "no:django",  # Disable pytest-django for browser tests
    ]

    return run_command(cmd, "Browser tests")


def run_smoke_tests():
    """Run HTTP smoke tests against running NetBox instance."""
    print_header("Running Smoke Tests")

    netbox_url = os.environ.get("NETBOX_URL", "http://localhost:8000")
    print_info(f"Testing against: {netbox_url}")

    cmd = ["python", "scripts/smoke_test.py", "--base-url", netbox_url]

    return run_command(cmd, "Smoke tests")


def run_django_checks():
    """Run Django system checks."""
    print_header("Running Django System Checks")

    # We need to run this inside the NetBox container or with proper Django setup
    print_info("Django checks verify plugin configuration and dependencies")

    # Try to run checks via docker exec if container is running
    docker_cmd = [
        "docker",
        "exec",
        "netbox-ssl-netbox-1",
        "python",
        "/opt/netbox/netbox/manage.py",
        "check",
        "--tag",
        "netbox_ssl",
    ]

    result = run_command(docker_cmd, "Django system checks (via Docker)")

    if not result:
        print_warning("Could not run checks via Docker.")
        print_info("You can run checks manually inside NetBox:")
        print_info("  docker exec -it netbox-ssl-netbox-1 python /opt/netbox/netbox/manage.py check")

    return result


def run_all_checks():
    """Run all Django checks including built-in ones."""
    print_header("Running All Django Checks")

    docker_cmd = [
        "docker",
        "exec",
        "netbox-ssl-netbox-1",
        "python",
        "/opt/netbox/netbox/manage.py",
        "check",
    ]

    return run_command(docker_cmd, "All Django checks (via Docker)")


def check_netbox_running():
    """Check if NetBox is running."""
    print_info("Checking if NetBox is running...")

    try:
        import requests

        netbox_url = os.environ.get("NETBOX_URL", "http://localhost:8000")
        resp = requests.get(f"{netbox_url}/login/", timeout=5)
        if resp.status_code == 200:
            print_success(f"NetBox is running at {netbox_url}")
            return True
    except Exception:
        pass

    print_warning("NetBox does not appear to be running")
    print_info("Start with: docker-compose up -d")
    return False


def main():
    parser = argparse.ArgumentParser(
        description="Run NetBox SSL plugin tests",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s                      Run all tests
    %(prog)s --unit               Unit tests only
    %(prog)s --browser            Browser tests only (requires running NetBox)
    %(prog)s --smoke              Smoke tests only (requires running NetBox)
    %(prog)s --checks             Django system checks only
    %(prog)s --coverage           Include coverage report
    %(prog)s --unit --coverage    Unit tests with coverage
        """,
    )

    parser.add_argument("--unit", action="store_true", help="Run unit tests")
    parser.add_argument("--parser", action="store_true", help="Run parser tests")
    parser.add_argument("--browser", action="store_true", help="Run browser tests")
    parser.add_argument("--smoke", action="store_true", help="Run smoke tests")
    parser.add_argument("--checks", action="store_true", help="Run Django checks")
    parser.add_argument("--all-checks", action="store_true", help="Run all Django checks")
    parser.add_argument("--coverage", action="store_true", help="Include coverage report")
    parser.add_argument("--quick", action="store_true", help="Quick tests (unit + parser only)")

    args = parser.parse_args()

    # If no specific test type selected, run all
    run_all = not any([args.unit, args.parser, args.browser, args.smoke, args.checks, args.all_checks, args.quick])

    results = []

    print_header("NetBox SSL Plugin Test Suite")
    print_info(f"Working directory: {Path(__file__).parent.parent}")

    # Quick mode: just unit and parser tests
    if args.quick:
        results.append(("Unit tests", run_unit_tests(args.coverage)))
        results.append(("Parser tests", run_parser_tests()))

    else:
        # Unit tests
        if run_all or args.unit:
            results.append(("Unit tests", run_unit_tests(args.coverage)))

        # Parser tests
        if run_all or args.parser:
            results.append(("Parser tests", run_parser_tests()))

        # Browser tests (require running NetBox)
        if args.browser or (run_all and check_netbox_running()):
            results.append(("Browser tests", run_browser_tests()))

        # Smoke tests (require running NetBox)
        if args.smoke or (run_all and check_netbox_running()):
            results.append(("Smoke tests", run_smoke_tests()))

        # Django checks (require running NetBox container)
        if args.checks:
            results.append(("Django checks", run_django_checks()))

        if args.all_checks:
            results.append(("All Django checks", run_all_checks()))

    # Summary
    print_header("Test Summary")

    passed = sum(1 for _, success in results if success)
    failed = sum(1 for _, success in results if not success)

    for name, success in results:
        if success:
            print_success(name)
        else:
            print_error(name)

    print()
    print(f"Total: {passed} passed, {failed} failed")

    if failed > 0:
        print_error("Some tests failed!")
        sys.exit(1)
    else:
        print_success("All tests passed!")
        sys.exit(0)


if __name__ == "__main__":
    main()
