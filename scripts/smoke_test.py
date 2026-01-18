#!/usr/bin/env python3
"""
Smoke test script for NetBox SSL plugin.

Automatically visits all plugin URLs and checks for errors.
Run from the host machine (not inside Docker).

Usage:
    python scripts/smoke_test.py
    python scripts/smoke_test.py --base-url http://localhost:8000
"""

import argparse
import re
import sys
from dataclasses import dataclass
from urllib.parse import urljoin

import requests


@dataclass
class TestResult:
    url: str
    method: str
    status_code: int
    success: bool
    error: str = ""


class NetBoxSmokeTest:
    """Smoke test runner for NetBox SSL plugin."""

    # All plugin URLs to test
    URLS_TO_TEST = [
        # Certificate URLs
        ("GET", "/plugins/ssl/certificates/"),
        ("GET", "/plugins/ssl/certificates/add/"),
        ("GET", "/plugins/ssl/certificates/import/"),
        # Assignment URLs
        ("GET", "/plugins/ssl/assignments/"),
        ("GET", "/plugins/ssl/assignments/add/"),
        # API URLs
        ("GET", "/api/plugins/ssl/certificates/"),
        ("GET", "/api/plugins/ssl/assignments/"),
    ]

    # Patterns that indicate errors in HTML responses
    ERROR_PATTERNS = [
        r"TemplateSyntaxError",
        r"TemplateDoesNotExist",
        r"ImproperlyConfigured",
        r"ImportError",
        r"AttributeError",
        r"TypeError",
        r"KeyError",
        r"ValueError",
        r"Serverfout",  # Dutch for "Server error"
        r"Server Error",
        r"class=['\"]error['\"]",
        r"Traceback \(most recent call last\)",
    ]

    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.results: list[TestResult] = []
        self.api_token = None

    def login(self) -> bool:
        """Login to NetBox and get session + API token."""
        print(f"🔐 Logging in to {self.base_url}...")

        # Get CSRF token from login page
        login_url = urljoin(self.base_url, "/login/")
        resp = self.session.get(login_url)
        if resp.status_code != 200:
            print(f"❌ Could not reach login page: {resp.status_code}")
            return False

        # Extract CSRF token
        csrf_match = re.search(r'name=["\']csrfmiddlewaretoken["\'] value=["\']([^"\']+)["\']', resp.text)
        if not csrf_match:
            print("❌ Could not find CSRF token")
            return False

        csrf_token = csrf_match.group(1)

        # Login
        login_data = {
            "csrfmiddlewaretoken": csrf_token,
            "username": self.username,
            "password": self.password,
            "next": "/",
        }
        resp = self.session.post(login_url, data=login_data, allow_redirects=True)

        if "logout" not in resp.text.lower() and resp.status_code != 200:
            print(f"❌ Login failed: {resp.status_code}")
            return False

        print("✅ Logged in successfully")

        # Get API token for API tests
        self._get_api_token()

        return True

    def _get_api_token(self):
        """Try to get or create an API token."""
        # For testing, we'll use basic auth or the pre-configured token
        # The default superuser token from docker setup
        self.api_token = "0123456789abcdef0123456789abcdef01234567"

    def check_for_errors(self, response: requests.Response) -> str:
        """Check response for error patterns."""
        # Check status code
        if response.status_code >= 500:
            return f"HTTP {response.status_code}"

        if response.status_code == 404:
            return "404 Not Found"

        # Check for error patterns in HTML
        for pattern in self.ERROR_PATTERNS:
            if re.search(pattern, response.text, re.IGNORECASE):
                # Extract a snippet of the error
                match = re.search(f".{{0,50}}{pattern}.{{0,100}}", response.text, re.IGNORECASE)
                snippet = match.group(0) if match else pattern
                # Clean up HTML
                snippet = re.sub(r"<[^>]+>", " ", snippet)
                snippet = re.sub(r"\s+", " ", snippet).strip()
                return f"Error pattern found: {snippet[:100]}"

        return ""

    def test_url(self, method: str, path: str) -> TestResult:
        """Test a single URL."""
        url = urljoin(self.base_url, path)
        headers = {}

        # Add API token for API requests
        if "/api/" in path and self.api_token:
            headers["Authorization"] = f"Token {self.api_token}"

        try:
            if method == "GET":
                resp = self.session.get(url, headers=headers, timeout=30)
            else:
                resp = self.session.request(method, url, headers=headers, timeout=30)

            error = self.check_for_errors(resp)
            success = not error and resp.status_code < 400

            return TestResult(
                url=path,
                method=method,
                status_code=resp.status_code,
                success=success,
                error=error,
            )
        except requests.RequestException as e:
            return TestResult(
                url=path,
                method=method,
                status_code=0,
                success=False,
                error=str(e),
            )

    def test_dynamic_urls(self):
        """Test URLs that depend on existing data."""
        # First, get list of certificates
        api_url = urljoin(self.base_url, "/api/plugins/ssl/certificates/")
        headers = {}
        if self.api_token:
            headers["Authorization"] = f"Token {self.api_token}"

        try:
            resp = self.session.get(api_url, headers=headers, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                results = data.get("results", [])
                if results:
                    cert_id = results[0].get("id")
                    if cert_id:
                        # Test certificate detail page
                        self.URLS_TO_TEST.extend(
                            [
                                ("GET", f"/plugins/ssl/certificates/{cert_id}/"),
                                ("GET", f"/plugins/ssl/certificates/{cert_id}/edit/"),
                                ("GET", f"/plugins/ssl/certificates/{cert_id}/changelog/"),
                                ("GET", f"/api/plugins/ssl/certificates/{cert_id}/"),
                            ]
                        )
        except Exception as e:
            print(f"⚠️  Could not fetch certificates for dynamic tests: {e}")

        # Get list of assignments
        api_url = urljoin(self.base_url, "/api/plugins/ssl/assignments/")
        try:
            resp = self.session.get(api_url, headers=headers, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                results = data.get("results", [])
                if results:
                    assignment_id = results[0].get("id")
                    if assignment_id:
                        self.URLS_TO_TEST.extend(
                            [
                                ("GET", f"/plugins/ssl/assignments/{assignment_id}/"),
                                ("GET", f"/plugins/ssl/assignments/{assignment_id}/edit/"),
                            ]
                        )
        except Exception as e:
            print(f"⚠️  Could not fetch assignments for dynamic tests: {e}")

    def run(self) -> bool:
        """Run all smoke tests."""
        print(f"\n🧪 NetBox SSL Plugin Smoke Test")
        print("=" * 50)

        if not self.login():
            return False

        # Add dynamic URLs based on existing data
        self.test_dynamic_urls()

        print(f"\n📋 Testing {len(self.URLS_TO_TEST)} URLs...\n")

        passed = 0
        failed = 0

        for method, path in self.URLS_TO_TEST:
            result = self.test_url(method, path)
            self.results.append(result)

            if result.success:
                print(f"  ✅ {method:6} {path} [{result.status_code}]")
                passed += 1
            else:
                print(f"  ❌ {method:6} {path} [{result.status_code}]")
                if result.error:
                    print(f"           └─ {result.error}")
                failed += 1

        # Summary
        print("\n" + "=" * 50)
        print(f"📊 Results: {passed} passed, {failed} failed")

        if failed > 0:
            print("\n❌ Failed tests:")
            for result in self.results:
                if not result.success:
                    print(f"   • {result.method} {result.url}: {result.error or f'HTTP {result.status_code}'}")

        return failed == 0


def main():
    parser = argparse.ArgumentParser(description="Smoke test for NetBox SSL plugin")
    parser.add_argument("--base-url", default="http://localhost:8000", help="NetBox base URL")
    parser.add_argument("--username", default="admin", help="NetBox username")
    parser.add_argument("--password", default="admin", help="NetBox password")
    args = parser.parse_args()

    tester = NetBoxSmokeTest(args.base_url, args.username, args.password)
    success = tester.run()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
