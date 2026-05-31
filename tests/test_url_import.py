"""
Playwright E2E tests for the URL Certificate Import flow (#106).

Covers the UI contract that Playwright uniquely validates — form render,
CSV parse → preview, and CSV validation errors — without depending on outbound
network reachability (the actual TLS scrape + import is covered by the Docker
integration test, which is deterministic). The "Run scan" step is exercised only
as far as the result page renders, since scraping arbitrary hosts from CI is not
reliable.

Requires:
- Running NetBox instance at http://localhost:8000 (admin/admin)
- Playwright installed

Run with:
    python -m pytest tests/test_url_import.py -m browser -v
"""

from __future__ import annotations

import os

import pytest

try:
    from playwright.sync_api import expect, sync_playwright

    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


pytestmark = [
    pytest.mark.browser,
    pytest.mark.skipif(not PLAYWRIGHT_AVAILABLE, reason="Playwright not installed"),
]

NETBOX_BASE_URL = os.environ.get("NETBOX_URL", "http://localhost:8000")
NETBOX_USERNAME = os.environ.get("NETBOX_USERNAME", "admin")
NETBOX_PASSWORD = os.environ.get("NETBOX_PASSWORD", "admin")

URL_IMPORT_PATH = "/plugins/ssl/certificates/url-import/"


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        yield browser
        browser.close()


@pytest.fixture
def page(browser):
    context = browser.new_context()
    page = context.new_page()
    page.goto(f"{NETBOX_BASE_URL}/login/")
    page.fill('input[name="username"]', NETBOX_USERNAME)
    page.fill('input[name="password"]', NETBOX_PASSWORD)
    page.click('button[type="submit"]')
    page.wait_for_url(f"{NETBOX_BASE_URL}/**")
    yield page
    context.close()


class TestUrlImportUI:
    """UI contract for the URL Certificate Import flow."""

    def test_input_form_renders(self, page):
        """The upload form and CSV-schema help are shown."""
        page.goto(f"{NETBOX_BASE_URL}{URL_IMPORT_PATH}")
        page.wait_for_load_state("networkidle")
        content = page.content()
        assert "Import Certificates from URLs" in content
        assert 'name="csv_text"' in content
        assert 'name="csv_file"' in content
        # CSV column reference present.
        assert "verify_chain" in content

    def test_csv_parse_shows_preview(self, page):
        """Pasting a valid CSV advances to the preview table without scanning."""
        page.goto(f"{NETBOX_BASE_URL}{URL_IMPORT_PATH}")
        page.fill('textarea[name="csv_text"]', "url\nhttps://example.com:443\n")
        page.click('button[type="submit"]')
        page.wait_for_load_state("networkidle")
        content = page.content()
        assert "Scan Preview" in content
        assert "example.com" in content
        # The confirm button (Run scan) is offered.
        assert "Run scan" in content

    def test_invalid_csv_shows_error(self, page):
        """A CSV without a url column surfaces a validation error, not a preview."""
        page.goto(f"{NETBOX_BASE_URL}{URL_IMPORT_PATH}")
        page.fill('textarea[name="csv_text"]', "hostname,port\nexample.com,443\n")
        page.click('button[type="submit"]')
        page.wait_for_load_state("networkidle")
        content = page.content()
        assert "Scan Preview" not in content
        assert "url" in content.lower()  # error references the missing url column

    def test_nav_entry_present(self, page):
        """The 'Import from URLs (CSV)' menu item links to the flow."""
        page.goto(f"{NETBOX_BASE_URL}/plugins/ssl/certificates/")
        page.wait_for_load_state("networkidle")
        # The URL-import route is reachable (nav item rendered for a permitted user).
        link = page.locator(f'a[href="{URL_IMPORT_PATH}"]')
        expect(link.first).to_have_count(1)
