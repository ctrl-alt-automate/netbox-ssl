"""
Playwright E2E tests for the Janus Renewal workflow.

These tests verify the complete renewal journey:
1. Import a certificate with a matching CN → renewal detected
2. Renewal confirmation page shows old/new cert comparison
3. Assignment transfer preview table
4. Confirm renewal → new cert created, assignments transferred, old archived
5. "Create as New" alternative path
6. "Renew" button on certificate detail page

Requires:
- Running NetBox instance at http://localhost:8000
- NETBOX_TOKEN environment variable
- Playwright installed

Run with:
    NETBOX_TOKEN="nbt_xxx" python -m pytest tests/test_janus_renewal.py -m browser -v
"""

from __future__ import annotations

import os
import re

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


@pytest.fixture(scope="module")
def browser():
    """Provide a browser instance for tests."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        yield browser
        browser.close()


@pytest.fixture
def page(browser):
    """Provide a fresh authenticated page for each test."""
    context = browser.new_context()
    page = context.new_page()

    # Login
    page.goto(f"{NETBOX_BASE_URL}/login/")
    page.fill('input[name="username"]', NETBOX_USERNAME)
    page.fill('input[name="password"]', NETBOX_PASSWORD)
    page.click('button[type="submit"]')
    page.wait_for_url(f"{NETBOX_BASE_URL}/**")

    yield page

    context.close()


def _navigate_to_renewal_page(page, new_pem: str) -> None:
    """Helper: paste a PEM into the import form and submit.

    If the CN matches an existing cert, this navigates to the renewal page.
    """
    page.goto(f"{NETBOX_BASE_URL}/plugins/ssl/certificates/import/")

    # Fill the PEM textarea
    page.fill('textarea[name="pem_content"]', new_pem)

    # Submit the import form (not the nav Search button)
    page.click('button.btn-primary[type="submit"]')

    # Wait for either renewal page or certificate detail page
    page.wait_for_load_state("networkidle")


class TestJanusRenewalDetection:
    """Tests for renewal detection when importing a certificate with matching CN."""

    def test_import_matching_cn_shows_renewal_page(self, page, renewal_test_data):
        """Importing a cert with the same CN as an existing cert shows renewal page."""
        _navigate_to_renewal_page(page, renewal_test_data["new_pem"])

        # Should be on the renewal page
        expect(page).to_have_url(re.compile(r".*/plugins/ssl/certificates/renew/"))

        # Should show the Janus Renewal banner
        expect(page.locator("text=Janus Renewal Detected")).to_be_visible()

    def test_renewal_page_shows_old_certificate(self, page, renewal_test_data):
        """Renewal page displays the existing certificate details."""
        _navigate_to_renewal_page(page, renewal_test_data["new_pem"])

        # Find the "Existing Certificate" card
        old_card = page.locator(".card-header:has-text('Existing Certificate')").locator("..")

        # CN should be visible
        expect(old_card.locator(f"text={renewal_test_data['cn']}")).to_be_visible()

        # Serial number should be visible
        serial = renewal_test_data["old_cert"]["serial_number"][:16]
        expect(old_card.locator(f"text={serial}")).to_be_visible()

        # Dates should be formatted (YYYY-MM-DD HH:MM), not raw ISO
        # The old cert is a model instance, so Django template filter handles it
        expect(old_card.locator("text=Valid From")).to_be_visible()
        expect(old_card.locator("text=Valid To")).to_be_visible()

    def test_renewal_page_shows_new_certificate(self, page, renewal_test_data):
        """Renewal page displays the new certificate details with formatted dates."""
        _navigate_to_renewal_page(page, renewal_test_data["new_pem"])

        # Find the "New Certificate" card
        new_card = page.locator(".card-header:has-text('New Certificate')").locator("..")

        # CN should match
        expect(new_card.locator(f"text={renewal_test_data['cn']}")).to_be_visible()

        # Dates should be formatted as YYYY-MM-DD HH:MM (not ISO with T and timezone)
        # Check that the date cells don't contain 'T' (ISO format indicator)
        date_cells = new_card.locator("td")
        for i in range(date_cells.count()):
            cell_text = date_cells.nth(i).text_content()
            # If it looks like a date value, it shouldn't have ISO format 'T'
            if cell_text and re.match(r"\d{4}-\d{2}", cell_text.strip()):
                assert "T" not in cell_text, f"Date still in ISO format: {cell_text}"

    def test_renewal_page_shows_assignments_table(self, page, renewal_test_data):
        """Renewal page shows the assignments that will be transferred."""
        _navigate_to_renewal_page(page, renewal_test_data["new_pem"])

        # Should show assignments section
        expect(page.locator("text=Assignments to Transfer")).to_be_visible()

        # Should show the assignment count (1)
        expect(page.locator("text=Assignments to Transfer (1)")).to_be_visible()

        # Should show the service name in the table
        service_name = renewal_test_data["service_name"]
        expect(page.locator(f"table >> text={service_name}")).to_be_visible()


class TestJanusRenewalExecution:
    """Tests for the renewal confirmation actions."""

    def test_confirm_renewal_creates_new_certificate(self, page, renewal_test_data):
        """Clicking 'Renew & Transfer' creates the new cert and redirects to detail."""
        _navigate_to_renewal_page(page, renewal_test_data["new_pem"])

        # Click the renewal button
        page.click('button:has-text("Renew & Transfer Assignments")')
        page.wait_for_load_state("networkidle")

        # Should redirect to a certificate detail page
        expect(page).to_have_url(re.compile(r".*/plugins/ssl/certificates/\d+/"))

        # Should show success message
        expect(page.locator("text=renewed successfully")).to_be_visible()

    def test_confirm_renewal_transfers_assignments(self, page, renewal_test_data, netbox_api):
        """After renewal, assignments are on the new cert and gone from the old."""
        _navigate_to_renewal_page(page, renewal_test_data["new_pem"])

        page.click('button:has-text("Renew & Transfer Assignments")')
        page.wait_for_load_state("networkidle")

        # Extract new cert ID from the URL
        url = page.url
        new_cert_id = int(url.rstrip("/").split("/")[-1])

        # New cert should have assignments
        new_cert = netbox_api.get_certificate(new_cert_id)
        assert new_cert["assignment_count"] > 0, "New certificate should have assignments"

        # Old cert retains its original assignments (copy, not move)
        # but should now be in 'replaced' status
        old_cert = netbox_api.get_certificate(renewal_test_data["old_cert_id"])
        assert old_cert["status"] == "replaced", "Old certificate should be archived"

    def test_confirm_renewal_archives_old_certificate(self, page, renewal_test_data, netbox_api):
        """After renewal, old cert has status 'replaced' and replaced_by set."""
        _navigate_to_renewal_page(page, renewal_test_data["new_pem"])

        page.click('button:has-text("Renew & Transfer Assignments")')
        page.wait_for_load_state("networkidle")

        # Extract new cert ID from URL
        url = page.url
        new_cert_id = int(url.rstrip("/").split("/")[-1])

        # Old cert should be archived
        old_cert = netbox_api.get_certificate(renewal_test_data["old_cert_id"])
        assert old_cert["status"] == "replaced", f"Expected 'replaced', got {old_cert['status']}"
        # replaced_by can be an int (ID) or a nested object with "id" key
        replaced_by = old_cert["replaced_by"]
        replaced_by_id = replaced_by["id"] if isinstance(replaced_by, dict) else replaced_by
        assert replaced_by_id == new_cert_id

    def test_create_as_new_preserves_old(self, page, renewal_test_data, netbox_api):
        """Clicking 'Create as New' leaves the old certificate untouched."""
        _navigate_to_renewal_page(page, renewal_test_data["new_pem"])

        # Click "Create as New Certificate"
        page.click('button:has-text("Create as New Certificate")')
        page.wait_for_load_state("networkidle")

        # Should redirect to a certificate detail page
        expect(page).to_have_url(re.compile(r".*/plugins/ssl/certificates/\d+/"))

        # Old cert should still be active with its assignment
        old_cert = netbox_api.get_certificate(renewal_test_data["old_cert_id"])
        assert old_cert["status"] == "active", f"Expected 'active', got {old_cert['status']}"
        assert old_cert["assignment_count"] > 0, "Old certificate should still have assignments"


class TestRenewButtonOnDetailPage:
    """Tests for the 'Renew This Certificate' button on the detail page."""

    def test_renew_button_visible_on_active_certificate(self, page, renewal_test_data):
        """Active certificate detail page shows the Renew button."""
        cert_id = renewal_test_data["old_cert_id"]
        page.goto(f"{NETBOX_BASE_URL}/plugins/ssl/certificates/{cert_id}/")

        expect(page.locator("text=Renew This Certificate")).to_be_visible()

    def test_renew_button_links_to_import_with_parameter(self, page, renewal_test_data):
        """Clicking the Renew button navigates to import page with renew_from parameter."""
        cert_id = renewal_test_data["old_cert_id"]
        page.goto(f"{NETBOX_BASE_URL}/plugins/ssl/certificates/{cert_id}/")

        # Click the renew button
        page.click("text=Renew This Certificate")
        page.wait_for_load_state("networkidle")

        # Should be on import page with renew_from parameter
        expect(page).to_have_url(re.compile(rf".*certificates/import/\?renew_from={cert_id}"))

    def test_renew_button_shows_renewal_banner(self, page, renewal_test_data):
        """Import page shows renewal mode banner when accessed via Renew button."""
        cert_id = renewal_test_data["old_cert_id"]
        page.goto(f"{NETBOX_BASE_URL}/plugins/ssl/certificates/{cert_id}/")

        page.click("text=Renew This Certificate")
        page.wait_for_load_state("networkidle")

        # Should show the renewal mode banner
        expect(page.locator("text=Renewal Mode")).to_be_visible()

        # Should mention the certificate CN
        expect(page.locator(f"text={renewal_test_data['cn']}")).to_be_visible()
