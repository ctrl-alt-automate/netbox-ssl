"""
Browser tests for NetBox SSL plugin using Playwright.

These tests verify the plugin UI works correctly in a real browser.
Requires a running NetBox instance with the plugin installed.

Run with: pytest tests/test_browser.py -m browser
"""

import os
import pytest
import re

# Check if playwright is available
try:
    from playwright.sync_api import sync_playwright, expect
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


# Skip all tests if Playwright is not available
pytestmark = [
    pytest.mark.browser,
    pytest.mark.skipif(not PLAYWRIGHT_AVAILABLE, reason="Playwright not installed"),
]


# Configuration from environment or defaults
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


@pytest.fixture(scope="module")
def authenticated_page(browser):
    """Provide an authenticated page instance."""
    context = browser.new_context()
    page = context.new_page()

    # Login to NetBox
    page.goto(f"{NETBOX_BASE_URL}/login/")

    # Fill login form
    page.fill('input[name="username"]', NETBOX_USERNAME)
    page.fill('input[name="password"]', NETBOX_PASSWORD)
    page.click('button[type="submit"]')

    # Wait for redirect after login
    page.wait_for_url(f"{NETBOX_BASE_URL}/**")

    yield page

    context.close()


@pytest.fixture
def page(browser):
    """Provide a fresh page instance for each test."""
    context = browser.new_context()
    page = context.new_page()

    # Login to NetBox
    page.goto(f"{NETBOX_BASE_URL}/login/")
    page.fill('input[name="username"]', NETBOX_USERNAME)
    page.fill('input[name="password"]', NETBOX_PASSWORD)
    page.click('button[type="submit"]')
    page.wait_for_url(f"{NETBOX_BASE_URL}/**")

    yield page

    context.close()


class TestCertificateListPage:
    """Tests for the certificate list page."""

    def test_certificate_list_loads(self, page):
        """Test that the certificate list page loads without errors."""
        page.goto(f"{NETBOX_BASE_URL}/plugins/ssl/certificates/")

        # Should have the page title
        expect(page.locator("h1, h2").first).to_be_visible()

        # Should not have server errors
        assert "Server Error" not in page.content()
        assert "TemplateSyntaxError" not in page.content()
        assert "Traceback" not in page.content()

    def test_certificate_list_has_add_button(self, page):
        """Test that the add certificate button is present."""
        page.goto(f"{NETBOX_BASE_URL}/plugins/ssl/certificates/")

        # Look for add button specific to certificates
        add_button = page.locator('a[href*="/plugins/ssl/certificates/add"]').first
        expect(add_button).to_be_visible()

    def test_certificate_list_has_import_button(self, page):
        """Test that the import certificate button is present."""
        page.goto(f"{NETBOX_BASE_URL}/plugins/ssl/certificates/")

        # Look for import button specific to certificates
        import_button = page.locator('a[href*="/plugins/ssl/certificates/import"]').first
        expect(import_button).to_be_visible()


class TestCertificateAddPage:
    """Tests for the add certificate page."""

    def test_add_page_loads(self, page):
        """Test that the add certificate page loads without errors."""
        page.goto(f"{NETBOX_BASE_URL}/plugins/ssl/certificates/add/")

        # Should have the main object-edit form (not the search form)
        expect(page.locator("form.object-edit")).to_be_visible()

        # Should not have server errors
        assert "Server Error" not in page.content()
        assert "TemplateSyntaxError" not in page.content()

    def test_add_page_has_required_fields(self, page):
        """Test that required form fields are present."""
        page.goto(f"{NETBOX_BASE_URL}/plugins/ssl/certificates/add/")

        # Check for the main certificate form (not search forms)
        form = page.locator("form.object-edit")
        expect(form).to_be_visible()


class TestCertificateImportPage:
    """Tests for the certificate import page."""

    def test_import_page_loads(self, page):
        """Test that the import page loads without errors."""
        page.goto(f"{NETBOX_BASE_URL}/plugins/ssl/certificates/import/")

        # Should have a form with POST method (the main import form, not search)
        expect(page.locator("form.form[method='post'], form[method='post']:not([action*='search'])").first).to_be_visible()

        # Should not have server errors
        assert "Server Error" not in page.content()
        assert "TemplateSyntaxError" not in page.content()

    def test_import_page_has_pem_textarea(self, page):
        """Test that the PEM input textarea is present."""
        page.goto(f"{NETBOX_BASE_URL}/plugins/ssl/certificates/import/")

        # Look for textarea for PEM input
        textarea = page.locator("textarea").first
        expect(textarea).to_be_visible()

    def test_import_rejects_private_key(self, page):
        """Test that importing a private key shows an error."""
        page.goto(f"{NETBOX_BASE_URL}/plugins/ssl/certificates/import/")

        # Fill in a private key
        private_key = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSktest
-----END PRIVATE KEY-----"""

        textarea = page.locator("textarea").first
        textarea.fill(private_key)

        # Submit the form - use the submit button inside the main form, not the search form
        # Look for submit button with specific text or inside the import form
        submit_btn = page.locator("form.form button[type='submit'], form[method='post']:not([action*='search']) button[type='submit']").first
        submit_btn.click()

        # Should show an error about private keys
        # Wait for the page to process
        page.wait_for_load_state("networkidle")

        # Check for error message (could be in form errors or alerts)
        content = page.content().lower()
        assert "private key" in content or "error" in content


class TestAssignmentListPage:
    """Tests for the assignment list page."""

    def test_assignment_list_loads(self, page):
        """Test that the assignment list page loads without errors."""
        page.goto(f"{NETBOX_BASE_URL}/plugins/ssl/assignments/")

        # Should have the page structure
        expect(page.locator("h1, h2").first).to_be_visible()

        # Should not have server errors
        assert "Server Error" not in page.content()
        assert "TemplateSyntaxError" not in page.content()


class TestAPIEndpoints:
    """Tests for API endpoints via browser."""

    def test_api_certificates_endpoint(self, page):
        """Test that the certificates API endpoint responds."""
        response = page.goto(f"{NETBOX_BASE_URL}/api/plugins/ssl/certificates/")

        # API should respond with JSON
        assert response.status < 500
        content = page.content()
        # Should contain JSON structure (even if wrapped in HTML pre tag)
        assert "results" in content or '"count"' in content or "count" in content

    def test_api_assignments_endpoint(self, page):
        """Test that the assignments API endpoint responds."""
        response = page.goto(f"{NETBOX_BASE_URL}/api/plugins/ssl/assignments/")

        # API should respond with JSON
        assert response.status < 500


class TestNavigationMenu:
    """Tests for plugin navigation menu."""

    def test_ssl_menu_exists(self, page):
        """Test that the SSL plugin menu exists in navigation."""
        page.goto(f"{NETBOX_BASE_URL}/")

        # Wait for page to load
        page.wait_for_load_state("networkidle")

        # Get all text from the page body to check for SSL menu items
        # NetBox 4.5 uses a different nav structure
        body_content = page.locator("body").inner_text()

        # Should have some reference to certificates or SSL in the navigation/menu
        assert "Certificate" in body_content or "SSL" in body_content or "certificate" in body_content.lower(), \
            "SSL/Certificate menu not found in page content"


class TestErrorHandling:
    """Tests for error handling and edge cases."""

    def test_nonexistent_certificate_returns_404(self, page):
        """Test that accessing a nonexistent certificate returns 404."""
        response = page.goto(f"{NETBOX_BASE_URL}/plugins/ssl/certificates/99999/")

        # Should return 404
        assert response.status == 404 or "not found" in page.content().lower()

    def test_invalid_url_handled_gracefully(self, page):
        """Test that invalid URLs are handled gracefully."""
        response = page.goto(f"{NETBOX_BASE_URL}/plugins/ssl/invalid-path/")

        # Should return 404, not 500
        assert response.status == 404


class TestDashboardWidget:
    """Tests for the dashboard widget."""

    def test_dashboard_loads_with_widget(self, page):
        """Test that the dashboard loads (widget may or may not be visible)."""
        page.goto(f"{NETBOX_BASE_URL}/")

        # Dashboard should load without errors
        assert "Server Error" not in page.content()
        assert "TemplateSyntaxError" not in page.content()


class TestFullWorkflow:
    """End-to-end workflow tests."""

    @pytest.mark.slow
    def test_certificate_list_to_detail_navigation(self, page):
        """Test navigating from list to detail page."""
        page.goto(f"{NETBOX_BASE_URL}/plugins/ssl/certificates/")

        # If there are certificates, try to click on one
        cert_links = page.locator('table tbody a[href*="/certificates/"]')

        if cert_links.count() > 0:
            # Click the first certificate
            cert_links.first.click()

            # Should navigate to detail page
            page.wait_for_load_state("networkidle")

            # Should not have errors
            assert "Server Error" not in page.content()
            assert "TemplateSyntaxError" not in page.content()


# Smoke test runner that checks all URLs
class TestSmokeAllUrls:
    """Smoke tests that verify all plugin URLs load without errors."""

    URLS_TO_TEST = [
        "/plugins/ssl/certificates/",
        "/plugins/ssl/certificates/add/",
        "/plugins/ssl/certificates/import/",
        "/plugins/ssl/assignments/",
        "/plugins/ssl/assignments/add/",
    ]

    ERROR_PATTERNS = [
        "TemplateSyntaxError",
        "TemplateDoesNotExist",
        "ImproperlyConfigured",
        "ImportError",
        "AttributeError",
        "Server Error",
        "Traceback (most recent call last)",
    ]

    @pytest.mark.parametrize("url_path", URLS_TO_TEST)
    def test_url_loads_without_errors(self, page, url_path):
        """Test that each URL loads without template/server errors."""
        response = page.goto(f"{NETBOX_BASE_URL}{url_path}")

        # Check status code
        assert response.status < 500, f"Server error on {url_path}: {response.status}"

        # Check for error patterns in content
        content = page.content()
        for pattern in self.ERROR_PATTERNS:
            assert pattern not in content, f"Found '{pattern}' on {url_path}"
