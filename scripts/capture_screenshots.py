#!/usr/bin/env python3
"""
Screenshot capture script for NetBox SSL Plugin documentation.

This script captures screenshots of the plugin UI for use in documentation.
Requires: selenium, pillow

Usage:
    pip install selenium pillow
    python capture_screenshots.py

The script will:
1. Start a Chrome browser
2. Navigate to the NetBox SSL plugin pages
3. Capture screenshots
4. Save them to docs/images/ and wiki images folder
"""

import os
import sys
import time
from pathlib import Path

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
except ImportError:
    print("Please install selenium: pip install selenium")
    sys.exit(1)

# Configuration
NETBOX_URL = "http://localhost:8000"
USERNAME = "admin"
PASSWORD = "admin"

# Output directories
SCRIPT_DIR = Path(__file__).parent.parent
DOCS_IMAGES = SCRIPT_DIR / "docs" / "images"
WIKI_IMAGES = SCRIPT_DIR.parent / "netbox-ssl.wiki" / "images"


def setup_driver():
    """Configure and return a Chrome WebDriver."""
    options = Options()
    options.add_argument("--window-size=1400,900")
    options.add_argument("--hide-scrollbars")
    # Uncomment for headless mode:
    # options.add_argument("--headless")

    driver = webdriver.Chrome(options=options)
    driver.implicitly_wait(10)
    return driver


def login(driver):
    """Log into NetBox."""
    driver.get(f"{NETBOX_URL}/login/")

    username_field = driver.find_element(By.NAME, "username")
    password_field = driver.find_element(By.NAME, "password")

    username_field.send_keys(USERNAME)
    password_field.send_keys(PASSWORD)

    submit_button = driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
    submit_button.click()

    # Wait for login to complete
    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.CSS_SELECTOR, ".navbar"))
    )
    print("✓ Logged in successfully")


def capture_screenshot(driver, filename, description):
    """Capture a screenshot and save to both output directories."""
    time.sleep(1)  # Allow page to fully render

    for output_dir in [DOCS_IMAGES, WIKI_IMAGES]:
        output_dir.mkdir(parents=True, exist_ok=True)
        filepath = output_dir / filename
        driver.save_screenshot(str(filepath))
        print(f"✓ Saved: {filepath}")

    print(f"  → {description}")


def main():
    """Main function to capture all screenshots."""
    print("NetBox SSL Plugin Screenshot Capture")
    print("=" * 40)

    driver = setup_driver()

    try:
        # Login
        login(driver)

        # 1. Certificate List
        print("\n📸 Capturing Certificate List...")
        driver.get(f"{NETBOX_URL}/plugins/ssl/certificates/")
        capture_screenshot(driver, "certificate-list.png", "Certificate list with status badges")

        # 2. Certificate Detail
        print("\n📸 Capturing Certificate Detail...")
        # Click on first certificate
        cert_link = driver.find_element(By.CSS_SELECTOR, "table tbody tr td a")
        cert_link.click()
        capture_screenshot(driver, "certificate-detail.png", "Certificate detail view with assignments")

        # 3. Certificate Import
        print("\n📸 Capturing Certificate Import...")
        driver.get(f"{NETBOX_URL}/plugins/ssl/certificates/import/")
        capture_screenshot(driver, "certificate-import.png", "Smart Paste import form")

        # 4. Assignments List
        print("\n📸 Capturing Assignments List...")
        driver.get(f"{NETBOX_URL}/plugins/ssl/assignments/")
        capture_screenshot(driver, "assignments-list.png", "Certificate assignments overview")

        # 5. Dashboard Widget
        print("\n📸 Capturing Dashboard Widget...")
        driver.get(f"{NETBOX_URL}/")
        # Scroll to find the widget
        driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        time.sleep(1)
        capture_screenshot(driver, "dashboard-widget.png", "SSL Certificate Status widget")

        print("\n" + "=" * 40)
        print("✅ All screenshots captured successfully!")
        print(f"\nScreenshots saved to:")
        print(f"  - {DOCS_IMAGES}")
        print(f"  - {WIKI_IMAGES}")

    except Exception as e:
        print(f"\n❌ Error: {e}")
        raise
    finally:
        driver.quit()


if __name__ == "__main__":
    main()
