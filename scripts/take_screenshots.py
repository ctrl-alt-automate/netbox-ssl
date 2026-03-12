#!/usr/bin/env python3
"""
Capture screenshots of all NetBox SSL plugin pages using Playwright.

Usage:
    python scripts/take_screenshots.py
    python scripts/take_screenshots.py --dark      # dark mode only
    python scripts/take_screenshots.py --light     # light mode only
    python scripts/take_screenshots.py --output /tmp/screenshots

Requires:
    pip install playwright
    playwright install chromium
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    print("ERROR: playwright not installed. Run: pip install playwright && playwright install chromium")
    sys.exit(1)

# Configuration
NETBOX_URL = os.environ.get("NETBOX_URL", "http://localhost:8000")
NETBOX_USERNAME = os.environ.get("NETBOX_USERNAME", "admin")
NETBOX_PASSWORD = os.environ.get("NETBOX_PASSWORD", "admin")

# Pages to capture: (filename, url_path, description)
PAGES: list[tuple[str, str, str]] = [
    ("certificate-list", "/plugins/ssl/certificates/", "Certificate list view"),
    ("certificate-detail", "/plugins/ssl/certificates/1/", "Certificate detail (tabbed)"),
    ("certificate-import", "/plugins/ssl/certificates/import/", "Smart Paste import"),
    ("assignments-list", "/plugins/ssl/assignments/", "Certificate assignments"),
    ("analytics-dashboard", "/plugins/ssl/analytics/", "Analytics dashboard"),
    ("compliance-report", "/plugins/ssl/compliance-report/", "Compliance report"),
    ("certificate-map", "/plugins/ssl/certificate-map/", "Certificate map topology"),
    ("ca-list", "/plugins/ssl/certificate-authorities/", "Certificate authorities"),
    ("csr-list", "/plugins/ssl/csrs/", "Certificate signing requests"),
]


def login(page, base_url: str, username: str, password: str) -> None:
    """Log in to NetBox."""
    page.goto(f"{base_url}/login/")
    page.fill("input[name='username']", username)
    page.fill("input[name='password']", password)
    page.click("button[type='submit']")
    page.wait_for_url(f"{base_url}/**")
    print(f"  Logged in as {username}")


def set_color_mode(page, base_url: str, mode: str) -> None:
    """Set NetBox color mode (light/dark) via JavaScript."""
    page.goto(f"{base_url}/")
    page.evaluate(f"""() => {{
        document.documentElement.setAttribute('data-bs-theme', '{mode}');
        localStorage.setItem('netbox-color-mode', '{mode}');
    }}""")
    # Reload to apply
    page.reload()
    page.wait_for_load_state("networkidle")


def capture_page(
    page,
    base_url: str,
    url_path: str,
    output_path: Path,
    wait_ms: int = 1000,
) -> bool:
    """Navigate to a page and capture a screenshot. Returns True on success."""
    try:
        page.goto(f"{base_url}{url_path}", wait_until="networkidle")
        page.wait_for_timeout(wait_ms)

        # For certificate map, expand first accordion and wait for HTMX
        if "certificate-map" in url_path:
            page.wait_for_timeout(2000)

        page.screenshot(path=str(output_path), full_page=False)
        return True
    except Exception as e:
        print(f"    SKIP: {e}")
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Capture NetBox SSL plugin screenshots")
    parser.add_argument("--output", "-o", default="docs/images", help="Output directory (default: docs/images)")
    parser.add_argument("--dark", action="store_true", help="Only capture dark mode")
    parser.add_argument("--light", action="store_true", help="Only capture light mode")
    parser.add_argument("--width", type=int, default=1440, help="Viewport width (default: 1440)")
    parser.add_argument("--height", type=int, default=900, help="Viewport height (default: 900)")
    parser.add_argument("--url", default=NETBOX_URL, help=f"NetBox URL (default: {NETBOX_URL})")
    args = parser.parse_args()

    modes: list[str] = []
    if args.dark and not args.light:
        modes = ["dark"]
    elif args.light and not args.dark:
        modes = ["light"]
    else:
        modes = ["light", "dark"]

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"NetBox URL: {args.url}")
    print(f"Output: {output_dir}")
    print(f"Viewport: {args.width}x{args.height}")
    print(f"Modes: {', '.join(modes)}")
    print()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": args.width, "height": args.height})
        page = context.new_page()

        login(page, args.url, NETBOX_USERNAME, NETBOX_PASSWORD)

        for mode in modes:
            print(f"\n[{mode.upper()} MODE]")
            set_color_mode(page, args.url, mode)

            suffix = f"-{mode}" if len(modes) > 1 else ""

            for filename, url_path, description in PAGES:
                output_path = output_dir / f"{filename}{suffix}.png"
                print(f"  {description}...", end=" ", flush=True)
                if capture_page(page, args.url, url_path, output_path):
                    print(f"OK → {output_path}")

        browser.close()

    total = len(PAGES) * len(modes)
    print(f"\nDone! {total} screenshots in {output_dir}/")


if __name__ == "__main__":
    main()
