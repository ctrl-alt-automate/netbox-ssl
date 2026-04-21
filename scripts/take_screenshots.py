#!/usr/bin/env python3
"""
Capture screenshots of every NetBox SSL plugin page using Playwright.

Usage:
    python scripts/take_screenshots.py
    python scripts/take_screenshots.py --dark      # dark mode only
    python scripts/take_screenshots.py --light     # light mode only
    python scripts/take_screenshots.py --output /tmp/screenshots
    python scripts/take_screenshots.py --width 1600 --height 1000

Requires:
    pip install playwright
    playwright install chromium

Dynamic IDs:
    The script resolves certificate/CA/CSR/source PKs at startup by querying
    the NetBox REST API with a known common_name or name. This way it keeps
    working even after seeder re-runs assign new IDs. Override with env vars
    if needed:
        CERT_DETAIL_CN       (default: www.prod.example.com)
        CA_DETAIL_NAME       (default: DigiCert)
        CSR_DETAIL_CN        (default: new-service.prod.example.com)
        EXT_SOURCE_NAME      (default: Lemur (demo))
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

try:
    import requests
    from playwright.sync_api import sync_playwright
except ImportError:
    print("ERROR: missing deps. Run: pip install playwright requests && playwright install chromium")
    sys.exit(1)

NETBOX_URL = os.environ.get("NETBOX_URL", "http://localhost:8000")
NETBOX_USERNAME = os.environ.get("NETBOX_USERNAME", "admin")
NETBOX_PASSWORD = os.environ.get("NETBOX_PASSWORD", "admin")
NETBOX_TOKEN = os.environ.get("NETBOX_TOKEN")  # optional; only needed for API lookup

# Known reference names for ID lookup — overridable via env vars.
CERT_DETAIL_CN = os.environ.get("CERT_DETAIL_CN", "www.prod.example.com")
CA_DETAIL_NAME = os.environ.get("CA_DETAIL_NAME", "DigiCert")
CSR_DETAIL_CN = os.environ.get("CSR_DETAIL_CN", "new-service.prod.example.com")
EXT_SOURCE_NAME = os.environ.get("EXT_SOURCE_NAME", "Lemur (demo)")


def resolve_ids(base_url: str, token: str | None) -> dict[str, int | None]:
    """Resolve PKs for detail-view screenshots.

    Precedence (highest to lowest):
        1. explicit env vars CERT_PK / CA_PK / CSR_PK / SOURCE_PK
        2. NetBox REST API lookup by name (needs NETBOX_TOKEN)
        3. fallback to PK=1
    """
    ids: dict[str, int | None] = {
        "cert": int(os.environ["CERT_PK"]) if os.environ.get("CERT_PK") else None,
        "ca": int(os.environ["CA_PK"]) if os.environ.get("CA_PK") else None,
        "csr": int(os.environ["CSR_PK"]) if os.environ.get("CSR_PK") else None,
        "source": int(os.environ["SOURCE_PK"]) if os.environ.get("SOURCE_PK") else None,
    }

    # Attempt API lookup for any still-unresolved IDs
    if token and any(v is None for v in ids.values()):
        headers = {"Authorization": f"Token {token}", "Accept": "application/json"}

        def _lookup(endpoint: str, query: dict) -> int | None:
            try:
                r = requests.get(
                    f"{base_url}/api/plugins/ssl/{endpoint}/",
                    params=query,
                    headers=headers,
                    timeout=10,
                )
                r.raise_for_status()
                results = r.json().get("results", [])
                return results[0]["id"] if results else None
            except Exception as e:
                print(f"    ! API lookup failed for {endpoint}: {e}")
                return None

        if ids["cert"] is None:
            ids["cert"] = _lookup("certificates", {"common_name": CERT_DETAIL_CN})
        if ids["ca"] is None:
            ids["ca"] = _lookup("certificate-authorities", {"name": CA_DETAIL_NAME})
        if ids["csr"] is None:
            ids["csr"] = _lookup("csrs", {"common_name": CSR_DETAIL_CN})
        if ids["source"] is None:
            ids["source"] = _lookup("external-sources", {"name": EXT_SOURCE_NAME})

    # Fallback to 1 if still unresolved
    for k, v in ids.items():
        if v is None:
            ids[k] = 1
            print(f"    (defaulting {k} PK to 1)")
    return ids


def build_pages(ids: dict[str, int | None]) -> list[tuple[str, str, str]]:
    """Compose the full page catalog — (filename, url_path, description)."""
    return [
        # ---- v0.4+ core pages ---------------------------------------
        ("certificate-list", "/plugins/ssl/certificates/", "Certificate list"),
        ("certificate-detail", f"/plugins/ssl/certificates/{ids['cert']}/", "Certificate detail (tabbed)"),
        ("certificate-import", "/plugins/ssl/certificates/import/", "Smart Paste import"),
        ("assignments-list", "/plugins/ssl/assignments/", "Assignments"),
        ("ca-list", "/plugins/ssl/certificate-authorities/", "Certificate authorities"),
        ("ca-detail", f"/plugins/ssl/certificate-authorities/{ids['ca']}/", "CA detail with renewal instructions"),
        ("csr-list", "/plugins/ssl/csrs/", "Certificate signing requests"),
        ("csr-detail", f"/plugins/ssl/csrs/{ids['csr']}/", "CSR detail"),
        # ---- v0.5 bulk import ---------------------------------------
        ("bulk-import", "/plugins/ssl/certificates/bulk-import/", "Bulk CSV/JSON import"),
        # ---- v0.7 insights ------------------------------------------
        ("analytics-dashboard", "/plugins/ssl/analytics/", "Analytics dashboard"),
        ("compliance-report", "/plugins/ssl/compliance-report/", "Compliance report"),
        ("certificate-map", "/plugins/ssl/certificate-map/", "Certificate map topology"),
        # ---- v0.8 external sources ---------------------------------
        ("external-sources-list", "/plugins/ssl/external-sources/", "External sources"),
        ("external-source-detail", f"/plugins/ssl/external-sources/{ids['source']}/", "External source detail"),
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
    """Set NetBox color mode (light/dark) via data-bs-theme + localStorage."""
    page.goto(f"{base_url}/")
    page.evaluate(f"""() => {{
        document.documentElement.setAttribute('data-bs-theme', '{mode}');
        localStorage.setItem('netbox-color-mode', '{mode}');
    }}""")
    page.reload()
    page.wait_for_load_state("networkidle")


def capture_page(page, base_url: str, url_path: str, output_path: Path, wait_ms: int = 1200) -> bool:
    """Navigate and screenshot. Returns True on success."""
    try:
        page.goto(f"{base_url}{url_path}", wait_until="networkidle")
        page.wait_for_timeout(wait_ms)

        # HTMX-heavy pages: expand all accordion panels and wait for lazy fragments.
        if "certificate-map" in url_path:
            # The tenant accordion uses data-bs-parent so opening one normally
            # collapses the others. Remove that exclusivity, then click every
            # still-collapsed button so HTMX fires shown.bs.collapse for each.
            page.evaluate(
                """() => {
                    document.querySelectorAll('.accordion-collapse').forEach(el => {
                        el.removeAttribute('data-bs-parent');
                    });
                    document.querySelectorAll(
                        '#topologyAccordion button[data-bs-toggle="collapse"]'
                    ).forEach(btn => {
                        if (btn.getAttribute('aria-expanded') !== 'true') btn.click();
                    });
                }"""
            )
            page.wait_for_timeout(7000)
            try:
                page.wait_for_load_state("networkidle", timeout=5000)
            except Exception:
                pass

        page.screenshot(path=str(output_path), full_page=False)
        return True
    except Exception as e:
        print(f"    SKIP: {e}")
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Capture NetBox SSL plugin screenshots")
    parser.add_argument("--output", "-o", default="docs/images", help="Output directory")
    parser.add_argument("--dark", action="store_true", help="Only capture dark mode")
    parser.add_argument("--light", action="store_true", help="Only capture light mode")
    parser.add_argument("--width", type=int, default=1440, help="Viewport width")
    parser.add_argument("--height", type=int, default=900, help="Viewport height")
    parser.add_argument("--url", default=NETBOX_URL, help=f"NetBox URL (default: {NETBOX_URL})")
    args = parser.parse_args()

    if args.dark and not args.light:
        modes = ["dark"]
    elif args.light and not args.dark:
        modes = ["light"]
    else:
        modes = ["light", "dark"]

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"NetBox URL: {args.url}")
    print(f"Output:     {output_dir}")
    print(f"Viewport:   {args.width}x{args.height}")
    print(f"Modes:      {', '.join(modes)}")
    print()

    print("Resolving detail-view PKs...")
    ids = resolve_ids(args.url, NETBOX_TOKEN)
    print(f"  cert PK={ids['cert']}  ca PK={ids['ca']}  csr PK={ids['csr']}  source PK={ids['source']}")
    pages = build_pages(ids)
    print(f"  {len(pages)} pages queued")
    print()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": args.width, "height": args.height})
        page = context.new_page()

        login(page, args.url, NETBOX_USERNAME, NETBOX_PASSWORD)

        for mode in modes:
            print(f"\n[{mode.upper()} MODE]")
            set_color_mode(page, args.url, mode)

            # Always append the mode suffix so parallel runs don't overwrite
            # each other and the README references stay stable.
            suffix = f"-{mode}"

            for filename, url_path, description in pages:
                output_path = output_dir / f"{filename}{suffix}.png"
                print(f"  {description}...", end=" ", flush=True)
                if capture_page(page, args.url, url_path, output_path):
                    print(f"OK -> {output_path}")

        browser.close()

    total = len(pages) * len(modes)
    print(f"\nDone! {total} screenshots in {output_dir}/")


if __name__ == "__main__":
    main()
