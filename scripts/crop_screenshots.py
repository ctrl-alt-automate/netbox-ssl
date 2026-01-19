#!/usr/bin/env python3
"""
Crop screenshots to remove Chrome UI elements.

Usage:
    1. Place your raw screenshots in a folder
    2. Run: python crop_screenshots.py /path/to/screenshots

The script will:
- Remove Chrome tabs, address bar, and toolbar (~110px from top)
- Remove the "foutopsporing" banner if present (~35px extra)
- Crop to just the NetBox content
- Save cropped images to docs/images/ and wiki images/
"""

import sys
import os
from pathlib import Path

try:
    from PIL import Image
except ImportError:
    print("Please install Pillow: pip install Pillow")
    sys.exit(1)

# Crop settings based on typical Chrome on macOS
CHROME_TOP_CROP = 110  # Tabs + address bar + toolbar
BANNER_HEIGHT = 35     # "Foutopsporing" banner height
BOTTOM_CROP = 0        # Usually no bottom crop needed

# Screenshot mapping (in order they were taken)
SCREENSHOT_NAMES = [
    "certificate-list.png",
    "certificate-detail.png",
    "certificate-import.png",
    "assignments-list.png",
    "dashboard-widget.png",
]

# Screenshots that have the debug banner
HAS_BANNER = [2, 3, 4]  # 0-indexed: import, assignments, dashboard


def crop_image(input_path, output_path, has_banner=False):
    """Crop Chrome UI from screenshot."""
    img = Image.open(input_path)
    width, height = img.size

    top_crop = CHROME_TOP_CROP
    if has_banner:
        top_crop += BANNER_HEIGHT

    # Crop: left, top, right, bottom
    cropped = img.crop((0, top_crop, width, height - BOTTOM_CROP))

    # Ensure output directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)

    cropped.save(output_path, "PNG", optimize=True)
    print(f"  ✓ Saved: {output_path}")
    return cropped.size


def main():
    if len(sys.argv) < 2:
        print("Usage: python crop_screenshots.py /path/to/screenshots")
        print("\nExpected files (in order):")
        for i, name in enumerate(SCREENSHOT_NAMES, 1):
            print(f"  {i}. Screenshot for {name}")
        sys.exit(1)

    input_dir = Path(sys.argv[1])
    if not input_dir.exists():
        print(f"Error: Directory not found: {input_dir}")
        sys.exit(1)

    # Find screenshot files (sorted by name/date)
    screenshots = sorted(input_dir.glob("Screenshot*.png"))
    if not screenshots:
        screenshots = sorted(input_dir.glob("*.png"))

    if len(screenshots) < len(SCREENSHOT_NAMES):
        print(f"Warning: Found {len(screenshots)} screenshots, expected {len(SCREENSHOT_NAMES)}")

    # Output directories
    script_dir = Path(__file__).parent.parent
    docs_images = script_dir / "docs" / "images"
    wiki_images = script_dir.parent / "netbox-ssl.wiki" / "images"

    print(f"Processing {len(screenshots)} screenshots...")
    print(f"Output: {docs_images}")
    print(f"Output: {wiki_images}")
    print()

    for i, (screenshot, name) in enumerate(zip(screenshots, SCREENSHOT_NAMES)):
        print(f"Processing: {screenshot.name} -> {name}")
        has_banner = i in HAS_BANNER

        if has_banner:
            print(f"  (removing debug banner)")

        for output_dir in [docs_images, wiki_images]:
            output_path = output_dir / name
            size = crop_image(screenshot, output_path, has_banner)

        print(f"  Final size: {size[0]}x{size[1]}")
        print()

    print("✅ Done! Screenshots cropped and saved.")


if __name__ == "__main__":
    main()
