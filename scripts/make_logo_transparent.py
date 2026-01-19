#!/usr/bin/env python3
"""Make logo background transparent using flood fill approach."""

from PIL import Image
import os

def make_transparent(input_path, output_path):
    """Remove white background using flood fill from corners."""
    img = Image.open(input_path).convert('RGBA')
    width, height = img.size
    pixels = img.load()

    # Create a mask for pixels to make transparent
    transparent_mask = set()

    # Flood fill from all four corners (where background definitely is)
    def flood_fill(start_x, start_y, threshold=30):
        """Flood fill to find connected white/light pixels."""
        stack = [(start_x, start_y)]
        visited = set()

        while stack:
            x, y = stack.pop()
            if (x, y) in visited:
                continue
            if x < 0 or x >= width or y < 0 or y >= height:
                continue

            visited.add((x, y))
            r, g, b, a = pixels[x, y]

            # Check if pixel is "white-ish" (high brightness, low saturation)
            brightness = (r + g + b) / 3
            max_diff = max(abs(r - g), abs(g - b), abs(r - b))

            # If bright and grayish (low color variance), it's background
            if brightness > 240 and max_diff < threshold:
                transparent_mask.add((x, y))
                # Add neighbors
                stack.extend([
                    (x+1, y), (x-1, y), (x, y+1), (x, y-1),
                    (x+1, y+1), (x-1, y-1), (x+1, y-1), (x-1, y+1)
                ])

    # Start flood fill from corners
    flood_fill(0, 0)
    flood_fill(width-1, 0)
    flood_fill(0, height-1)
    flood_fill(width-1, height-1)

    # Also start from middle of edges
    flood_fill(width//2, 0)
    flood_fill(width//2, height-1)
    flood_fill(0, height//2)
    flood_fill(width-1, height//2)

    # Apply transparency
    for x, y in transparent_mask:
        r, g, b, a = pixels[x, y]
        pixels[x, y] = (r, g, b, 0)

    # Save
    img.save(output_path, 'PNG')
    print(f"Saved transparent logo to {output_path}")
    print(f"Made {len(transparent_mask)} pixels transparent")
    return img.size


if __name__ == "__main__":
    # Process the logo
    input_file = '../temp/project-logo.png'
    output_files = [
        '../netbox-ssl/docs/images/logo.png',
        '../netbox-ssl.wiki/images/logo.png'
    ]

    # Make directories if needed
    os.makedirs('../netbox-ssl/docs/images', exist_ok=True)
    os.makedirs('../netbox-ssl.wiki/images', exist_ok=True)

    # Process
    for output_file in output_files:
        size = make_transparent(input_file, output_file)
        print(f"  Size: {size[0]}x{size[1]}")

    print("\nDone!")
