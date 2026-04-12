#!/usr/bin/env python3
"""
Generate built-in wallpapers for sotOS compositor.

Produces 24-bit uncompressed BMP files (bottom-up scanline order).

Wallpapers:
  tokyo-night.bmp  -- 1024x768 vertical gradient #1A1B26 -> #10101C
  sotos-logo.bmp   -- same gradient + centered "sotOS" text in #C0CAF5

Usage:
    python scripts/gen_wallpapers.py [--output-dir assets/wallpapers]
"""

import argparse
import os
import sys

from PIL import Image, ImageDraw, ImageFont


# Tokyo Night palette
BG_TOP = (0x1A, 0x1B, 0x26)     # top of gradient
BG_BOT = (0x10, 0x10, 0x1C)     # bottom of gradient
TEXT_COLOR = (0xC0, 0xCA, 0xF5)  # foreground text

WIDTH = 1024
HEIGHT = 768


def lerp(a, b, t):
    """Linear interpolation between tuples a and b, t in [0,1]."""
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(len(a)))


def make_gradient(w, h):
    """Create a vertical gradient image from BG_TOP to BG_BOT."""
    img = Image.new("RGB", (w, h))
    for y in range(h):
        t = y / max(h - 1, 1)
        color = lerp(BG_TOP, BG_BOT, t)
        for x in range(w):
            img.putpixel((x, y), color)
    return img


def make_tokyo_night(w, h):
    """Pure vertical gradient wallpaper."""
    return make_gradient(w, h)


def make_sotos_logo(w, h):
    """Gradient wallpaper with centered 'sotOS' text."""
    img = make_gradient(w, h)
    draw = ImageDraw.Draw(img)

    # Try to get a large font; fall back to default if unavailable
    font = None
    font_size = 72
    for name in ["DejaVuSans-Bold.ttf", "arial.ttf", "Arial Bold.ttf",
                 "LiberationSans-Bold.ttf", "FreeSansBold.ttf"]:
        try:
            font = ImageFont.truetype(name, font_size)
            break
        except (OSError, IOError):
            continue

    if font is None:
        # PIL default bitmap font -- smaller but works everywhere
        font = ImageFont.load_default()

    text = "sotOS"
    bbox = draw.textbbox((0, 0), text, font=font)
    tw = bbox[2] - bbox[0]
    th = bbox[3] - bbox[1]
    x = (w - tw) // 2
    y = (h - th) // 2
    draw.text((x, y), text, fill=TEXT_COLOR, font=font)
    return img


def main():
    p = argparse.ArgumentParser(description="Generate sotOS wallpapers")
    p.add_argument("--output-dir", default="assets/wallpapers",
                   help="Directory to write BMP files")
    args = p.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    print(f"Generating wallpapers ({WIDTH}x{HEIGHT})...")

    tokyo = make_tokyo_night(WIDTH, HEIGHT)
    tokyo_path = os.path.join(args.output_dir, "tokyo-night.bmp")
    tokyo.save(tokyo_path, "BMP")
    print(f"  {tokyo_path}: {os.path.getsize(tokyo_path):,} bytes")

    logo = make_sotos_logo(WIDTH, HEIGHT)
    logo_path = os.path.join(args.output_dir, "sotos-logo.bmp")
    logo.save(logo_path, "BMP")
    print(f"  {logo_path}: {os.path.getsize(logo_path):,} bytes")

    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
