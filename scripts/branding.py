#!/usr/bin/env python3
"""
branding.py — White-label branding for IPDR.

- Loads branding config (colors, names, domain) from the DB
- Generates a full favicon set from one uploaded square source image
- Validates uploaded logos/icons (format, size, dimensions)

Favicon sizes generated (per 2025 best practice):
  favicon-16, -32, -48, apple-touch-icon (180), android-chrome-192, -512, favicon.ico
"""

import os
import io

BRANDING_DIR = os.environ.get("BRANDING_DIR", "/opt/ipdr/branding")

# Upload constraints (documented for the admin UI)
LOGO_MAX_BYTES = 500 * 1024        # 500 KB
LOGO_ALLOWED = {"png", "svg", "jpg", "jpeg", "webp"}
LOGO_MAX_DIM = 1200                 # px, either dimension
ICON_MIN_DIM = 128                  # square source should be >= 128 (512 recommended)
ICON_RECOMMENDED = 512

FAVICON_SIZES = [16, 32, 48, 180, 192, 512]


def ensure_dir():
    os.makedirs(BRANDING_DIR, exist_ok=True)


def validate_image(file_storage, kind="logo"):
    """
    Validate an uploaded image. Returns (ok, message, ext).
    kind: 'logo' (wide, any ratio) or 'icon' (square source for favicon)
    """
    if not file_storage or not file_storage.filename:
        return False, "No file provided.", None

    filename = file_storage.filename.lower()
    ext = filename.rsplit(".", 1)[-1] if "." in filename else ""

    if kind == "icon":
        allowed = {"png", "jpg", "jpeg", "webp"}  # need raster for favicon gen
    else:
        allowed = LOGO_ALLOWED

    if ext not in allowed:
        return False, f"Format .{ext} not allowed. Use: {', '.join(sorted(allowed))}", None

    # Size check
    file_storage.seek(0, os.SEEK_END)
    size = file_storage.tell()
    file_storage.seek(0)
    if size > LOGO_MAX_BYTES:
        return False, f"File too large ({size//1024} KB). Max {LOGO_MAX_BYTES//1024} KB.", None

    # SVG: can't dimension-check, accept as logo only
    if ext == "svg":
        return True, "OK (SVG vector)", "svg"

    # Raster: check dimensions with Pillow
    try:
        from PIL import Image
        img = Image.open(file_storage)
        img.verify()
        file_storage.seek(0)
        img = Image.open(file_storage)
        w, h = img.size
        file_storage.seek(0)
    except Exception as e:
        return False, f"Could not read image: {e}", None

    if kind == "icon":
        if w < ICON_MIN_DIM or h < ICON_MIN_DIM:
            return False, f"Icon too small ({w}×{h}). Minimum {ICON_MIN_DIM}×{ICON_MIN_DIM}, {ICON_RECOMMENDED}×{ICON_RECOMMENDED} recommended.", None
        if abs(w - h) > max(w, h) * 0.1:
            return False, f"Icon should be square (got {w}×{h}). Crop to 1:1 first.", None
    else:
        if w > LOGO_MAX_DIM or h > LOGO_MAX_DIM:
            return False, f"Logo too large ({w}×{h}). Max {LOGO_MAX_DIM}px either side.", None

    return True, f"OK ({w}×{h})", ext


def save_logo(file_storage, ext):
    """Save the sidebar logo. Keeps original format."""
    ensure_dir()
    # Normalize: save as logo.<ext>, but always also keep a reference name
    dest = os.path.join(BRANDING_DIR, f"logo.{ext}")
    # Remove any old logo.* first
    for e in ("png", "svg", "jpg", "jpeg", "webp"):
        old = os.path.join(BRANDING_DIR, f"logo.{e}")
        if os.path.exists(old) and old != dest:
            try: os.remove(old)
            except OSError: pass
    file_storage.seek(0)
    file_storage.save(dest)
    return dest


def generate_favicons(file_storage):
    """
    Generate a full favicon set from one square source image.
    Returns (ok, message).
    """
    ensure_dir()
    try:
        from PIL import Image
    except ImportError:
        return False, "Pillow not installed — run: pip install Pillow"

    try:
        file_storage.seek(0)
        src = Image.open(file_storage).convert("RGBA")
    except Exception as e:
        return False, f"Could not open source: {e}"

    # Generate PNG sizes
    names = {
        16: "favicon-16x16.png",
        32: "favicon-32x32.png",
        48: "favicon-48x48.png",
        180: "apple-touch-icon.png",
        192: "android-chrome-192x192.png",
        512: "android-chrome-512x512.png",
    }
    for size, name in names.items():
        resized = src.resize((size, size), Image.LANCZOS)
        resized.save(os.path.join(BRANDING_DIR, name), "PNG", optimize=True)

    # Multi-resolution ICO (16/32/48)
    try:
        ico_sizes = [(16, 16), (32, 32), (48, 48)]
        src.save(os.path.join(BRANDING_DIR, "favicon.ico"), sizes=ico_sizes)
    except Exception:
        # Fallback: single-size ico from 32px
        src.resize((32, 32), Image.LANCZOS).save(os.path.join(BRANDING_DIR, "favicon.ico"))

    return True, "Favicon set generated (16, 32, 48, 180, 192, 512 + .ico)"


DEFAULTS = {
    "product_name": "IPDR",
    "tagline": "CGNAT Compliance Portal",
    "company_name": "Example ISP",
    "domain": "ipdr.example.com",
    "color_primary": "#20A0E0",
    "color_primary_dark": "#1880B8",
    "color_bg_dark": "#0f1923",
    "color_bg_sidebar": "#141e2a",
    "color_bg_card": "#1a2736",
    "color_bg_body": "#111a24",
    "color_success": "#2ecc71",
    "color_warning": "#f1c40f",
    "color_danger": "#e74c3c",
    "has_logo": False,
    "has_favicon": False,
    "logo_version": 0,
    "favicon_version": 0,
}
