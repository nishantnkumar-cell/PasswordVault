#!/usr/bin/env python3
"""Generate the Secret Vault app icon in every format the platforms need.

The icon is a white keyhole on a signal-red tile. Run from the repository root:

    pip install resvg-py pillow
    python3 contrib/icons/generate.py

It rewrites everything under contrib/icons/ except this script and README.md.
The SVG sources are written first; the PNG, ICO and ICNS files are rendered
from them, so edit the shapes here, never the outputs.
"""

import io
import os

import resvg_py
from PIL import Image

OUT = os.path.dirname(os.path.abspath(__file__))
APP_ID = "dev.passwordvault.app"

RED_LIGHT = "#EE3B36"
RED_DARK = "#B5161B"
HALO = "#FFFFFF"
RING = "#FFC9C4"
GLYPH = "#FFFFFF"

# The keyhole on a 512 grid: a round head and a tapered slot.
KEYHOLE = (
    '<circle cx="256" cy="214" r="62"/>'
    '<path d="M228 244H284L306 368H206Z"/>'
)


def gradient(x, y, side):
    return (
        f'<linearGradient id="bg" gradientUnits="userSpaceOnUse" '
        f'x1="{x}" y1="{y}" x2="{x + side}" y2="{y + side}">'
        f'<stop offset="0" stop-color="{RED_LIGHT}"/>'
        f'<stop offset="1" stop-color="{RED_DARK}"/></linearGradient>'
    )


def full_svg():
    """64 px and up: inset tile, soft halo and a thin ring around the keyhole."""
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">'
        f"<defs>{gradient(16, 16, 480)}</defs>"
        '<rect x="16" y="16" width="480" height="480" rx="108" fill="url(#bg)"/>'
        f'<circle cx="256" cy="256" r="184" fill="{HALO}" fill-opacity="0.16"/>'
        f'<path fill="{RING}" fill-rule="evenodd" d="M72 256a184 184 0 1 0 368 0a184 184 0 1 0 -368 0Z'
        'M84 256a172 172 0 1 0 344 0a172 172 0 1 0 -344 0Z"/>'
        f'<g fill="{GLYPH}">{KEYHOLE}</g>'
        "</svg>"
    )


def small_svg():
    """48 px and below: full-bleed tile and a larger keyhole, no halo or ring."""
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">'
        f"<defs>{gradient(0, 0, 512)}</defs>"
        '<rect width="512" height="512" rx="96" fill="url(#bg)"/>'
        f'<g fill="{GLYPH}" transform="translate(256 260) scale(1.4) translate(-256 -260)">{KEYHOLE}</g>'
        "</svg>"
    )


def macos_svg():
    """macOS draws no mask: the tile sits on a 1024 canvas with a transparent margin."""
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024">'
        "<defs>"
        f"{gradient(100, 100, 824)}"
        '<filter id="shadow" x="-10%" y="-10%" width="120%" height="130%">'
        '<feDropShadow dx="0" dy="10" stdDeviation="12" flood-color="#000" flood-opacity="0.28"/>'
        "</filter></defs>"
        '<rect x="100" y="100" width="824" height="824" rx="185" fill="url(#bg)" filter="url(#shadow)"/>'
        '<g transform="translate(100 100) scale(1.609375)">'
        f'<circle cx="256" cy="256" r="200" fill="{HALO}" fill-opacity="0.16"/>'
        f'<path fill="{RING}" fill-rule="evenodd" d="M56 256a200 200 0 1 0 400 0a200 200 0 1 0 -400 0Z'
        'M68 256a188 188 0 1 0 376 0a188 188 0 1 0 -376 0Z"/>'
        f'<g fill="{GLYPH}">{KEYHOLE}</g></g>'
        "</svg>"
    )


def ios_svg():
    """iOS and iPadOS mask the corners themselves: an opaque, square 1024 tile."""
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">'
        f"<defs>{gradient(0, 0, 512)}</defs>"
        '<rect width="512" height="512" fill="url(#bg)"/>'
        f'<circle cx="256" cy="256" r="184" fill="{HALO}" fill-opacity="0.16"/>'
        f'<path fill="{RING}" fill-rule="evenodd" d="M72 256a184 184 0 1 0 368 0a184 184 0 1 0 -368 0Z'
        'M84 256a172 172 0 1 0 344 0a172 172 0 1 0 -344 0Z"/>'
        f'<g fill="{GLYPH}">{KEYHOLE}</g>'
        "</svg>"
    )


def symbolic_svg():
    """GNOME symbolic icon: the keyhole alone, one colour, on a 16 px grid."""
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16">'
        '<g fill="#2e3436" transform="translate(8 8) scale(0.065) translate(-256 -260)">'
        f"{KEYHOLE}</g></svg>"
    )


def write(path, text):
    full = os.path.join(OUT, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8", newline="\n") as f:
        f.write(text + "\n")


def render(svg, size):
    png = resvg_py.svg_to_bytes(svg_string=svg, width=size, height=size)
    return Image.open(io.BytesIO(bytes(png))).convert("RGBA")


def for_size(size):
    return small_svg() if size <= 48 else full_svg()


def main():
    write("secret-vault.svg", full_svg())
    write("secret-vault-small.svg", small_svg())
    write("secret-vault-macos.svg", macos_svg())

    # Linux: a drop-in hicolor theme tree named after the app id.
    write(f"hicolor/scalable/apps/{APP_ID}.svg", full_svg())
    write(f"hicolor/symbolic/apps/{APP_ID}-symbolic.svg", symbolic_svg())
    for size in (16, 24, 32, 48, 64, 128, 256, 512):
        d = os.path.join(OUT, f"hicolor/{size}x{size}/apps")
        os.makedirs(d, exist_ok=True)
        render(for_size(size), size).save(os.path.join(d, f"{APP_ID}.png"), optimize=True)

    # Windows: one .ico with every size Explorer, the taskbar and the tray ask for.
    ico_sizes = (16, 20, 24, 32, 40, 48, 64, 256)
    ico = [render(for_size(s), s) for s in ico_sizes]
    ico[-1].save(
        os.path.join(OUT, "secret-vault.ico"),
        format="ICO",
        sizes=[(s, s) for s in ico_sizes],
        append_images=ico[:-1],
    )

    # macOS: .icns from the padded artwork.
    icns_sizes = (16, 32, 64, 128, 256, 512, 1024)
    icns = [render(macos_svg(), s) for s in icns_sizes]
    icns[-1].save(os.path.join(OUT, "secret-vault.icns"), format="ICNS", append_images=icns[:-1])

    # iPhone and iPad: one opaque 1024 PNG in the app's asset catalog.
    ios = os.path.join(OUT, "../../mobile/ios/SecretVault/Assets.xcassets/AppIcon.appiconset/icon-1024.png")
    os.makedirs(os.path.dirname(ios), exist_ok=True)
    render(ios_svg(), 1024).convert("RGB").save(ios, optimize=True)


if __name__ == "__main__":
    main()
