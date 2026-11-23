"""Draw the SegCheck icon (the two overlapping zone rings from the app's logo) as a Windows .ico.

    python scripts/launcher/make_icon.py

Writes scripts/launcher/segcheck.ico (used by SegCheck.exe) and segcheck_web/static/favicon.ico.
Needs Pillow, which SegCheck's environment already has (it comes with reportlab).
"""
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[2]
BACKGROUND = (26, 21, 16, 255)   # --bg-1
BORDER = (240, 145, 95, 90)      # soft orange edge
ORANGE = (240, 145, 95, 255)     # ring A: one network zone
TEAL = (79, 209, 197, 255)       # ring B: the other zone
SIZES = [16, 24, 32, 48, 64, 128, 256]


def draw(size=1024):
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    pen = ImageDraw.Draw(image)
    radius = size * 0.22
    pen.rounded_rectangle([0, 0, size - 1, size - 1], radius=radius, fill=BACKGROUND, outline=BORDER, width=size // 64)
    ring = size * 0.25           # ring radius
    width = int(size * 0.085)    # ring stroke
    middle = size / 2
    for colour, centre in ((ORANGE, middle - size * 0.135), (TEAL, middle + size * 0.135)):
        pen.ellipse([centre - ring, middle - ring, centre + ring, middle + ring], outline=colour, width=width)
    # The orange ring passes over the teal one at the top crossing: two separate zones, one boundary.
    top = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    ImageDraw.Draw(top).ellipse([middle - size * 0.135 - ring, middle - ring, middle - size * 0.135 + ring, middle + ring],
                                outline=ORANGE, width=width)
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rectangle([middle - size * 0.02, 0, middle + size * 0.3, middle], fill=255)
    image.paste(top, (0, 0), Image.composite(top, Image.new("RGBA", (size, size)), mask).split()[3])
    return image


def main():
    art = draw()
    targets = [ROOT / "scripts" / "launcher" / "segcheck.ico", ROOT / "segcheck_web" / "static" / "favicon.ico"]
    for target in targets:
        target.parent.mkdir(parents=True, exist_ok=True)
        art.save(target, format="ICO", sizes=[(s, s) for s in SIZES])
        print(target)
    art.resize((256, 256), Image.LANCZOS).save(ROOT / "scripts" / "launcher" / "segcheck-256.png")


if __name__ == "__main__":
    main()
