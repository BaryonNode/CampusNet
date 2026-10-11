# -*- coding: utf-8 -*-
"""生成应用图标（icon.ico / icon.png）。

需要 Pillow：  pip install pillow
用法：        python tools/make_icon.py

图标含义：蓝色圆角底 + 白色无线信号弧 —— 一眼看出是"连网络"。
在 16x16 下也能辨认，所以没放多余细节。
"""
from __future__ import annotations

import pathlib

from PIL import Image, ImageDraw

ROOT = pathlib.Path(__file__).resolve().parent.parent
S = 1024                      # 先画大图再缩放，边缘更干净
BG_TOP = (0x2F, 0x6F, 0xED)
BG_BOTTOM = (0x14, 0x3A, 0xB0)
RADIUS_RATIO = 0.23           # 圆角半径
ARC_RADII = (0.19, 0.32, 0.45)
ARC_WIDTH = 0.062
ARC_START, ARC_END = 200, 340
DOT_RATIO = 0.062
CENTER_Y = 0.70


def make_icon(size: int = S) -> Image.Image:
    # 竖向渐变
    grad = Image.new("RGB", (1, size))
    for y in range(size):
        t = y / max(1, size - 1)
        grad.putpixel((0, y), tuple(
            int(BG_TOP[i] + (BG_BOTTOM[i] - BG_TOP[i]) * t) for i in range(3)))
    grad = grad.resize((size, size))

    # 圆角遮罩
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        [0, 0, size - 1, size - 1], radius=int(size * RADIUS_RATIO), fill=255)

    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    img.paste(grad, (0, 0), mask)

    # 白色无线信号弧 + 圆点
    d = ImageDraw.Draw(img)
    cx, cy = size // 2, int(size * CENTER_Y)
    width = max(2, int(size * ARC_WIDTH))
    for ratio in ARC_RADII:
        r = int(size * ratio)
        d.arc([cx - r, cy - r, cx + r, cy + r],
              start=ARC_START, end=ARC_END, fill="white", width=width)
    dot = int(size * DOT_RATIO)
    d.ellipse([cx - dot, cy - dot, cx + dot, cy + dot], fill="white")
    return img


def main() -> int:
    img = make_icon()
    ico = ROOT / "icon.ico"
    png = ROOT / "icon.png"
    img.save(ico, format="ICO",
             sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    img.resize((256, 256), Image.LANCZOS).save(png, format="PNG")
    print("已生成：%s (%d 字节)" % (ico.name, ico.stat().st_size))
    print("已生成：%s (%d 字节)" % (png.name, png.stat().st_size))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
