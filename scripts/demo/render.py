#!/usr/bin/env python3
"""Render an asciicast v2 recording (from record.py) to an animated GIF.

    scripts/demo/render.py out/live.cast docs/assets/demo-live.gif

The terminal is emulated with pyte and drawn with Pillow; ffmpeg builds the
GIF palette. Text is never edited. The one cosmetic change is a highlighter
that colors severity words, statuses, category IDs and ATT&CK IDs in output
the program printed without color, the way an editor theme would.

    pip install pyte pillow     # plus ffmpeg on PATH
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

import pyte
from PIL import Image, ImageDraw, ImageFont

# GitHub dark-ish palette.
BG = (13, 17, 23)
FG = (201, 209, 217)
CHROME = (22, 27, 34)
BORDER = (48, 54, 61)
ANSI16 = {
    "black": (72, 79, 88), "red": (255, 123, 114), "green": (63, 185, 80), "brown": (210, 153, 34),
    "blue": (88, 166, 255), "magenta": (188, 140, 255), "cyan": (57, 197, 207), "white": (177, 186, 196),
    "brightblack": (110, 118, 129), "brightred": (255, 161, 152), "brightgreen": (86, 211, 100),
    "brightbrown": (227, 179, 65), "brightblue": (121, 192, 255), "brightmagenta": (210, 168, 255),
    "brightcyan": (86, 212, 221), "brightwhite": (240, 246, 252),
}
ANSI16["yellow"] = ANSI16["brown"]
ANSI16["brightyellow"] = ANSI16["brightbrown"]
CRIT_BG = (218, 54, 51)

HIGHLIGHT = [
    (re.compile(r"\b(critical|CRITICAL)\b"), ((255, 255, 255), CRIT_BG, True)),
    (re.compile(r"\b(high|HIGH|FAIL)\b"), (ANSI16["red"], None, True)),
    (re.compile(r"\b(medium|MEDIUM)\b"), (ANSI16["brown"], None, False)),
    (re.compile(r"\b(low|LOW)\b"), (ANSI16["cyan"], None, False)),
    (re.compile(r"\b(PASS|ok:)"), (ANSI16["green"], None, True)),
    (re.compile(r"\b(clean)\b"), (ANSI16["green"], None, False)),
    (re.compile(r"\bSKIP\b"), (ANSI16["brightblack"], None, False)),
    (re.compile(r"\bPS\d\d\b"), (ANSI16["cyan"], None, True)),
    (re.compile(r"\bT\d{4}(?:\.\d{3})?\b"), (ANSI16["magenta"], None, False)),
    (re.compile(r"^pisentry (Top 10|posture audit)\b.*$"), (ANSI16["brightwhite"], None, True)),
    (re.compile(r"\b[A-Z]{3}-\d\d\b"), (ANSI16["brightblue"], None, False)),
]


class Screen(pyte.Screen):
    """pyte plus SU/SD (CSI S, CSI T), which tmux uses to clear a pane."""

    def scroll_up(self, count=None, *args, **kwargs):
        top, bottom = (self.margins.top, self.margins.bottom) if self.margins else (0, self.lines - 1)
        for _ in range(min(count or 1, bottom - top + 1)):
            for y in range(top, bottom):
                self.buffer[y] = self.buffer[y + 1]
            self.buffer[bottom] = pyte.screens.StaticDefaultDict(self.default_char)
        self.dirty.update(range(self.lines))

    def scroll_down(self, count=None, *args, **kwargs):
        top, bottom = (self.margins.top, self.margins.bottom) if self.margins else (0, self.lines - 1)
        for _ in range(min(count or 1, bottom - top + 1)):
            for y in range(bottom, top, -1):
                self.buffer[y] = self.buffer[y - 1]
            self.buffer[top] = pyte.screens.StaticDefaultDict(self.default_char)
        self.dirty.update(range(self.lines))


class Stream(pyte.ByteStream):
    csi = dict(pyte.ByteStream.csi, S="scroll_up", T="scroll_down")


def color(c, default):
    if c == "default":
        return default
    if c in ANSI16:
        return ANSI16[c]
    if isinstance(c, str) and re.fullmatch(r"[0-9a-fA-F]{6}", c):
        return tuple(int(c[i:i + 2], 16) for i in (0, 2, 4))
    return default


class Painter:
    def __init__(self, cols, rows, font_size, title):
        here = os.path.dirname(os.path.abspath(__file__))
        self.font = ImageFont.truetype(find_font("JetBrainsMono-Regular.ttf", "DejaVuSansMono.ttf"), font_size)
        self.bold = ImageFont.truetype(find_font("JetBrainsMono-Bold.ttf", "DejaVuSansMono-Bold.ttf"), font_size)
        self.ui = ImageFont.truetype(find_font("JetBrainsMono-Medium.ttf", "DejaVuSans.ttf"), font_size - 2)
        self.cw = round(self.font.getlength("M"))
        self.ch = round(font_size * 1.38)
        self.cols, self.rows = cols, rows
        self.pad, self.bar, self.margin = 18, 38, 0
        self.w = cols * self.cw + 2 * self.pad
        self.h = rows * self.ch + 2 * self.pad + self.bar
        self.base = Image.new("RGB", (self.w, self.h), BG)
        d = ImageDraw.Draw(self.base)
        d.rectangle([0, 0, self.w, self.bar], fill=CHROME)
        d.line([0, self.bar, self.w, self.bar], fill=BORDER)
        for i, c in enumerate([(255, 95, 87), (254, 188, 46), (40, 200, 64)]):
            x = 20 + i * 22
            d.ellipse([x - 6, self.bar // 2 - 6, x + 6, self.bar // 2 + 6], fill=c)
        tw = d.textlength(title, font=self.ui)
        d.text(((self.w - tw) / 2, self.bar / 2), title, font=self.ui, fill=(139, 148, 158), anchor="lm")

    def paint(self, screen):
        img = self.base.copy()
        d = ImageDraw.Draw(img)
        y0 = self.bar + self.pad
        for y in range(self.rows):
            line = screen.buffer[y]
            text = "".join(line[x].data for x in range(self.cols))
            hl = [None] * self.cols
            if text.startswith(("PASS", "SKIP")):
                # A passing check's severity is not a finding; keep it quiet.
                for m in re.finditer(r"\b(critical|high|medium|low)\b", text):
                    for x in range(m.start(), m.end()):
                        hl[x] = (ANSI16["brightblack"], None, False)
            for rx, style in HIGHLIGHT:
                for m in rx.finditer(text):
                    for x in range(m.start(), m.end()):
                        if hl[x] is None:
                            hl[x] = style
            for x in range(self.cols):
                c = line[x]
                fg, bg = color(c.fg, FG), (CRIT_BG if c.bg == "red" else color(c.bg, None))
                bold = c.bold
                if c.fg == "default" and c.bg == "default" and hl[x]:
                    fg, bg, bold = hl[x][0], hl[x][1], hl[x][2] or c.bold
                if c.reverse:
                    fg, bg = (bg or BG), fg
                if bg is None and getattr(screen.cursor, "x", -1) == x and screen.cursor.y == y and not screen.cursor.hidden:
                    bg, fg = (88, 166, 255), BG
                px, py = self.pad + x * self.cw, y0 + y * self.ch
                if bg is not None:
                    d.rectangle([px, py, px + self.cw - 1, py + self.ch - 1], fill=bg)
                if c.data.strip():
                    d.text((px, py + self.ch / 2), c.data, font=self.bold if bold else self.font,
                           fill=fg if not getattr(c, "faint", False) else tuple(v // 2 for v in fg), anchor="lm")
        return img


def find_font(*names):
    for root in ("/usr/share/fonts", "/usr/local/share/fonts", os.path.expanduser("~/.fonts"),
                 "/Library/Fonts", "/System/Library/Fonts"):
        for dirpath, _, files in os.walk(root):
            for n in names:
                if n in files:
                    return os.path.join(dirpath, n)
    sys.exit(f"none of {names} found; install JetBrains Mono or DejaVu Sans Mono")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cast")
    ap.add_argument("gif")
    ap.add_argument("--font-size", type=int, default=15)
    ap.add_argument("--idle", type=float, default=1.6, help="cap pauses longer than this many seconds")
    ap.add_argument("--speed", type=float, default=1.0)
    ap.add_argument("--fps", type=float, default=12, help="max frames per second")
    ap.add_argument("--hold", type=float, default=3.0, help="hold the last frame this long")
    ap.add_argument("--title", default=None)
    a = ap.parse_args()
    if not shutil.which("ffmpeg"):
        sys.exit("ffmpeg is required")

    with open(a.cast, encoding="utf-8") as f:
        header = json.loads(f.readline())
        events = [json.loads(l) for l in f if l.strip()]
    cols, rows = header["width"], header["height"]
    screen = Screen(cols, rows)
    stream = Stream(screen)
    painter = Painter(cols, rows, a.font_size, a.title or header.get("title", "pisentry"))

    # Collapse long pauses, then sample at most fps frames per second.
    t, last, timeline = 0.0, 0.0, []
    for ts, kind, data in events:
        if kind != "o":
            continue
        gap = min(ts - last, a.idle) / a.speed
        last = ts
        t += gap
        timeline.append((t, data))
    step = 1.0 / a.fps
    tmp = tempfile.mkdtemp(prefix="pisentry-render-")
    frames, prev, i, n = [], None, 0, len(timeline)
    clock = 0.0
    while i < n:
        clock = max(clock + step, timeline[i][0])
        while i < n and timeline[i][0] <= clock:
            stream.feed(timeline[i][1].encode("utf-8"))
            i += 1
        img = painter.paint(screen)
        if prev is not None and img.tobytes() == prev[1]:
            continue
        path = os.path.join(tmp, f"f{len(frames):05d}.png")
        img.save(path)
        frames.append([path, clock])
        prev = (path, img.tobytes())
    # Durations from timestamps.
    concat = os.path.join(tmp, "list.txt")
    with open(concat, "w") as f:
        for k, (path, at) in enumerate(frames):
            nxt = frames[k + 1][1] if k + 1 < len(frames) else at + a.hold
            f.write(f"file '{path}'\nduration {max(nxt - at, 0.02):.3f}\n")
        f.write(f"file '{frames[-1][0]}'\n")
    palette = os.path.join(tmp, "palette.png")
    subprocess.run(["ffmpeg", "-loglevel", "error", "-y", "-f", "concat", "-safe", "0", "-i", concat,
                    "-vf", "palettegen=max_colors=128:stats_mode=full", palette], check=True)
    subprocess.run(["ffmpeg", "-loglevel", "error", "-y", "-f", "concat", "-safe", "0", "-i", concat,
                    "-i", palette, "-lavfi", "paletteuse=dither=none:diff_mode=rectangle",
                    "-gifflags", "+transdiff", "-loop", "0", a.gif], check=True)
    shutil.rmtree(tmp)
    total = frames[-1][1] + a.hold
    print(f"[render] {a.gif}: {len(frames)} frames, {total:.1f}s, {os.path.getsize(a.gif) / 1e6:.2f} MB, "
          f"{painter.w}x{painter.h}", file=sys.stderr)


if __name__ == "__main__":
    main()
