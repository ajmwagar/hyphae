#!/usr/bin/env python3
"""Generate hyphae's logo: a deterministic hyphal network.

Reproducible by design - same seed, same SVG. No binary assets in the repo.
"""
import math, random

W = H = 640
CX, CY = W / 2, H / 2
SEED = 0x68797068  # "hyph"

def branches(rng, x, y, ang, length, width, depth, out, tips):
    if depth == 0 or length < 6:
        out.append(("dot", x, y, width))
        tips.append((x, y, width))
        return
    # slight wobble so filaments look organic, not geometric
    steps = 4
    pts = [(x, y)]
    for i in range(steps):
        ang += rng.uniform(-0.20, 0.20)
        seg = length / steps
        x += math.cos(ang) * seg
        y += math.sin(ang) * seg
        pts.append((x, y))
    d = "M " + " L ".join(f"{px:.1f} {py:.1f}" for px, py in pts)
    out.append(("path", d, width))
    # branch: one fork continues, one peels off
    branches(rng, x, y, ang + rng.uniform(0.18, 0.5), length * rng.uniform(0.55, 0.72), width * 0.62, depth - 1, out, tips)
    branches(rng, x, y, ang - rng.uniform(0.18, 0.5), length * rng.uniform(0.5, 0.68), width * 0.58, depth - 1, out, tips)

def build():
    rng = random.Random(SEED)
    shapes, tips = [], []
    # clustered, asymmetric trunks: fungi do not grow in an even sunburst
    clusters = [(0.6, 3), (2.1, 2), (3.5, 2), (4.7, 2), (5.6, 1)]
    for base, count in clusters:
        for _ in range(count):
            a0 = base + rng.uniform(-0.35, 0.35)
            r = rng.uniform(30, 74)
            x = CX + math.cos(a0) * r
            y = CY + math.sin(a0) * r
            branches(rng, x, y, a0, rng.uniform(70, 112), 6.4, 5, shapes, tips)

    # anastomosis: hyphae genuinely fuse, which is what makes a network fungal
    for _ in range(90):
        if len(tips) < 2:
            break
        ax, ay, aw = rng.choice(tips)
        best = None
        for (bx, by, bw) in tips:
            d = math.hypot(bx - ax, by - ay)
            if 18 < d < 92 and (best is None or d < best[0]):
                best = (d, bx, by, bw)
        if best:
            d, bx, by, bw = best
            mx = (ax + bx) / 2 + rng.uniform(-9, 9)
            my = (ay + by) / 2 + rng.uniform(-9, 9)
            shapes.append(("path", f"M {ax:.1f} {ay:.1f} Q {mx:.1f} {my:.1f} {bx:.1f} {by:.1f}", max(0.7, min(aw, bw) * 0.34)))
    return shapes

def to_svg(shapes):
    paths, dots = [], []
    for s in shapes:
        if s[0] == "path":
            _, d, w = s
            paths.append(f'<path d="{d}" stroke-width="{w:.2f}"/>')
        else:
            _, x, y, w = s
            dots.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{max(1.1, w*0.30):.2f}"/>')
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img" aria-label="hyphae">
  <title>hyphae</title>
  <defs>
    <radialGradient id="core" cx="50%" cy="50%" r="50%">
      <stop offset="0%" stop-color="#f6ffe9" stop-opacity="0.95"/>
      <stop offset="55%" stop-color="#8fe36b" stop-opacity="0.55"/>
      <stop offset="100%" stop-color="#8fe36b" stop-opacity="0"/>
    </radialGradient>
    <linearGradient id="fila" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#d9ffb8"/>
      <stop offset="55%" stop-color="#7ee06a"/>
      <stop offset="100%" stop-color="#3fa96a"/>
    </linearGradient>
  </defs>
  <g fill="none" stroke="url(#fila)" stroke-linecap="round" stroke-linejoin="round" opacity="0.95">
    {chr(10) + "    ".join(paths)}
  </g>
  <g fill="url(#fila)" opacity="0.9">
    {chr(10) + "    ".join(dots)}
  </g>
  <circle cx="{CX}" cy="{CY}" r="150" fill="url(#core)"/>
</svg>
'''

if __name__ == "__main__":
    import pathlib, sys
    out = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path("docs/img/hyphae-logo.svg")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(to_svg(build()))
    print(f"wrote {out} ({out.stat().st_size} bytes)")
