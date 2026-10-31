"""Draws the PCForge icon with the standard library only and writes assets/icon.ico + assets/icon.png."""
import os
import struct
import sys
import zlib

BOLT = [(0.60, 0.10), (0.27, 0.55), (0.47, 0.55), (0.38, 0.90), (0.73, 0.43), (0.53, 0.43), (0.66, 0.10)]
TOP, BOTTOM = (255, 138, 40), (196, 82, 8)


def inside_poly(x, y, poly):
    hit = False
    j = len(poly) - 1
    for i in range(len(poly)):
        xi, yi = poly[i]
        xj, yj = poly[j]
        if (yi > y) != (yj > y) and x < (xj - xi) * (y - yi) / (yj - yi) + xi:
            hit = not hit
        j = i
    return hit


def rounded(x, y, r=0.22):
    dx, dy = abs(x - 0.5) - (0.5 - r), abs(y - 0.5) - (0.5 - r)
    return (max(dx, 0) ** 2 + max(dy, 0) ** 2) ** 0.5 <= r if dx > 0 and dy > 0 else (dx <= 0 or dy <= 0) and max(dx, dy) <= 0 or (dx <= r and dy <= 0) or (dy <= r and dx <= 0)


def render(size):
    ss = 3 if size <= 64 else 2
    rows = []
    for py in range(size):
        row = bytearray([0])
        for px in range(size):
            r = g = b = a = 0
            for sy in range(ss):
                for sx in range(ss):
                    x, y = (px + (sx + 0.5) / ss) / size, (py + (sy + 0.5) / ss) / size
                    if rounded(x, y):
                        t = y
                        base = tuple(TOP[i] + (BOTTOM[i] - TOP[i]) * t for i in range(3))
                        c = (255, 255, 255) if inside_poly(x, y, BOLT) else base
                        r, g, b, a = r + c[0], g + c[1], b + c[2], a + 255
            n = ss * ss
            if a:
                cnt = a / 255
                row += bytes((int(r / cnt), int(g / cnt), int(b / cnt), int(a / n)))
            else:
                row += bytes(4)
        rows.append(bytes(row))
    return rows


def png(size):
    raw = b"".join(render(size))

    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def main(out):
    os.makedirs(out, exist_ok=True)
    sizes = [16, 32, 48, 64, 256]
    images = [png(s) for s in sizes]
    with open(os.path.join(out, "icon.png"), "wb") as fh:
        fh.write(images[sizes.index(64)])
    header = struct.pack("<HHH", 0, 1, len(sizes))
    offset = 6 + 16 * len(sizes)
    entries = b""
    for s, data in zip(sizes, images):
        entries += struct.pack("<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
    with open(os.path.join(out, "icon.ico"), "wb") as fh:
        fh.write(header + entries + b"".join(images))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "assets")
