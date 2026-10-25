#!/usr/bin/env python3
"""Generate the extension PNG icons without third-party libraries."""

import os
import struct
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ICON_DIR = os.path.join(ROOT, "icons")
SIZES = (16, 32, 48, 128)
SUPERSAMPLE = 4

SHIELD = (
    (0.50, 0.12), (0.78, 0.22), (0.78, 0.47), (0.74, 0.63),
    (0.64, 0.76), (0.50, 0.86), (0.36, 0.76), (0.26, 0.63),
    (0.22, 0.47), (0.22, 0.22),
)

CHECK = ((0.35, 0.48), (0.46, 0.59), (0.66, 0.37))
CHECK_WIDTH = 0.085
CORNER_RADIUS = 0.22


def inside_rounded_square(x, y, radius):
    if x < 0 or x > 1 or y < 0 or y > 1:
        return False

    cx = min(max(x, radius), 1 - radius)
    cy = min(max(y, radius), 1 - radius)
    dx = x - cx
    dy = y - cy
    return (dx * dx + dy * dy) <= radius * radius


def inside_polygon(x, y, points):
    inside = False
    count = len(points)
    j = count - 1

    for i in range(count):
        xi, yi = points[i]
        xj, yj = points[j]
        crosses = ((yi > y) != (yj > y)) and (
            x < (xj - xi) * (y - yi) / ((yj - yi) or 1e-12) + xi
        )
        if crosses:
            inside = not inside
        j = i

    return inside


def distance_to_segment(px, py, ax, ay, bx, by):
    vx = bx - ax
    vy = by - ay
    length_squared = vx * vx + vy * vy
    if length_squared == 0:
        return ((px - ax) ** 2 + (py - ay) ** 2) ** 0.5

    t = ((px - ax) * vx + (py - ay) * vy) / length_squared
    t = max(0.0, min(1.0, t))
    dx = px - (ax + t * vx)
    dy = py - (ay + t * vy)
    return (dx * dx + dy * dy) ** 0.5


def render(size):
    source_size = size * SUPERSAMPLE
    pixels = bytearray(source_size * source_size * 4)

    for y in range(source_size):
        ny = (y + 0.5) / source_size
        for x in range(source_size):
            nx = (x + 0.5) / source_size
            offset = (y * source_size + x) * 4

            if not inside_rounded_square(nx, ny, CORNER_RADIUS):
                continue

            blend = max(0.0, min(1.0, (nx * 0.35) + (ny * 0.65)))
            red = int(99 + (55 - 99) * blend)
            green = int(102 + (48 - 102) * blend)
            blue = int(241 + (163 - 241) * blend)
            alpha = 255

            if inside_polygon(nx, ny, SHIELD):
                red, green, blue = 248, 250, 252

                check_distance = min(
                    distance_to_segment(nx, ny, *CHECK[0], *CHECK[1]),
                    distance_to_segment(nx, ny, *CHECK[1], *CHECK[2]),
                )

                if check_distance <= CHECK_WIDTH / 2:
                    red, green, blue = 55, 48, 163

            pixels[offset:offset + 4] = bytes((red, green, blue, alpha))

    return bytes(pixels), source_size


def downsample(source, source_size, target_size):
    factor = source_size // target_size
    output = bytearray(target_size * target_size * 4)

    for y in range(target_size):
        for x in range(target_size):
            red = green = blue = alpha = 0
            for sy in range(factor):
                for sx in range(factor):
                    offset = (((y * factor + sy) * source_size) + (x * factor + sx)) * 4
                    red += source[offset]
                    green += source[offset + 1]
                    blue += source[offset + 2]
                    alpha += source[offset + 3]

            count = factor * factor
            offset = (y * target_size + x) * 4
            output[offset:offset + 4] = bytes((
                round(red / count),
                round(green / count),
                round(blue / count),
                round(alpha / count),
            ))

    return bytes(output)


def png_chunk(kind, payload):
    body = kind + payload
    return (
        struct.pack(">I", len(payload))
        + body
        + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)
    )


def write_png(path, width, height, rgba):
    stride = width * 4
    raw = bytearray()

    for y in range(height):
        raw.append(0)
        raw.extend(rgba[y * stride:(y + 1) * stride])

    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    png = (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", header)
        + png_chunk(b"IDAT", zlib.compress(bytes(raw), 9))
        + png_chunk(b"IEND", b"")
    )

    with open(path, "wb") as handle:
        handle.write(png)


def main():
    os.makedirs(ICON_DIR, exist_ok=True)

    for size in SIZES:
        source, source_size = render(size)
        output = downsample(source, source_size, size)
        path = os.path.join(ICON_DIR, "icon-" + str(size) + ".png")
        write_png(path, size, size, output)
        print("wrote", os.path.relpath(path, ROOT))


if __name__ == "__main__":
    main()
