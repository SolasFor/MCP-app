"""Pure-Python in-memory BGRA-to-PNG encoder with bounded dimensions and byte budgets."""
from __future__ import annotations

import struct
import zlib

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def _chunk(tag: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(tag + data) & 0xFFFFFFFF
    return struct.pack("!I", len(data)) + tag + data + struct.pack("!I", crc)


def _bgra_to_rgb_scanlines(bgra: bytes, width: int, height: int, step: int) -> tuple[bytes, int, int]:
    """Convert top-down BGRA bytes to RGB PNG scanlines with nearest-step decimation."""
    out_w = max(1, (width + step - 1) // step)
    out_h = max(1, (height + step - 1) // step)
    src_stride = width * 4
    rows: list[bytes] = []
    if step == 1:
        for y in range(height):
            row = bgra[y * src_stride : (y + 1) * src_stride]
            rgb = bytearray(out_w * 3)
            rgb[0::3] = row[2::4]
            rgb[1::3] = row[1::4]
            rgb[2::3] = row[0::4]
            rows.append(b"\x00" + bytes(rgb))
        return b"".join(rows), out_w, out_h

    for oy in range(out_h):
        sy = min(oy * step, height - 1)
        row = bgra[sy * src_stride : (sy + 1) * src_stride]
        sub = row[:: 4 * step]
        rgb = bytearray(len(sub) * 3)
        rgb[0::3] = row[2 :: 4 * step][: len(sub)]
        rgb[1::3] = row[1 :: 4 * step][: len(sub)]
        rgb[2::3] = row[0 :: 4 * step][: len(sub)]
        rows.append(b"\x00" + bytes(rgb))
    return b"".join(rows), out_w, out_h


def _encode_rgb_png(scanlines: bytes, width: int, height: int, *, level: int = 6) -> bytes:
    ihdr = struct.pack("!IIBBBBB", width, height, 8, 2, 0, 0, 0)
    idat = zlib.compress(scanlines, level=level)
    return _PNG_SIGNATURE + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", idat) + _chunk(b"IEND", b"")


def encode_bgra_to_png(
    bgra: bytes,
    width: int,
    height: int,
    *,
    max_width: int = 1280,
    max_bytes: int = 1_500_000,
) -> tuple[bytes, int, int]:
    """Encode raw top-down BGRA frame buffer into size-bounded PNG bytes in memory only."""
    if width <= 0 or height <= 0:
        raise ValueError("Invalid image dimensions")
    expected = width * height * 4
    if len(bgra) < expected:
        raise ValueError("BGRA buffer is smaller than width * height * 4")

    step = 1
    while (width + step - 1) // step > max_width:
        step += 1

    while True:
        scanlines, out_w, out_h = _bgra_to_rgb_scanlines(bgra, width, height, step)
        png = _encode_rgb_png(scanlines, out_w, out_h, level=6)
        if len(png) <= max_bytes or (out_w <= 320 and out_h <= 240):
            return png, out_w, out_h
        if step >= 8:
            png_max = _encode_rgb_png(scanlines, out_w, out_h, level=9)
            return png_max, out_w, out_h
        step += 1
