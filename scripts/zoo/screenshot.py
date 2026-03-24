"""
screenshot.py — Capture and decode KeepKey emulator OLED screenshots.

The DebugLinkGetState response contains a 2048-byte `layout` field
packed as 1 bit per pixel (256 wide x 64 tall). Each byte holds 8
vertical pixels, LSB = topmost row within that byte.

Byte index: x + (y // 8) * 256
Bit within byte: y % 8
"""
import os
from PIL import Image


OLED_W = 256
OLED_H = 64
LAYOUT_SIZE = OLED_W * OLED_H // 8  # 2048 bytes

# Default upscale factor for readability (256x64 is tiny on modern screens)
DEFAULT_SCALE = 2


def decode_layout(layout_bytes, scale=1):
    """Decode 2048-byte bitfield into a PIL Image.

    Args:
        layout_bytes: 2048-byte 1bpp bitfield from DebugLinkGetState.layout
        scale: Integer upscale factor (1=native 256x64, 2=512x128, etc.)
    """
    w, h = OLED_W * scale, OLED_H * scale
    im = Image.new("RGB", (w, h), (0, 0, 0))
    pix = im.load()

    for x in range(OLED_W):
        for y in range(OLED_H):
            byte_idx = x + (y // 8) * OLED_W
            if byte_idx < len(layout_bytes):
                if (layout_bytes[byte_idx] >> (y % 8)) & 1:
                    # Fill scale x scale block
                    for sx in range(scale):
                        for sy in range(scale):
                            pix[x * scale + sx, y * scale + sy] = (255, 255, 255)

    return im


def capture_screenshot(debug_client, filename, scale=DEFAULT_SCALE):
    """Capture current OLED state via DebugLink and save as PNG.

    Args:
        debug_client: DebugLink instance (has read_state() or _call())
        filename: Output PNG path
        scale: Integer upscale factor (default 2 for 512x128 output)

    Returns:
        True if screenshot captured, False if layout unavailable.
    """
    from keepkeylib import messages_pb2 as proto

    state = debug_client._call(proto.DebugLinkGetState())

    if not state.HasField('layout') or len(state.layout) < LAYOUT_SIZE:
        print(f"  WARNING: layout field empty or too small ({len(state.layout) if state.HasField('layout') else 0} bytes)")
        return False

    im = decode_layout(state.layout, scale=scale)

    os.makedirs(os.path.dirname(filename) or '.', exist_ok=True)
    im.save(filename)
    return True


def decode_layout_raw(layout_bytes):
    """Decode layout to native 256x64 without scaling (for programmatic use)."""
    return decode_layout(layout_bytes, scale=1)
