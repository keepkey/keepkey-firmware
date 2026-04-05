#!/usr/bin/env python3
"""Minimal smoke test: boot emulator, read one OLED frame, save PNG, exit.

Usage: python3 smoke_screenshot.py [output.png]
Exit 0 = screenshot captured, non-blank
Exit 1 = failed
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'deps', 'python-keepkey'))

from keepkeylib.client import KeepKeyDebuglinkClient
from keepkeylib.transport_udp import UDPTransport
from keepkeylib import messages_pb2 as proto

out = sys.argv[1] if len(sys.argv) > 1 else '/tmp/smoke.png'
main_host = os.environ.get('KK_TRANSPORT_MAIN', '127.0.0.1:11044')
debug_host = os.environ.get('KK_TRANSPORT_DEBUG', '127.0.0.1:11045')

print("1. Connecting to %s..." % main_host)
c = KeepKeyDebuglinkClient(UDPTransport(main_host))
c.set_debuglink(UDPTransport(debug_host))
v = c.features
print("2. Firmware: %s v%d.%d.%d" % (v.vendor, v.major_version, v.minor_version, v.patch_version))

print("3. DebugLinkGetState (read_layout)...")
state = c.debug._call(proto.DebugLinkGetState())
layout = state.layout
print("4. Layout: %d bytes" % len(layout))

if len(layout) < 2048:
    print("FAIL: layout too small")
    sys.exit(1)

# Check non-blank
nonzero = sum(1 for b in layout if (b if isinstance(b, int) else ord(b)) != 0)
print("5. Non-zero bytes: %d / 2048" % nonzero)

# Decode to PNG
try:
    from screenshot import capture_screenshot
    os.makedirs(os.path.dirname(out) or '.', exist_ok=True)
    capture_screenshot(c.debug, out, scale=3)
    sz = os.path.getsize(out)
    print("6. PNG: %s (%d bytes)" % (out, sz))
    if sz > 400:
        print("PASS: real screenshot captured")
        sys.exit(0)
    else:
        print("FAIL: PNG too small (likely blank)")
        sys.exit(1)
except ImportError:
    # No Pillow — just report layout stats
    if nonzero > 10:
        print("PASS: layout has content (%d non-zero bytes), but no Pillow to save PNG" % nonzero)
        sys.exit(0)
    else:
        print("FAIL: layout is blank")
        sys.exit(1)
