#!/usr/bin/env python3
"""Capture the on-device dice-entry screens from kkemu.

Evidence tool for the dice_entropy ResetDevice flow: drives a full reset with
device-side dice collection via DebugLinkDecision.input injection and saves
the OLED at each interesting state.
"""

import hashlib
import os
import sys
import time
from pathlib import Path

os.environ.setdefault("PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION", "python")
os.environ.setdefault("TEMPORARILY_DISABLE_PROTOBUF_VERSION_CHECK", "true")

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "deps" / "python-keepkey"))

from keepkeylib.client import KeepKeyDebuglinkClient, _write_png
from keepkeylib.transport_udp import UDPTransport
from keepkeylib import messages_pb2 as proto

OUT = Path(sys.argv[1]).resolve()
OUT.mkdir(parents=True, exist_ok=True)

client = KeepKeyDebuglinkClient(
    UDPTransport(os.environ.get("KK_TRANSPORT_MAIN", "127.0.0.1:11044")))
client.set_debuglink(
    UDPTransport(os.environ.get("KK_TRANSPORT_DEBUG", "127.0.0.1:11045")))


def snap(name):
    time.sleep(0.3)
    layout = client.debug.read_layout()
    rows = []
    for y in range(64):
        row = bytearray(256)
        for x in range(256):
            b = layout[x + (y // 8) * 256]
            if isinstance(b, str):
                b = ord(b)
            if (b >> (y % 8)) & 1:
                row[x] = 255
        rows.append(bytes(row))
    path = OUT / name
    with open(path, "wb") as f:
        f.write(_write_png(str(path), 256, 64, rows))
    print(path)


client.auto_button = True
client.wipe_device()
client.auto_button = False

ret = client.call_raw(proto.ResetDevice(
    display_random=True, strength=256, passphrase_protection=False,
    pin_protection=False, language='english', label='dice evidence',
    dice_entropy=True))
assert isinstance(ret, proto.ButtonRequest), ret

client.transport.write(proto.ButtonAck())
time.sleep(0.3)
snap("01-dice-screen-initial.png")

client.debug.press_input("123")
snap("02-after-three-rolls.png")

client.debug.press_input("u")
snap("03-after-undo.png")

rolls = "123456" * 17  # 102, extras past 99 dropped; net = 2 + 99 capped
client.debug.press_input(rolls[:40])
time.sleep(0.2)
client.debug.press_input(rolls[40:80])
time.sleep(0.2)
client.debug.press_input(rolls[80:])
resp = client.transport.read_blocking()
assert isinstance(resp, proto.ButtonRequest), resp
snap("04-digest-confirm.png")

client.debug.press_yes()
ret = client.call_raw(proto.ButtonAck())
assert isinstance(ret, proto.ButtonRequest), ret  # post-mix entropy display
snap("05-postmix-internal-entropy.png")

client.debug.press_yes()
ret = client.call_raw(proto.ButtonAck())
assert isinstance(ret, proto.EntropyRequest), ret
ret = client.call_raw(proto.EntropyAck(entropy=b'E' * 32))

assert isinstance(ret, proto.ButtonRequest), ret
snap("06-backup-explainer.png")
client.debug.press_yes()
ret = client.call_raw(proto.ButtonAck())
while isinstance(ret, proto.ButtonRequest):
    client.debug.press_yes()
    ret = client.call_raw(proto.ButtonAck())
assert isinstance(ret, proto.Success), ret
print("flow complete:", ret.message)
