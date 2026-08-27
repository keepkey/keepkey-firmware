#!/usr/bin/env python3
"""Capture the THOR/Maya LP-withdraw percent confirm screens from kkemu.

Evidence tool for the integer-percent rendering change (no float formats).
"""

import os
import sys
import time
from pathlib import Path

os.environ.setdefault("PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION", "python")
os.environ.setdefault("TEMPORARILY_DISABLE_PROTOBUF_VERSION_CHECK", "true")

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "deps" / "python-keepkey"))
sys.path.insert(0, str(ROOT / "scripts" / "zoo"))

from keepkeylib.client import KeepKeyDebuglinkClient
from keepkeylib.transport_udp import UDPTransport
from keepkeylib import messages_pb2 as proto
from keepkeylib.tools import parse_path


def dump_layout(debug_client, filename):
    """Save the raw 2048-byte 1bpp OLED layout; converted to PNG on the host."""
    state = debug_client._call(proto.DebugLinkGetState())
    if not state.layout:
        return False
    with open(filename, "wb") as f:
        f.write(state.layout)
    return True

OUT = Path(sys.argv[1]).resolve()
OUT.mkdir(parents=True, exist_ok=True)

main_ep = os.environ.get("KK_TRANSPORT_MAIN", "127.0.0.1:11044")
debug_ep = os.environ.get("KK_TRANSPORT_DEBUG", "127.0.0.1:11045")

client = KeepKeyDebuglinkClient(UDPTransport(main_ep))
client.set_debuglink(UDPTransport(debug_ep))

client.auto_button = True
client.wipe_device()
client.load_device_by_mnemonic(
    mnemonic=("all " * 11 + "all").strip(),
    pin="",
    passphrase_protection=False,
    label="percent evidence",
    language="english",
)

counter = {"n": 0}
real_press_yes = client.debug.press_yes


def capturing_press_yes():
    counter["n"] += 1
    time.sleep(0.2)
    path = OUT / ("thor-withdraw-%02d.layout" % counter["n"])
    dump_layout(client.debug, str(path))
    print(path)
    real_press_yes()


client.debug.press_yes = capturing_press_yes


THOR_ROUTER = "d37bbe5744d730a1d98d8dc97c42f0ca46ad7146"


def _build_deposit_calldata(memo):
    selector = bytes.fromhex("1fece7b4")
    vault = bytes(12) + bytes.fromhex(THOR_ROUTER)
    asset = bytes(32)
    amount = (500000000000000000).to_bytes(32, "big")
    memo_offset = (4 * 32).to_bytes(32, "big")
    memo_bytes = memo.encode("ascii")
    memo_len = len(memo_bytes).to_bytes(32, "big")
    pad = ((len(memo_bytes) + 31) // 32) * 32
    return selector + vault + asset + amount + memo_offset + memo_len + \
        memo_bytes + bytes(pad - len(memo_bytes))


from binascii import unhexlify

client.ethereum_sign_tx(
    n=parse_path("m/44'/60'/0'/0/0"),
    nonce=1,
    gas_price=50000000000,
    gas_limit=300000,
    to=unhexlify(THOR_ROUTER),
    value=500000000000000000,
    chain_id=1,
    data=_build_deposit_calldata(
        "WITHDRAW:ETH.USDT-0xdac17f958d2ee523a2206206994597c13d831ec7:2505"
    ),
)
print("captured %d screens" % counter["n"])
