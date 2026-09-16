#!/usr/bin/env python3
"""Capture the maximum-boundary ClearSign attestor screens from kkemu.

This is an emulator evidence tool, not a hardware provisioning tool. It wipes
and initializes the emulator connected at the supplied UDP endpoints.
"""

import argparse
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


# The pinned python-keepkey uses legacy generated descriptors, while the
# current device protocol is generated on demand below. Both compatibility
# switches must be set before either protobuf module is imported.
os.environ.setdefault("PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION", "python")
os.environ.setdefault("TEMPORARILY_DISABLE_PROTOBUF_VERSION_CHECK", "true")

ROOT = Path(__file__).resolve().parents[2]
PYTHON_KEEPKEY = ROOT / "deps" / "python-keepkey"
DEVICE_PROTOCOL = ROOT / "deps" / "device-protocol"
ZOO_SCRIPTS = ROOT / "scripts" / "zoo"

PROGRAM_ID = "99vQwtBwYtrqqD9YSXbdum3KBdxPAVxYTaQ3cfnJSrN2"
PROGRAM_BYTES = bytes.fromhex(
    "792689378ecd51d80406eb0caa3b62795beb10b6c5dc96bc2e0df03cbfee1abf"
)
DISCRIMINATOR = bytes.fromhex("0d9e0ddf5fd51c06")
PROGRAM_NAME = "Boundary Program 123"
INSTRUCTION_NAME = "Review All Types 123"
ARGUMENTS = (
    (1, "u64 LE", "Amount1234567890"),
    (2, "u8", "Flag123456789012"),
    (3, "public key", "RecipientPubKey1"),
    (4, "bytes32 hex", "OrderHash1234567"),
)
ACCOUNT_INDEX = 7
ACCOUNT_LABEL = "VaultAccount1234"
SCREEN_NAMES = (
    "01-schema-identity.png",
    "02-program-id-44chars.png",
    "03-discriminator-8bytes.png",
    "04-arg-u64-le-16char-label.png",
    "05-arg-u8-16char-label.png",
    "06-arg-public-key-16char-label.png",
    "07-arg-bytes32-hex-16char-label.png",
    "08-account-16char-label.png",
)


def generate_current_protocol():
    generated = tempfile.TemporaryDirectory(prefix="kk-attestor-proto-")
    subprocess.run(
        [
            "protoc",
            "-I",
            str(DEVICE_PROTOCOL),
            "--python_out=" + generated.name,
            str(DEVICE_PROTOCOL / "types.proto"),
            str(DEVICE_PROTOCOL / "messages.proto"),
        ],
        check=True,
    )
    sys.path.insert(0, generated.name)
    module = importlib.import_module("messages_pb2")
    return generated, module


def length_prefixed_text(value):
    raw = value.encode("ascii")
    if not 1 <= len(raw) <= 255:
        raise ValueError("schema text length out of bounds")
    return bytes([len(raw)]) + raw


def boundary_schema():
    payload = bytearray(b"KKSOLSC1")
    payload.append(1)
    payload.extend(PROGRAM_BYTES)
    payload.append(len(DISCRIMINATOR))
    payload.extend(DISCRIMINATOR)
    if len(PROGRAM_NAME) != 20 or len(INSTRUCTION_NAME) != 20:
        raise ValueError(
            "boundary program and instruction names must be 20 characters"
        )
    payload.extend(length_prefixed_text(PROGRAM_NAME))
    payload.extend(length_prefixed_text(INSTRUCTION_NAME))
    payload.append(len(ARGUMENTS))
    for arg_type, _display_type, label in ARGUMENTS:
        if len(label) != 16:
            raise ValueError("boundary argument labels must be 16 characters")
        payload.append(arg_type)
        payload.extend(length_prefixed_text(label))
    if len(ACCOUNT_LABEL) != 16:
        raise ValueError("boundary account label must be 16 characters")
    payload.append(1)
    payload.append(ACCOUNT_INDEX)
    payload.extend(length_prefixed_text(ACCOUNT_LABEL))
    return bytes(payload)


def git_revision(path):
    return subprocess.check_output(
        ["git", "-C", str(path), "rev-parse", "HEAD"], text=True
    ).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="directory for PNG evidence")
    parser.add_argument(
        "--main",
        default=os.environ.get("KK_TRANSPORT_MAIN", "127.0.0.1:11044"),
        help="kkemu main UDP endpoint",
    )
    parser.add_argument(
        "--debug",
        default=os.environ.get("KK_TRANSPORT_DEBUG", "127.0.0.1:11045"),
        help="kkemu debug UDP endpoint",
    )
    args = parser.parse_args()

    generated, attestor_proto = generate_current_protocol()
    try:
        sys.path.insert(0, str(PYTHON_KEEPKEY))
        sys.path.insert(0, str(ZOO_SCRIPTS))

        from keepkeylib import mapping
        from keepkeylib import messages_pb2 as proto
        from keepkeylib.client import KeepKeyDebuglinkClient
        from keepkeylib.transport_udp import UDPTransport
        from screenshot import capture_screenshot

        # The deliberately older pinned host package has no attestor wrappers.
        # Register only the new request/response wire classes; framing,
        # confirmations, and DebugLink remain the pinned host implementation.
        mapping.map_class_to_type[attestor_proto.ClearsignAttestorSign] = 1702
        mapping.map_type_to_class[1703] = attestor_proto.ClearsignAttestorSignature

        output = Path(args.output).resolve()
        output.mkdir(parents=True, exist_ok=True)
        client = KeepKeyDebuglinkClient(UDPTransport(args.main))
        client.set_debuglink(UDPTransport(args.debug))

        client.auto_button = True
        client.wipe_device()
        client.load_device_by_mnemonic(
            mnemonic=("all " * 11 + "all").strip(),
            pin="",
            passphrase_protection=False,
            label="RC21 OLED Gate",
            language="english",
        )
        client.apply_policy("AdvancedMode", 1)
        client.auto_button = False

        response = client.call_raw(
            attestor_proto.ClearsignAttestorSign(payload=boundary_schema())
        )
        for index, name in enumerate(SCREEN_NAMES):
            if not isinstance(response, proto.ButtonRequest):
                raise RuntimeError(
                    "screen %d expected ButtonRequest, got %s"
                    % (index + 1, type(response).__name__)
                )
            time.sleep(0.2)
            path = output / name
            if not capture_screenshot(client.debug, str(path), scale=3):
                raise RuntimeError("failed to capture " + name)
            print(path)
            client.debug.press_yes()
            response = client.call_raw(proto.ButtonAck())

        if not isinstance(response, attestor_proto.ClearsignAttestorSignature):
            raise RuntimeError(
                "expected attestor signature, got " + type(response).__name__
            )
        if len(response.signature) != 64 or len(response.public_key) != 33:
            raise RuntimeError("attestor returned malformed key or signature")

        manifest = {
            "firmware_commit": git_revision(ROOT),
            "device_protocol_commit": git_revision(DEVICE_PROTOCOL),
            "program_name": PROGRAM_NAME,
            "program_name_characters": len(PROGRAM_NAME),
            "instruction_name": INSTRUCTION_NAME,
            "instruction_name_characters": len(INSTRUCTION_NAME),
            "program_id": PROGRAM_ID,
            "program_id_characters": len(PROGRAM_ID),
            "discriminator_hex": DISCRIMINATOR.hex(),
            "discriminator_bytes": len(DISCRIMINATOR),
            "arguments": [
                {"type": display_type, "label": label, "label_characters": len(label)}
                for _arg_type, display_type, label in ARGUMENTS
            ],
            "account": {
                "index": ACCOUNT_INDEX,
                "label": ACCOUNT_LABEL,
                "label_characters": len(ACCOUNT_LABEL),
            },
            "screens": list(SCREEN_NAMES),
            "attestation_signature_bytes": len(response.signature),
            "attestation_public_key_bytes": len(response.public_key),
        }
        with (output / "manifest.json").open("w", encoding="utf-8") as handle:
            json.dump(manifest, handle, indent=2, sort_keys=True)
            handle.write("\n")
        print("captured %d screens; attestation completed" % len(SCREEN_NAMES))
    finally:
        generated.cleanup()


if __name__ == "__main__":
    main()
