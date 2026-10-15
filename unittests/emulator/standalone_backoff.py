#!/usr/bin/env python3
"""PIN-backoff regression using an owned UDP process and synthetic flash only."""

import argparse
import ctypes
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time


def private_port():
    for _ in range(100):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as main:
            main.bind(("127.0.0.1", 0))
            port = main.getsockname()[1]
            if port == 65535:
                continue
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as debug:
                try:
                    debug.bind(("127.0.0.1", port + 1))
                except OSError:
                    continue
                return port
    raise RuntimeError("no unused UDP port pair")


def request(peer, message_id, payload=b""):
    frame = b"?##" + struct.pack(">HL", message_id, len(payload)) + payload
    assert len(frame) <= 64
    peer.send(frame.ljust(64, b"\0"))
    frame = peer.recv(64)
    assert len(frame) == 64 and frame[:3] == b"?##", frame[:9]
    response_id, length = struct.unpack(">HL", frame[3:9])
    remaining = max(0, length - 55)
    while remaining:
        frame = peer.recv(64)
        assert len(frame) == 64 and frame[:1] == b"?"
        remaining -= min(remaining, 63)
    return response_id


def run(library, emulator):
    lib = ctypes.CDLL(str(library))
    lib.kkemu_init.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
    lib.kkemu_init.restype = ctypes.c_int
    lib.storage_setPin.argtypes = [ctypes.c_char_p]
    lib.kkemu_shutdown.argtypes = []
    lib.kkemu_shutdown.restype = None
    results = []
    for failures in (0, 3):
        with tempfile.TemporaryDirectory(prefix="kkemu-backoff-") as directory:
            flash = (ctypes.c_uint8 * 1048576).from_buffer_copy(b"\xff" * 1048576)
            assert lib.kkemu_init(flash, len(flash)) == 0
            # Internal storage helpers seed exactly the persisted state at issue;
            # no DebugLink mutations or hardware transports are involved.
            lib.storage_setPin(b"1234")
            for _ in range(failures):
                lib.storage_increasePinFails()
            lib.kkemu_shutdown()
            Path(directory, "emulator.img").write_bytes(bytes(flash))
            port = private_port()
            with Path(directory, "process.log").open("w") as log:
                proc = subprocess.Popen(
                    [str(emulator)], cwd=directory, stdout=log,
                    stderr=subprocess.STDOUT,
                    env=dict(os.environ, KEEPKEY_UDP_PORT=str(port)))
                try:
                    # Establish readiness with the emulator's health datagram,
                    # without creating a half-complete protobuf response.
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
                        peer.connect(("127.0.0.1", port))
                        peer.settimeout(0.1)
                        deadline = time.monotonic() + 5
                        while True:
                            assert proc.poll() is None, "emulator exited"
                            try:
                                peer.send(b"PINGPING")
                                if peer.recv(64) == b"PONGPONG":
                                    break
                            except (socket.timeout, ConnectionRefusedError):
                                pass
                            if time.monotonic() >= deadline:
                                raise RuntimeError("emulator failed to start")
                            time.sleep(0.02)
                        peer.settimeout(12)
                        assert request(peer, 0) == 17  # Initialize -> Features
                        assert request(peer, 24) == 2  # ClearSession -> Success
                        began = time.monotonic()
                        response = request(peer, 1, b"\x18\x01")  # protected Ping
                        elapsed = time.monotonic() - began
                        assert response == 18, response  # PinMatrixRequest
                        if failures:
                            assert elapsed >= 7, "backoff was bypassed"
                        else:
                            assert elapsed < 2, "zero-failure control stalled"
                        results.append(dict(failures=failures, response=response,
                                            elapsed=elapsed, pid=proc.pid))
                finally:
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--emulator", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run(args.library.resolve(), args.emulator.resolve())
    text = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(text)
    print(text, end="")
