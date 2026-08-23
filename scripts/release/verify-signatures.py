#!/usr/bin/env python3
"""Verify the 3-of-5 signatures on a KeepKey firmware image, host-side.

    scripts/release/verify-signatures.py <image.bin> [image.bin ...]
    scripts/release/verify-signatures.py --self-test

Why this exists
---------------
`hash-manifest.sh --require-signed` is a STRUCTURAL gate: it proves the
canonical unsigned draft was not published, and a signature region holding one
non-zero byte passes it. It cannot detect a placeholder and it cannot detect a
forgery. This does the real check -- the same one the device performs in
`lib/board/signatures.c:signatures_ok()` -- so a release can be verified before
it ships rather than by a user's bootloader afterwards.

What is verified, mirroring signatures_ok() exactly:

  * magic is 'KPKY'
  * the three key indices are each in 1..PUBKEYS and mutually distinct
  * digest = sha256(image[META_LEN : META_LEN + codelen])
  * each of the three 64-byte compact signatures verifies against the pubkey
    its index selects

Header layout (256-byte descriptor, from memory.h / hash-manifest.sh):

    0x00  4  magic 'KPKY'        0x08  1  sig_index1     0x40  64  signature 1
    0x04  4  codelen (LE)        0x09  1  sig_index2     0x80  64  signature 2
                                 0x0A  1  sig_index3     0xC0  64  signature 3

The public keys are parsed out of `include/keepkey/board/pubkeys.h` at runtime
rather than duplicated here, so a key rotation cannot leave this script
verifying against a stale set. If the header ever stops parsing, that is a
failure, not a fallback.
"""

import hashlib
import re
import sys
from pathlib import Path

try:
    from ecdsa import BadSignatureError, SECP256k1, VerifyingKey
    from ecdsa.util import sigdecode_string
except ImportError:
    sys.exit("error: needs `ecdsa` (pip install ecdsa) -- python-keepkey already depends on it")

META_LEN = 256
OFF_MAGIC, OFF_CODELEN = 0x00, 0x04
OFF_SIGINDEX = (0x08, 0x09, 0x0A)
OFF_SIG = (0x40, 0x80, 0xC0)
SIG_LEN = 64
MAGIC = b"KPKY"

REPO = Path(__file__).resolve().parents[2]
PUBKEYS_H = REPO / "include" / "keepkey" / "board" / "pubkeys.h"

# secp256k1 group order, for the low-S report.
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def load_pubkeys(path=PUBKEYS_H):
    """Parse the pubkey table out of pubkeys.h. Uncompressed, 65 bytes, 0x04."""
    src = path.read_text()
    body = src[src.index("static const uint8_t pubkey"):]
    body = body[: body.index("};")]
    keys, cur = [], []
    for value in re.findall(r"0x([0-9a-fA-F]{2})", body):
        cur.append(int(value, 16))
        if len(cur) == 65:
            keys.append(bytes(cur))
            cur = []
    if cur:
        raise ValueError(f"trailing {len(cur)} bytes: pubkeys.h did not parse as 65-byte keys")
    if not keys:
        raise ValueError("no pubkeys parsed")
    for i, k in enumerate(keys):
        if k[0] != 0x04:
            raise ValueError(f"pubkey {i + 1} is not uncompressed (0x{k[0]:02x})")
    return keys


def verify_image(path, keys):
    """Return (ok, [lines]). Mirrors signatures_ok()."""
    out = []
    blob = path.read_bytes()
    if len(blob) < META_LEN:
        return False, [f"  file is {len(blob)} bytes, shorter than the {META_LEN}-byte descriptor"]

    if blob[OFF_MAGIC:OFF_MAGIC + 4] != MAGIC:
        return False, [f"  bad magic {blob[OFF_MAGIC:OFF_MAGIC + 4]!r}, expected {MAGIC!r}"]

    codelen = int.from_bytes(blob[OFF_CODELEN:OFF_CODELEN + 4], "little")
    if codelen == 0 or META_LEN + codelen > len(blob):
        return False, [f"  codelen {codelen} does not fit a {len(blob)}-byte file"]
    out.append(f"  codelen   {codelen} bytes")

    indices = [blob[o] for o in OFF_SIGINDEX]
    for n, idx in enumerate(indices, 1):
        if not 1 <= idx <= len(keys):
            return False, out + [f"  sig_index{n} = {idx}, outside 1..{len(keys)}"]
    if len(set(indices)) != len(indices):
        return False, out + [f"  duplicate key indices {indices} -- a 3-of-5 needs three distinct keys"]
    out.append(f"  keys      {indices[0]}, {indices[1]}, {indices[2]}")

    digest = hashlib.sha256(blob[META_LEN:META_LEN + codelen]).digest()
    out.append(f"  digest    {digest.hex()}")

    ok = True
    for n, (idx, off) in enumerate(zip(indices, OFF_SIG), 1):
        sig = blob[off:off + SIG_LEN]
        vk = VerifyingKey.from_string(keys[idx - 1][1:], curve=SECP256k1)
        try:
            vk.verify_digest(sig, digest, sigdecode=sigdecode_string)
        except BadSignatureError:
            out.append(f"  sig{n} (key {idx})  INVALID")
            ok = False
            continue
        # Reported, not enforced: the device accepts either form here, so
        # failing on it would reject images the device treats as valid.
        s = int.from_bytes(sig[32:], "big")
        note = "" if s <= N // 2 else "  [high-S, non-canonical]"
        out.append(f"  sig{n} (key {idx})  ok{note}")
    return ok, out


def self_test():
    """Prove the checks fire. Signs a fake image with throwaway keys, so it
    exercises the real verify path rather than asserting on constants."""
    from ecdsa import SigningKey
    from ecdsa.util import sigencode_string
    import tempfile

    sks = [SigningKey.generate(curve=SECP256k1) for _ in range(5)]
    keys = [b"\x04" + sk.get_verifying_key().to_string() for sk in sks]
    code = b"\xa5" * 512
    digest = hashlib.sha256(code).digest()

    def build(indices, sign_with=None, corrupt=False):
        img = bytearray(META_LEN + len(code))
        img[0:4] = MAGIC
        img[OFF_CODELEN:OFF_CODELEN + 4] = len(code).to_bytes(4, "little")
        for o, idx in zip(OFF_SIGINDEX, indices):
            img[o] = idx
        for off, idx in zip(OFF_SIG, sign_with or indices):
            # Clamp only the fixture's choice of signer: out-of-range indices
            # are what the header check under test is supposed to reject, so
            # the builder must still produce a file for it to reject.
            sk = sks[(idx - 1) % len(sks)]
            sig = sk.sign_digest(digest, sigencode=sigencode_string)
            img[off:off + SIG_LEN] = sig
        img[META_LEN:] = code
        if corrupt:
            img[META_LEN] ^= 0xFF
        return bytes(img)

    failures = []
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "f.bin"

        def check(label, blob, expect):
            p.write_bytes(blob)
            got, _ = verify_image(p, keys)
            if got != expect:
                failures.append(f"{label}: expected {expect}, got {got}")

        check("a properly signed image verifies", build([1, 2, 3]), True)
        check("a modified image fails", build([1, 2, 3], corrupt=True), False)
        check("duplicate indices fail", build([1, 1, 2]), False)
        check("index 0 fails", build([0, 2, 3]), False)
        check("index 6 fails", build([6, 2, 3]), False)
        # The one that matters: right structure, wrong signer.
        check("a signature by the wrong key fails", build([1, 2, 3], sign_with=[1, 2, 4]), False)
        # And the gate hash-manifest.sh cannot catch.
        blob = bytearray(build([1, 2, 3]))
        blob[OFF_SIG[2]:OFF_SIG[2] + SIG_LEN] = b"\x01" * SIG_LEN
        check("a non-zero placeholder signature fails", bytes(blob), False)

    for f in failures:
        print(f"  FAIL {f}")
    print(f"\nself-test: {'PASSED' if not failures else str(len(failures)) + ' FAILED'}")
    return 1 if failures else 0


def main(argv):
    if "--self-test" in argv:
        return self_test()
    if len(argv) < 2:
        return print(__doc__.strip()) or 2

    keys = load_pubkeys()
    print(f"{len(keys)} public keys from {PUBKEYS_H.relative_to(REPO)}\n")

    worst = 0
    for arg in argv[1:]:
        path = Path(arg)
        print(path)
        if not path.is_file():
            print("  not a file")
            worst = 1
            continue
        ok, lines = verify_image(path, keys)
        print("\n".join(lines))
        print(f"  => {'SIGNED' if ok else 'NOT VERIFIED'}\n")
        worst = worst or (0 if ok else 1)
    return worst


if __name__ == "__main__":
    sys.exit(main(sys.argv))
