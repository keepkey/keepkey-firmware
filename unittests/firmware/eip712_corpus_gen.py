#!/usr/bin/env python3
"""Regenerate eip712_corpus.inc from eip712_corpus.json.

The corpus is a list of real-world EIP-712 documents, one per protocol, each
written from the type strings in the protocol's own source (see "source").
Every one must sign on the device; Eip712Stream.RealWorldCorpus walks each
through the firmware and compares its domain separator and message hash with
the "expected" values here.

Those values are computed by a reference encoder written from the EIP-712
specification (below; pure Python, no firmware code). With --crosscheck
<node_modules> the same documents are also hashed by MetaMask's
@metamask/eth-sig-util (signTypedData V4) and ethers' TypedDataEncoder, and
the script refuses to write anything unless all of them agree.

    python3 eip712_corpus_gen.py [--crosscheck path/to/node_modules]
"""

import argparse
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(HERE, "eip712_corpus.json")
INC = os.path.join(HERE, "eip712_corpus.inc")

# --- keccak-256 (pure Python) ------------------------------------------------
_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M = (1 << 64) - 1


def _rol(x, n):
    return ((x << n) | (x >> (64 - n))) & _M if n else x


def _f(a):
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _ROT[x][y])
        a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
              for y in range(5)] for x in range(5)]
        a[0][0] ^= rc
    return a


def keccak(data):
    rate = 136
    data = bytearray(data)
    data.append(1)
    while len(data) % rate:
        data.append(0)
    data[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(data), rate):
        for i in range(rate // 8):
            a[i % 5][i // 5] ^= int.from_bytes(data[off + 8 * i:off + 8 * i + 8],
                                               "little")
        a = _f(a)
    return b"".join(a[i % 5][i // 5].to_bytes(8, "little") for i in range(4))


assert keccak(b"").hex() == (
    "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")

# --- EIP-712 reference encoder, from the specification -----------------------


def base_type(t):
    return t.split("[", 1)[0]


def encode_type(primary, types):
    deps = []

    def collect(name):
        if name in deps or name not in types:
            return
        deps.append(name)
        for field in types[name]:
            collect(base_type(field["type"]))

    collect(primary)
    deps.remove(primary)
    return "".join(
        "%s(%s)" % (n, ",".join("%s %s" % (f["type"], f["name"])
                                for f in types[n]))
        for n in [primary] + sorted(deps))


def to_int(v):
    if isinstance(v, bool):
        raise ValueError("bool is not an integer")
    if isinstance(v, str):
        return int(v, 16) if v.startswith("0x") else int(v)
    return int(v)


def hex_bytes(v):
    assert v.startswith("0x"), v
    return bytes.fromhex(v[2:])


def encode_value(t, v, types):
    if t.endswith("]"):
        inner = t[:t.rindex("[")]
        return keccak(b"".join(encode_value(inner, x, types) for x in v))
    if t in types:
        return hash_struct(t, v, types)
    if t == "string":
        return keccak(v.encode("utf-8"))
    if t == "bytes":
        return keccak(hex_bytes(v))
    if t == "address":
        return bytes(12) + hex_bytes(v)
    if t == "bool":
        return (1 if v else 0).to_bytes(32, "big")
    if t.startswith("bytes"):
        return hex_bytes(v).ljust(32, b"\0")
    if t.startswith("uint"):
        return to_int(v).to_bytes(32, "big")
    if t.startswith("int"):
        return (to_int(v) % (1 << 256)).to_bytes(32, "big")
    raise ValueError("unsupported type " + t)


def hash_struct(name, data, types):
    out = keccak(encode_type(name, types).encode("ascii"))
    for f in types[name]:
        out += encode_value(f["type"], data[f["name"]], types)
    return keccak(out)


def reference(doc):
    t = doc["types"]
    domain = hash_struct("EIP712Domain", doc["domain"], t)
    message = hash_struct(doc["primaryType"], doc["message"], t)
    return {
        "domain_separator": domain.hex(),
        "message_hash": message.hex(),
        "digest": keccak(b"\x19\x01" + domain + message).hex(),
    }


# --- What a host sends: one value per device member_path ---------------------


def leaf_bytes(t, v):
    if t == "string":
        return v.encode("utf-8")
    if t == "bytes":
        return hex_bytes(v)
    if t == "address":
        b = hex_bytes(v)
        assert len(b) == 20, v
        return b
    if t == "bool":
        return bytes([1 if v else 0])
    m = re.match(r"^bytes([0-9]+)$", t)
    if m:
        b = hex_bytes(v)
        assert len(b) == int(m.group(1)), (t, v)
        return b
    m = re.match(r"^(u?)int([0-9]+)$", t)
    if m:
        n = int(m.group(2)) // 8
        x = to_int(v)
        if m.group(1):
            assert 0 <= x < (1 << (8 * n)), (t, v)
        else:
            assert -(1 << (8 * n - 1)) <= x < (1 << (8 * n - 1)), (t, v)
        return (x % (1 << (8 * n))).to_bytes(n, "big")
    raise ValueError("unsupported leaf " + t)


def flatten(types, t, v, path, out):
    if t.endswith("]"):
        inner = t[:t.rindex("[")]
        dim = t[t.rindex("[") + 1:-1]
        assert not dim or int(dim) == len(v), (t, len(v))
        out.append((path, len(v).to_bytes(2, "big"), True))
        for i, x in enumerate(v):
            flatten(types, inner, x, path + [i], out)
    elif t in types:
        for i, f in enumerate(types[t]):
            flatten(types, f["type"], v[f["name"]], path + [i], out)
    else:
        out.append((path, leaf_bytes(t, v), False))


def values(doc):
    out = []
    flatten(doc["types"], "EIP712Domain", doc["domain"], [0], out)
    flatten(doc["types"], doc["primaryType"], doc["message"], [1], out)
    return out


# --- Independent JavaScript implementations ----------------------------------

_JS = r"""
const path = require('path');
const nm = process.argv[1];
const sigUtil = require(path.join(nm, '@metamask/eth-sig-util'));
const ethers = require(path.join(nm, 'ethers'));
const corpus = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const hex = (b) => Buffer.from(b).toString('hex');
const out = corpus.map(({ doc }) => {
  const v4 = sigUtil.SignTypedDataVersion.V4;
  const r = {
    sigutil: {
      domain_separator: hex(sigUtil.TypedDataUtils.hashStruct(
          'EIP712Domain', doc.domain, doc.types, v4)),
      message_hash: hex(sigUtil.TypedDataUtils.hashStruct(
          doc.primaryType, doc.message, doc.types, v4)),
      digest: hex(sigUtil.TypedDataUtils.eip712Hash(doc, v4)),
    },
  };
  try {
    const types = Object.assign({}, doc.types);
    delete types.EIP712Domain;
    const enc = ethers.utils._TypedDataEncoder;
    r.ethers = {
      domain_separator: enc.hashDomain(doc.domain).slice(2),
      message_hash: enc.from(types, doc.primaryType)
          .hash(doc.message).slice(2),
      digest: enc.hash(doc.domain, types, doc.message).slice(2),
    };
  } catch (e) {
    r.ethers = { error: String(e.message || e).slice(0, 120) };
  }
  return r;
});
process.stdout.write(JSON.stringify(out));
"""


def crosscheck(corpus, node_modules):
    res = subprocess.run(["node", "-e", _JS, node_modules],
                         input=json.dumps(corpus).encode(),
                         capture_output=True, check=True)
    results = json.loads(res.stdout)
    ok = True
    for entry, r in zip(corpus, results):
        ref = reference(entry["doc"])
        if r["sigutil"] != ref:
            print("MISMATCH eth-sig-util:", entry["id"], r["sigutil"], ref)
            ok = False
        if "error" in r["ethers"]:
            print("ethers refused %s: %s" % (entry["id"], r["ethers"]["error"]))
        elif r["ethers"] != ref:
            print("MISMATCH ethers:", entry["id"], r["ethers"], ref)
            ok = False
        else:
            print("agree (spec, eth-sig-util, ethers): " + entry["id"])
    return ok


# --- C++ table ---------------------------------------------------------------


def c_str(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def emit(corpus):
    lines = [
        "// Generated by eip712_corpus_gen.py from eip712_corpus.json. Do not"
        " edit.",
        "// clang-format off",
    ]
    for entry in corpus:
        doc = entry["doc"]
        exp = entry["expected"]
        vals = values(doc)
        leaves = sum(1 for _, _, is_len in vals if not is_len)
        lines.append("{%s, %s," % (c_str(entry["id"]), c_str(doc["primaryType"])))
        lines.append(" {")
        for name, members in doc["types"].items():
            ms = ", ".join("{%s, %s}" % (c_str(m["name"]), c_str(m["type"]))
                           for m in members)
            lines.append("  {%s, {%s}}," % (c_str(name), ms))
        lines.append(" },")
        lines.append(" {")
        for path, b, _ in vals:
            lines.append("  {{%s}, %s}," % (", ".join(str(p) for p in path),
                                           c_str(b.hex())))
        lines.append(" },")
        lines.append(" %d, %s, %s}," % (leaves, c_str(exp["domain_separator"]),
                                        c_str(exp["message_hash"])))
    lines.append("// clang-format on")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--crosscheck", metavar="NODE_MODULES")
    args = ap.parse_args()
    with open(CORPUS) as f:
        corpus = json.load(f)
    for entry in corpus:
        entry["expected"] = reference(entry["doc"])
        values(entry["doc"])  # every value must be encodable
    if args.crosscheck and not crosscheck(corpus, args.crosscheck):
        sys.exit("independent implementations disagree; nothing written")
    with open(CORPUS, "w") as f:
        json.dump(corpus, f, indent=1)
        f.write("\n")
    with open(INC, "w") as f:
        f.write(emit(corpus))
    print("wrote %d documents" % len(corpus))


if __name__ == "__main__":
    main()
