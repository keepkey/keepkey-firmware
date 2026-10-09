#!/usr/bin/env python3

"""Generate tron_tokens.def from the vetted tron_tokens.json.

Each row is checked before it can reach the firmware: the address must be a
valid Base58Check mainnet address, the symbol a short uppercase label used by
no other row, and the decimals within what the display formatter supports.
"""

from __future__ import print_function

import hashlib
import json
import os
import re
import sys

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
SYMBOL = re.compile(r"^[A-Z0-9]{1,8}$")


def b58check_decode(text):
    value = 0
    for char in text:
        value = value * 58 + ALPHABET.index(char)
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    raw = b"\0" * (len(text) - len(text.lstrip("1"))) + raw
    payload, checksum = raw[:-4], raw[-4:]
    digest = hashlib.sha256(hashlib.sha256(payload).digest()).digest()
    if digest[:4] != checksum:
        raise ValueError("bad Base58Check checksum: %s" % text)
    return payload


def rows(path):
    with open(path, "r") as source:
        tokens = json.load(source)["tokens"]
    if not tokens:
        raise ValueError("no TRC-20 tokens in %s" % path)
    seen_addresses, seen_symbols = set(), set()
    for token in tokens:
        raw = b58check_decode(token["address"])
        if len(raw) != 21 or raw[0] != 0x41:
            raise ValueError("not a TRON mainnet address: %s" % token["address"])
        symbol, decimals = token["symbol"], token["decimals"]
        if not SYMBOL.match(symbol) or symbol == "TRX":
            raise ValueError("unsafe symbol: %r" % symbol)
        if not isinstance(decimals, int) or not 0 <= decimals <= 18:
            raise ValueError("unsupported decimals for %s" % symbol)
        if raw in seen_addresses or symbol in seen_symbols:
            raise ValueError("duplicate address or symbol: %s" % symbol)
        if not token.get("issuer_source") or not token.get("chain_check"):
            raise ValueError("missing provenance for %s" % symbol)
        seen_addresses.add(raw)
        seen_symbols.add(symbol)
        yield raw, symbol, decimals, token["address"]


def main(argv):
    if len(argv) != 3:
        print("usage: %s TRON_TOKENS_JSON OUTPUT_DEF" % argv[0], file=sys.stderr)
        return 2
    out = []
    for raw, symbol, decimals, address in sorted(rows(argv[1])):
        escaped = "".join("\\x%02x" % b for b in raw)
        out.append('X("%s", "%s", %d) // %s\n' % (escaped, symbol, decimals,
                                                  address))
    text = "".join(out)
    if os.path.exists(argv[2]):
        with open(argv[2], "r") as existing:
            if existing.read() == text:
                return 0
    with open(argv[2], "w") as target:
        target.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
