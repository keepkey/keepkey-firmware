#!/usr/bin/env python3
"""SRAM budget gate for ARM firmware builds.

Fails CI when the runtime stack/heap reserve — the gap between the end of
static allocation (_ebss) and the top-of-RAM stack (_stack) — drops below the
per-variant budget, or when the largest single stack frame (-fstack-usage)
leaves less than the configured margin inside that reserve.

Why this exists: RC7's zcash-privacy build shipped with an 11,232-byte gap
while msg_write() carried a 12,416-byte automatic TrezorFrameBuffer — every
USB response overwrote static memory, hard-faulting on boot. The linker also
ASSERTs a 16 KiB floor (tools/firmware/keepkey.ld); this script is the
observability + frame-margin half of that gate.

Usage:
  check_sram_budget.py --elf bin/...firmware.keepkey.elf \
      --su-tar bin/stack-usage.tgz --budgets tools/sram-budgets.json \
      --variant zcash-privacy
"""

import argparse
import json
import sys
import tarfile

from elftools.elf.elffile import ELFFile  # pip install pyelftools


def read_symbols(elf_path):
    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".symtab")
        if symtab is None:
            sys.exit(f"ERROR: {elf_path} has no .symtab")
        wanted = {}
        for sym in symtab.iter_symbols():
            if sym.name in ("_ebss", "_stack"):
                wanted[sym.name] = sym["st_value"]
        missing = {"_ebss", "_stack"} - set(wanted)
        if missing:
            sys.exit(f"ERROR: {elf_path} missing symbols: {sorted(missing)}")
        return wanted


def largest_frames(su_tar_path, top_n=15):
    """Parse GCC -fstack-usage records from a tar of .su files.

    Record format: "<file>:<line>:<col>:<function>\t<bytes>\t<qualifier>"
    """
    frames = []
    with tarfile.open(su_tar_path, "r:*") as tar:
        for member in tar:
            if not member.name.endswith(".su") or not member.isfile():
                continue
            data = tar.extractfile(member).read().decode("utf-8", "replace")
            for line in data.splitlines():
                parts = line.rsplit("\t", 2)
                if len(parts) != 3:
                    continue
                loc, size, qual = parts
                try:
                    frames.append((int(size), loc.split("/")[-1], qual))
                except ValueError:
                    continue
    frames.sort(reverse=True)
    return frames[:top_n]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--elf", required=True)
    ap.add_argument("--su-tar", required=True)
    ap.add_argument("--budgets", required=True)
    ap.add_argument("--variant", required=True)
    args = ap.parse_args()

    budgets = json.load(open(args.budgets))
    reserve_min = budgets.get("variants", {}).get(args.variant, {}).get(
        "reserve_min", budgets["reserve_min"])
    frame_margin = budgets.get("variants", {}).get(args.variant, {}).get(
        "frame_margin", budgets["frame_margin"])

    syms = read_symbols(args.elf)
    gap = syms["_stack"] - syms["_ebss"]

    frames = largest_frames(args.su_tar)
    if not frames:
        # An empty .su archive means -fstack-usage generation broke (or the
        # tar glob went stale). Treating it as "largest frame = 0" would let
        # the margin check false-pass — fail loudly instead.
        sys.exit("ERROR: no -fstack-usage records found in "
                 f"{args.su_tar} — stack-usage generation is broken; "
                 "refusing to pass the frame-margin gate without data")
    largest = frames[0][0]

    print(f"SRAM budget report — variant: {args.variant}")
    print(f"  _ebss  = 0x{syms['_ebss']:08x}")
    print(f"  _stack = 0x{syms['_stack']:08x}")
    print(f"  stack/heap reserve (gap) = {gap:,} B "
          f"(budget: >= {reserve_min:,} B)")
    print(f"  largest stack frame      = {largest:,} B "
          f"(gap - largest must be >= {frame_margin:,} B)")
    print("  top stack frames (-fstack-usage):")
    for size, loc, qual in frames:
        print(f"    {size:7,} B  {qual:14s} {loc}")

    failed = False
    if gap < reserve_min:
        print(f"::error::SRAM gate: reserve {gap:,} B < budget "
              f"{reserve_min:,} B for {args.variant}")
        failed = True
    if gap - largest < frame_margin:
        print(f"::error::SRAM gate: reserve minus largest frame "
              f"({gap:,} - {largest:,} = {gap - largest:,} B) < margin "
              f"{frame_margin:,} B for {args.variant}")
        failed = True

    if failed:
        sys.exit(1)
    print("SRAM budget gate: PASS")


if __name__ == "__main__":
    main()
