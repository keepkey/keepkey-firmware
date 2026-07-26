#!/usr/bin/env python3
"""Enforce the fixed-schedule shape of the ARM Pallas scalar multiplier."""

import argparse
import re
import subprocess
import sys
from pathlib import Path


SYMBOL_RE = re.compile(r"^([0-9a-fA-F]+) <([^>]+)>:$")
CONDITIONAL_BRANCHES = {
    "beq",
    "bne",
    "bcs",
    "bcc",
    "bmi",
    "bpl",
    "bvs",
    "bvc",
    "bhi",
    "bls",
    "bge",
    "blt",
    "bgt",
    "ble",
    "cbz",
    "cbnz",
}
FORBIDDEN_VARIABLE_LATENCY = {"umull", "umlal", "smull", "smlal", "udiv", "sdiv"}


def parse_instruction(line):
    parts = [part.strip() for part in line.split("\t") if part.strip()]
    if len(parts) < 3 or not parts[0].endswith(":"):
        return None
    try:
        address = int(parts[0][:-1], 16)
    except ValueError:
        return None
    mnemonic = parts[2].split(".", 1)[0]
    operands = parts[3] if len(parts) > 3 else ""
    return address, mnemonic, operands


def symbol_instructions(disassembly, symbol):
    lines = disassembly.splitlines()
    start = None
    for index, line in enumerate(lines):
        match = SYMBOL_RE.match(line)
        if match and match.group(2) == symbol:
            start = index + 1
            break
    if start is None:
        return None

    instructions = []
    for line in lines[start:]:
        if SYMBOL_RE.match(line):
            break
        instruction = parse_instruction(line)
        if instruction is not None:
            instructions.append(instruction)
    return instructions


def branch_target(operands):
    match = re.match(r"([0-9a-fA-F]+)", operands)
    return int(match.group(1), 16) if match else None


def verify_full(disassembly):
    symbol = "pallas_ct_point_mult"
    instructions = symbol_instructions(disassembly, symbol)
    if instructions is None:
        raise ValueError(f"missing required ARM symbol: {symbol}")

    non_canary_branches = []
    for index, instruction in enumerate(instructions):
        address, mnemonic, operands = instruction
        if mnemonic not in CONDITIONAL_BRANCHES:
            continue

        next_instruction = (
            instructions[index + 1] if index + 1 < len(instructions) else None
        )
        if (
            next_instruction is not None
            and next_instruction[1] == "bl"
            and "<__stack_chk_fail>" in next_instruction[2]
        ):
            continue
        non_canary_branches.append((address, mnemonic, branch_target(operands)))

    if len(non_canary_branches) != 1:
        raise ValueError(
            f"{symbol} must have one fixed loop branch; found "
            f"{non_canary_branches}"
        )

    branch_address, mnemonic, target = non_canary_branches[0]
    if target is None or target >= branch_address:
        raise ValueError(f"{symbol} loop branch is not backward: {non_canary_branches[0]}")

    required_calls = {
        "ct_point_double": None,
        "ct_point_add_internal": None,
        "ct_point_select": None,
    }
    for address, instruction_mnemonic, operands in instructions:
        if instruction_mnemonic != "bl":
            continue
        for required in required_calls:
            if f"<{required}>" in operands:
                required_calls[required] = address

    missing = [name for name, address in required_calls.items() if address is None]
    if missing:
        raise ValueError(f"{symbol} is missing fixed-round calls: {missing}")
    outside_loop = [
        name
        for name, address in required_calls.items()
        if not target <= address < branch_address
    ]
    if outside_loop:
        raise ValueError(f"fixed-round calls moved outside scalar loop: {outside_loop}")

    progress_symbol = "pallas_ct_point_mult_progress"
    progress_instructions = symbol_instructions(disassembly, progress_symbol)
    if progress_instructions is None:
        raise ValueError(f"missing required ARM symbol: {progress_symbol}")
    progress_branches = []
    for index, instruction in enumerate(progress_instructions):
        address, instruction_mnemonic, operands = instruction
        if instruction_mnemonic not in CONDITIONAL_BRANCHES:
            continue
        next_instruction = (
            progress_instructions[index + 1]
            if index + 1 < len(progress_instructions)
            else None
        )
        if (
            next_instruction is not None
            and next_instruction[1] == "bl"
            and "<__stack_chk_fail>" in next_instruction[2]
        ):
            continue
        progress_branches.append(
            (address, instruction_mnemonic, branch_target(operands))
        )
    if len(progress_branches) != 1:
        raise ValueError(
            f"{progress_symbol} must have one fixed loop branch; found "
            f"{progress_branches}"
        )
    progress_branch_address, _, progress_target = progress_branches[0]
    if progress_target is None or progress_target >= progress_branch_address:
        raise ValueError(
            f"{progress_symbol} loop branch is not backward: "
            f"{progress_branches[0]}"
        )
    progress_required_calls = {
        "ct_point_double": None,
        "ct_point_add_internal": None,
        "ct_point_select": None,
    }
    for address, instruction_mnemonic, operands in progress_instructions:
        if instruction_mnemonic != "bl":
            continue
        for required in progress_required_calls:
            if f"<{required}>" in operands:
                progress_required_calls[required] = address
    progress_missing = [
        name for name, address in progress_required_calls.items() if address is None
    ]
    if progress_missing:
        raise ValueError(
            f"{progress_symbol} is missing fixed-round calls: {progress_missing}"
        )
    progress_outside_loop = [
        name
        for name, address in progress_required_calls.items()
        if not progress_target <= address < progress_branch_address
    ]
    if progress_outside_loop:
        raise ValueError(
            f"{progress_symbol} fixed-round calls moved outside scalar loop: "
            f"{progress_outside_loop}"
        )

    # Secret-dependent selects are written as masks.  On the pinned ARM build,
    # every remaining conditional branch in this module must therefore be a
    # backward, fixed-bound loop (apart from stack-canary failure branches).
    unexpected_branches = []
    ct_symbols = []
    for line in disassembly.splitlines():
        match = SYMBOL_RE.match(line)
        if match and match.group(2).startswith(("ct_", "pallas_ct_")):
            ct_symbols.append(match.group(2))
    for ct_symbol in ct_symbols:
        ct_instructions = symbol_instructions(disassembly, ct_symbol)
        for index, instruction in enumerate(ct_instructions):
            address, instruction_mnemonic, operands = instruction
            if instruction_mnemonic not in CONDITIONAL_BRANCHES:
                continue
            next_instruction = (
                ct_instructions[index + 1]
                if index + 1 < len(ct_instructions)
                else None
            )
            if (
                next_instruction is not None
                and next_instruction[1] == "bl"
                and "<__stack_chk_fail>" in next_instruction[2]
            ):
                continue
            ct_target = branch_target(operands)
            if ct_target is None or ct_target >= address:
                unexpected_branches.append((ct_symbol, instruction))
    if unexpected_branches:
        raise ValueError(
            "secret arithmetic contains a non-loop conditional branch: "
            f"{unexpected_branches}"
        )

    current_symbol = None
    forbidden_instructions = []
    forbidden_conditional_execution = []
    for line in disassembly.splitlines():
        symbol_match = SYMBOL_RE.match(line)
        if symbol_match:
            current_symbol = symbol_match.group(2)
            continue
        if current_symbol is None or not current_symbol.startswith(("ct_", "pallas_ct_")):
            continue
        instruction = parse_instruction(line)
        if instruction is None:
            continue
        if instruction[1] in FORBIDDEN_VARIABLE_LATENCY:
            forbidden_instructions.append((current_symbol, instruction))
        if instruction[1].startswith("it") and current_symbol != "ct_fe_to_bn":
            forbidden_conditional_execution.append((current_symbol, instruction))
    if forbidden_instructions:
        raise ValueError(
            "secret arithmetic contains variable-latency long multiply/divide: "
            f"{forbidden_instructions}"
        )
    if forbidden_conditional_execution:
        raise ValueError(
            "secret arithmetic contains conditional execution: "
            f"{forbidden_conditional_execution}"
        )

    print(
        "Pallas ARM disassembly gate: PASS "
        f"(regular + progress multipliers each have one backward {mnemonic} "
        "loop; double/add/select all inside; "
        "only fixed backward loops; no secret IT; no long multiply/divide)"
    )


def verify_bitcoin_only(disassembly):
    forbidden = ("pallas_ct_", "redpallas_", "pallas_point_")
    present = [name for name in forbidden if f"<{name}" in disassembly]
    if present:
        raise ValueError(f"bitcoin-only image contains privacy symbols: {present}")
    print("Pallas ARM disassembly gate: PASS (privacy code absent from bitcoin-only)")


def main():
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--elf", type=Path)
    source.add_argument("--disassembly", type=Path)
    parser.add_argument("--objdump", default="arm-none-eabi-objdump")
    parser.add_argument("--variant", choices=("full", "bitcoin-only"), required=True)
    args = parser.parse_args()

    if args.disassembly:
        disassembly = args.disassembly.read_text(encoding="utf-8")
    else:
        result = subprocess.run(
            [args.objdump, "-d", str(args.elf)],
            check=True,
            stdout=subprocess.PIPE,
            universal_newlines=True,
        )
        disassembly = result.stdout

    if args.variant == "full":
        verify_full(disassembly)
    else:
        verify_bitcoin_only(disassembly)


if __name__ == "__main__":
    try:
        main()
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        print(f"Pallas ARM disassembly gate: FAIL: {error}", file=sys.stderr)
        sys.exit(1)
