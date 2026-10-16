#!/usr/bin/env python3
"""Exercise file handling and the actual firmware parser through the CLI."""

import pathlib
import struct
import subprocess
import sys
import tempfile
import unittest


VALIDATOR = pathlib.Path(sys.argv.pop(1)).resolve()
PROGRAM_LIMIT = (1 << 20) - 10 - 512


def valid_program():
    """Independent C773 calldata fixture with one uint256 argument."""
    program = bytearray(179)
    program[:8] = b"C773\x01\x02\x00\x01"
    program[17] = 1  # Chain 1.
    program[18] = 0x11  # Contract 0x1100...00.
    program[38:42] = bytes.fromhex("aabbccdd")
    program[70] = 1  # Source, compiler and token-set hashes.
    program[102] = 2
    program[134] = 3
    program[169] = 7  # Provider and issuance/revocation epochs.
    program[173] = 8
    program[177] = 3
    program[178] = 7
    sections = (
        (1, b"\x00\x01\x00\x04Test"),
        (2, bytes.fromhex("0002 080000000100010000 010100000000000000")),
        (3, b"\x00\x00"),
        (6, b"\x00\x00"),
        (7, bytes.fromhex("0002 01000000ffffffff 0a00ffffffffffff")),
        (8, bytes.fromhex("0001 01 001c 0000000000000001 11") + bytes(19)),
        (9, struct.pack(">8H4BH", 1, 2, 0, 0, 0, 0, 2, 1, 2, 0, 0, 0, 4)),
    )
    for kind, payload in sections:
        program.extend(struct.pack(">BI", kind, len(payload)))
        program.extend(payload)
    return program


class ValidatorCLI(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = pathlib.Path(self.temp.name)
        self.program = self.directory / "program.c773"

    def invoke(self, arguments, expected_status, diagnostic=b""):
        result = subprocess.run(
            [str(VALIDATOR), *map(str, arguments)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, expected_status, result.stderr)
        self.assertIn(diagnostic, result.stderr)
        return result

    def check_bytes(self, data, status, diagnostic=b""):
        self.program.write_bytes(data)
        return self.invoke([self.program], status, diagnostic)

    def test_valid_program_reaches_untrusted_result(self):
        result = self.check_bytes(valid_program(), 0)
        self.assertEqual(result.stderr, b"")

    def test_truncated_program(self):
        self.check_bytes(valid_program()[:-1], 1, b"device verifier refused")

    def test_trailing_data(self):
        self.check_bytes(valid_program() + b"\x00", 1, b"device verifier refused")

    def test_bad_magic(self):
        data = valid_program()
        data[0] = 0
        self.check_bytes(data, 1, b"device verifier refused")

    def test_empty_file(self):
        self.check_bytes(b"", 2, b"empty or too large")

    def test_missing_file(self):
        self.invoke([self.program], 2)

    def test_usage(self):
        self.invoke([], 2, b"usage:")

    def test_read_error(self):
        # POSIX fopen succeeds on directories; fread reports EISDIR.
        self.invoke([self.directory], 2, b"could not read program")

    def test_capacity_minus_one_reaches_parser(self):
        self.check_bytes(bytes(PROGRAM_LIMIT - 1), 1, b"device verifier refused")

    def test_exact_capacity_reaches_parser(self):
        # These bytes exceed the device's program bound, but must reach its
        # verifier rather than be misclassified as a truncated file read.
        self.check_bytes(bytes(PROGRAM_LIMIT), 1, b"device verifier refused")

    def test_capacity_plus_one(self):
        self.check_bytes(bytes(PROGRAM_LIMIT + 1), 2, b"empty or too large")

    def test_far_over_capacity(self):
        self.check_bytes(bytes(PROGRAM_LIMIT + 4096), 2, b"empty or too large")


if __name__ == "__main__":
    unittest.main()
