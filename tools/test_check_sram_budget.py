"""Regression checks for the stack-usage acceptance gate."""

import io
import tarfile
import tempfile
import unittest

from check_sram_budget import largest_frames


class StackUsageRecords(unittest.TestCase):
    def parse(self, record):
        data = record.encode("utf-8")
        with tempfile.NamedTemporaryFile(suffix=".tar") as archive:
            with tarfile.open(fileobj=archive, mode="w") as tar:
                info = tarfile.TarInfo("firmware/example.su")
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            archive.flush()
            return largest_frames(archive.name)

    def test_static_frame_is_measured(self):
        self.assertEqual(
            [(128, "example.c:4:2:sign", "static")],
            self.parse("example.c:4:2:sign\t128\tstatic\n"),
        )

    def test_dynamic_frame_cannot_pass_the_gate(self):
        with self.assertRaisesRegex(SystemExit, "dynamic stack frame"):
            self.parse("example.c:4:2:sign\t128\tdynamic\n")

    def test_bounded_dynamic_frame_uses_compiler_maximum(self):
        self.assertEqual(
            [(128, "example.c:4:2:sign", "dynamic,bounded")],
            self.parse("example.c:4:2:sign\t128\tdynamic,bounded\n"),
        )


if __name__ == "__main__":
    unittest.main()
