"""Regression tests for fixture generation's independent-encoder gate."""
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import eip712_corpus_gen as gen


class CorpusCrosscheck(unittest.TestCase):
    def setUp(self):
        self.entry = {
            "id": "test-message",
            "doc": {
                "types": {"EIP712Domain": [],
                          "Message": [{"name": "value", "type": "uint32"}]},
                "primaryType": "Message", "domain": {},
                "message": {"value": 1},
            },
        }
        self.reference = gen.reference(self.entry["doc"])

    def check_result(self, ethers, entry=None):
        result = subprocess.CompletedProcess(
            [], 0, stdout=json.dumps([
                {"sigutil": self.reference, "ethers": ethers}]).encode())
        with patch.object(gen.subprocess, "run", return_value=result), \
                contextlib.redirect_stdout(io.StringIO()):
            return gen.crosscheck([entry or self.entry], "node_modules")

    @unittest.skipUnless(shutil.which("node"), "Node is required for path resolution")
    def test_relative_node_modules_path(self):
        # Minimal encoders isolate Node's actual module resolution. The full
        # corpus is separately crosschecked against the real packages.
        ref = json.dumps(self.reference)
        modules = {
            "ethers": "const r = " + ref + "; module.exports = {utils: {"
                      "_TypedDataEncoder: {hashDomain: () => '0x' + r.domain_separator,"
                      "from: () => ({hash: () => '0x' + r.message_hash}),"
                      "hash: () => '0x' + r.digest}}};",
            "@metamask/eth-sig-util": "const r = " + ref + "; module.exports = {"
                      "SignTypedDataVersion: {V4: 'V4'}, TypedDataUtils: {"
                      "hashStruct: (t) => Buffer.from(t === 'EIP712Domain' ? "
                      "r.domain_separator : r.message_hash, 'hex'),"
                      "eip712Hash: () => Buffer.from(r.digest, 'hex')}};",
        }
        with tempfile.TemporaryDirectory() as tmp:
            for name, source in modules.items():
                target = Path(tmp) / "node_modules" / name / "index.js"
                target.parent.mkdir(parents=True)
                target.write_text(source)
            previous = os.getcwd()
            try:
                os.chdir(tmp)
                for relative in ["node_modules", "./node_modules"]:
                    with self.subTest(path=relative), \
                            contextlib.redirect_stdout(io.StringIO()):
                        self.assertTrue(gen.crosscheck([self.entry], relative))
            finally:
                os.chdir(previous)

    def test_unexpected_encoder_error_preserves_both_fixture_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            corpus, inc = Path(tmp) / "corpus.json", Path(tmp) / "corpus.inc"
            corpus.write_text(json.dumps([self.entry]))
            inc.write_text("original compiled fixture\n")
            originals = (corpus.read_bytes(), inc.read_bytes())
            result = subprocess.CompletedProcess([], 0, stdout=json.dumps([
                {"sigutil": self.reference,
                 "ethers": {"error": "encoder API unavailable"}}]).encode())
            with patch.object(gen, "CORPUS", str(corpus)), \
                    patch.object(gen, "INC", str(inc)), \
                    patch.object(gen.sys, "argv", ["generator", "--crosscheck",
                                                   "node_modules"]), \
                    patch.object(gen.subprocess, "run", return_value=result), \
                    contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    gen.main()
            self.assertEqual(originals, (corpus.read_bytes(), inc.read_bytes()))

    def test_only_named_exact_refusals_are_allowed(self):
        for name, expected in gen.EXPECTED_ETHERS_REFUSALS.items():
            with self.subTest(document=name):
                entry = dict(self.entry, id=name)
                refusal = dict(expected, error="expected validation refusal")
                self.assertTrue(self.check_result(refusal, entry))
                self.assertFalse(self.check_result(refusal))
                self.assertFalse(self.check_result(
                    {"error": "encoder API unavailable"}, entry))
                changed = dict(refusal, reason="unexpected validation failure")
                self.assertFalse(self.check_result(changed, entry))

    def test_missing_encoder_results_are_rejected(self):
        result = subprocess.CompletedProcess([], 0, stdout=b"[]")
        with patch.object(gen.subprocess, "run", return_value=result), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(gen.crosscheck([self.entry], "node_modules"))


if __name__ == "__main__":
    unittest.main()
