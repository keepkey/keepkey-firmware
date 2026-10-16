"""Regression tests for fixture generation's independent-encoder gate."""
import contextlib
import hashlib
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
        self.entry["expected"] = self.reference

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
                    patch.object(gen.sys, "argv", ["generator", "--crosscheck",
                                                   "node_modules", "--output",
                                                   str(inc)]), \
                    patch.object(gen.subprocess, "run", return_value=result), \
                    contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    gen.main()
            self.assertEqual(originals, (corpus.read_bytes(), inc.read_bytes()))

    def test_emit_retains_pinned_hashes_without_recomputing_or_writing_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            corpus, inc = Path(tmp) / "corpus.json", Path(tmp) / "corpus.inc"
            corpus.write_text(json.dumps([self.entry]))
            original = corpus.read_bytes()
            expected = gen.emit([self.entry])
            with patch.object(gen, "CORPUS", str(corpus)), \
                    patch.object(gen.sys, "argv", ["generator", "--output", str(inc)]), \
                    patch.object(gen, "reference", side_effect=AssertionError), \
                    patch.object(gen.subprocess, "run", side_effect=AssertionError), \
                    contextlib.redirect_stdout(io.StringIO()):
                gen.main()
            self.assertEqual(corpus.read_bytes(), original)
            self.assertEqual(inc.read_text(), expected)

    def test_invalid_value_does_not_replace_existing_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            corpus, inc = Path(tmp) / "corpus.json", Path(tmp) / "corpus.inc"
            self.entry["doc"]["message"]["value"] = 1 << 32
            corpus.write_text(json.dumps([self.entry]))
            inc.write_text("previous fixture\n")
            original = corpus.read_bytes()
            with patch.object(gen, "CORPUS", str(corpus)), \
                    patch.object(gen.sys, "argv", ["generator", "--output", str(inc)]):
                with self.assertRaises(AssertionError):
                    gen.main()
            self.assertEqual(corpus.read_bytes(), original)
            self.assertEqual(inc.read_text(), "previous fixture\n")

    def test_output_must_not_alias_input_corpus(self):
        with tempfile.TemporaryDirectory() as tmp:
            corpus = Path(tmp) / "corpus.json"
            corpus.write_text(json.dumps([self.entry]))
            original = corpus.read_bytes()
            alias = Path(tmp) / "alias.json"
            alias.symlink_to(corpus)
            for output in (corpus, alias):
                with self.subTest(output=output.name), \
                        patch.object(gen, "CORPUS", str(corpus)), \
                        patch.object(gen.sys, "argv", ["generator", "--output", str(output)]), \
                        contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as error:
                        gen.main()
                    self.assertEqual(error.exception.code, 2)
                self.assertEqual(corpus.read_bytes(), original)

    def test_pinned_corpus_matches_the_reviewed_native_fixture(self):
        # Goldens from B2 8862cb5c6 and python-keepkey 45e2651. Updating the
        # corpus requires deliberately reviewing its expected hashes again.
        raw = Path(gen.CORPUS).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         "cdb76e876da5421ccb8c8c75c235c83da2c033cbb98249c1f12608571ea0fa61")
        corpus = json.loads(raw)
        self.assertEqual(len(corpus), 61)
        self.assertEqual(len({entry["id"] for entry in corpus}), 61)
        self.assertEqual(hashlib.sha256(gen.emit(corpus).encode()).hexdigest(),
                         "b15eae2c6fc002690c9046e8043821e266b9cbc28e701fdb48d19910efeedddf")
        for entry in corpus:
            with self.subTest(document=entry["id"]):
                self.assertEqual(entry["expected"], gen.reference(entry["doc"]))

    def test_crosscheck_rejects_changed_pinned_hashes(self):
        self.entry["expected"] = dict(self.reference, message_hash="00" * 32)
        self.assertFalse(self.check_result(self.reference))

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
