"""Public fixture exceptions must not hide credentials in the same files."""

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipUnless(shutil.which("gitleaks"), "gitleaks is required")
class GitleaksAllowlists(unittest.TestCase):
    def scan(self, fixtures):
        config = Path(__file__).resolve().parents[1] / ".gitleaks.toml"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            for name, contents in fixtures.items():
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents)
            report = root / "report.json"
            result = subprocess.run([
                "gitleaks", "detect", "--no-git", "--source", str(source),
                "--config", str(config), "--redact", "--report-format=json",
                "--report-path", str(report)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            findings = json.loads(report.read_text())
            return sorted((str(Path(f["File"]).relative_to(source)),
                           f["StartLine"], f["RuleID"]) for f in findings)

    def test_documented_commit_does_not_exempt_credentials(self):
        credential = "synthetic_" + "39oG97AmQf6SvR8kT2uZhP0cE5jW4xBn"
        commit = "4ce2a07cbce95882f84b3a1aa6e88976af1f6c8b"
        actual = self.scan({
            "docs/release/probe.md": 'python-keepkey: "' + commit +
                                     '"\napi_key: "' + credential + '"\n',
            "outside.md": 'python-keepkey: "' + commit + '"\n',
        })
        self.assertEqual(actual, [
            ("docs/release/probe.md", 2, "generic-api-key"),
            ("outside.md", 1, "generic-api-key"),
        ])


if __name__ == "__main__":
    unittest.main()
