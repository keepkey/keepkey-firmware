#!/usr/bin/env python3
"""Exercise the gate's real blob reads in a disposable git repository."""
import ast
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class BlobReadTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git('init', '-q')
        (self.root / 'fixture').write_text('audit evidence\n')
        self.git('add', 'fixture')
        self.git('-c', 'user.name=Audit Test', '-c', 'user.email=audit@example.invalid',
                 'commit', '-qm', 'fixture')
        # Import the actual functions without running the historical merge
        # audit at module scope or substituting this repository's revisions.
        source = Path(__file__).with_name('merge_direction_gate.py')
        tree = ast.parse(source.read_text(), filename=str(source))
        tree.body = [node for node in tree.body
                     if isinstance(node, ast.FunctionDef) and node.name in ('sh', 'blob')]
        namespace = {'ROOT': str(self.root), 'subprocess': subprocess, 'sys': sys}
        exec(compile(tree, str(source), 'exec'), namespace)
        self.blob = namespace['blob']

    def git(self, *args):
        return subprocess.check_output(('git', '-C', str(self.root), *args), text=True).strip()

    def test_present_file_is_read(self):
        self.assertEqual('audit evidence\n', self.blob('HEAD', 'fixture'))

    def test_deleted_path_is_absent(self):
        self.assertIsNone(self.blob('HEAD', 'deleted'))

    def test_missing_blob_object_aborts(self):
        oid = self.git('rev-parse', 'HEAD:fixture')
        (self.root / '.git' / 'objects' / oid[:2] / oid[2:]).unlink()
        with self.assertRaisesRegex(SystemExit, 'FATAL: git show'):
            self.blob('HEAD', 'fixture')

    def test_invalid_revision_aborts(self):
        with self.assertRaisesRegex(SystemExit, 'FATAL: git ls-tree'):
            self.blob('missing-revision', 'fixture')


if __name__ == '__main__':
    unittest.main()
