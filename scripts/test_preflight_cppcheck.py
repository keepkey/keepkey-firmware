"""Verify the shared analyzer's argv, package checks and failure propagation."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CppcheckInvocation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'scripts').mkdir()
        for name in ('cppcheck.sh', 'cppcheck-version'):
            shutil.copy2(ROOT / 'scripts' / name, self.root / 'scripts' / name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                        CPPCHECK_ARGV=str(self.root / 'argv.json'))
        self.stub('dpkg-query', '#!/bin/sh\nprintf %s "${TEST_PACKAGE_VERSION:-2.13.0-2ubuntu3}"\n')
        self.stub('cppcheck', '''#!/usr/bin/env python3
import json, os, sys
if sys.argv[1:] == ['--version']:
    print(os.environ.get('TEST_EXECUTABLE_VERSION', 'Cppcheck 2.13.0'))
else:
    with open(os.environ['CPPCHECK_ARGV'], 'w') as f:
        json.dump(sys.argv[1:], f)
    sys.exit(int(os.environ.get('TEST_ANALYZER_EXIT', '0')))
''')

    def stub(self, name, body):
        p = self.bin / name
        p.write_text(body)
        p.chmod(0o755)

    def run_analyzer(self, *args):
        return subprocess.run(['sh', 'scripts/cppcheck.sh', *args], cwd=self.root,
                              env=self.env, capture_output=True, text=True)

    def test_exact_arguments_and_literal_output_path(self):
        output = 'report with spaces $(touch SHOULD_NOT_EXIST).txt'
        result = self.run_analyzer(output)
        self.assertEqual(0, result.returncode, result.stderr)
        args = json.loads((self.root / 'argv.json').read_text())
        self.assertEqual('-j', args[0])
        self.assertGreater(int(args[1]), 0)
        self.assertEqual([
            '--cppcheck-build-dir=.cppcheck-build',
            '--enable=warning,style,performance,portability',
            '--std=c11', '--platform=unspecified', '--inconclusive', '--force', '--inline-suppr',
            '--suppressions-list=.cppcheck-suppressions',
            '-I', 'include', '-I', 'deps/crypto/trezor-firmware/crypto', '-I', 'deps/device-protocol',
            '-DSTM32F2=1', '-DUSE_ETHEREUM=1', '-DUSE_KECCAK=1', '-DUSE_NANO=1',
            '-DPB_FIELD_16BIT=1', '-DEMULATOR=1',
            '--template=::warning file={file},line={line},col={column}::{severity}: {message} [{id}]',
            '--output-file=' + output, '--error-exitcode=1',
            'lib/', 'include/keepkey/', 'tools/',
        ], args[2:])
        self.assertFalse((self.root / 'SHOULD_NOT_EXIST').exists())

    def test_stale_package_is_rejected_before_analysis(self):
        self.env['TEST_PACKAGE_VERSION'] = '2.12.0-1'
        result = self.run_analyzer('report.txt')
        self.assertNotEqual(0, result.returncode)
        self.assertIn('package mismatch', result.stderr)
        self.assertFalse((self.root / 'argv.json').exists())

    def test_shadowed_executable_is_rejected_before_analysis(self):
        self.env['TEST_EXECUTABLE_VERSION'] = 'Cppcheck 2.12.0'
        result = self.run_analyzer('report.txt')
        self.assertNotEqual(0, result.returncode)
        self.assertIn('executable mismatch', result.stderr)
        self.assertFalse((self.root / 'argv.json').exists())

    def test_analyzer_failure_is_preserved(self):
        self.env['TEST_ANALYZER_EXIT'] = '7'
        self.assertEqual(7, self.run_analyzer('report.txt').returncode)

    def test_missing_or_extra_output_arguments_are_rejected(self):
        for args in ((), ('a', 'b')):
            self.assertEqual(2, self.run_analyzer(*args).returncode)
        self.assertFalse((self.root / 'argv.json').exists())


if __name__ == '__main__':
    unittest.main()
