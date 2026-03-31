#!/usr/bin/env python3
"""
CI trigger for test report generation.

The actual report generator lives in deps/python-keepkey/scripts/generate-test-report.py
(stdlib-only PDF writer with SECTIONS as single source of truth for test catalog,
screenshot filter, and report layout).

This script finds the JUnit XML + screenshots from CI artifacts and calls through.
"""
import os
import sys
import glob
import subprocess

REPORT_GENERATOR = os.path.join(
    os.path.dirname(__file__), '..', 'deps', 'python-keepkey', 'scripts', 'generate-test-report.py'
)

def main():
    if not os.path.exists(REPORT_GENERATOR):
        print("ERROR: %s not found — is the python-keepkey submodule initialized?" % REPORT_GENERATOR,
              file=sys.stderr)
        sys.exit(1)

    # Collect JUnit XMLs from CI artifacts
    junit_files = (
        glob.glob('test-reports/python-keepkey/junit*.xml') +
        glob.glob('test-reports/firmware-unit/*.xml')
    )

    # Merge multiple JUnit XMLs into one for the report generator
    merged = 'test-reports/junit-merged.xml'
    if junit_files:
        import xml.etree.ElementTree as ET
        root = ET.Element('testsuites')
        for jf in junit_files:
            try:
                tree = ET.parse(jf)
                for suite in tree.iter('testsuite'):
                    root.append(suite)
            except ET.ParseError:
                print("WARN: skipping malformed %s" % jf, file=sys.stderr)
        ET.ElementTree(root).write(merged, xml_declaration=True, encoding='unicode')
        print("Merged %d JUnit files -> %s" % (len(junit_files), merged))
    else:
        print("WARN: no JUnit XML files found", file=sys.stderr)
        merged = None

    # Find screenshots directory
    screenshot_dir = 'test-reports/screenshots'
    if not os.path.isdir(screenshot_dir):
        screenshot_dir = None

    # Build command
    cmd = [sys.executable, REPORT_GENERATOR, '--output=test-report.pdf']
    if merged:
        cmd.append('--junit=%s' % merged)
    if screenshot_dir:
        cmd.append('--screenshots=%s' % screenshot_dir)
    fw_version = os.environ.get('FW_VERSION')
    if fw_version:
        cmd.append('--fw-version=%s' % fw_version)

    print("Running: %s" % ' '.join(cmd))
    result = subprocess.run(cmd)

    # Don't exit non-zero -- let the report be uploaded even with partial results
    if result.returncode != 0:
        print("WARN: report generator exited %d" % result.returncode, file=sys.stderr)

    if os.path.exists('test-report.pdf'):
        size = os.path.getsize('test-report.pdf')
        print("Generated test-report.pdf (%d bytes)" % size)
    else:
        print("ERROR: test-report.pdf not created", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
