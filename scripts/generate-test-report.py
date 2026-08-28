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
import hashlib
import json
import subprocess
from pathlib import Path

REPORT_GENERATOR = os.path.join(
    os.path.dirname(__file__), '..', 'deps', 'python-keepkey', 'scripts', 'generate-test-report.py'
)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def validate_arm_manifests(arm_dir, firmware_sha, python_sha):
    required = {'full', 'bitcoin-only'}
    found = set()
    for manifest_path in sorted(arm_dir.glob('*/arm-build-manifest.json')):
        artifact = manifest_path.parent.name
        matches = [variant for variant in required
                   if artifact.endswith('-' + variant)]
        if len(matches) != 1:
            raise RuntimeError('unrecognized ARM artifact directory: %s' % artifact)
        variant = matches[0]
        if variant in found:
            raise RuntimeError('duplicate ARM manifest for %s' % variant)
        with open(manifest_path, encoding='utf-8') as handle:
            manifest = json.load(handle)
        if manifest.get('variant') != variant:
            raise RuntimeError('ARM manifest variant mismatch: %s' % artifact)
        if manifest.get('firmware_sha') != firmware_sha:
            raise RuntimeError('ARM manifest firmware SHA mismatch: %s' % artifact)
        if manifest.get('python_sha') != python_sha:
            raise RuntimeError('ARM manifest Python SHA mismatch: %s' % artifact)
        files = manifest.get('files', [])
        if not files:
            raise RuntimeError('ARM manifest contains no binaries: %s' % artifact)
        for item in files:
            binary = manifest_path.parent / item.get('name', '')
            if (not binary.is_file() or
                    sha256_file(binary) != item.get('sha256')):
                raise RuntimeError('ARM artifact hash mismatch: %s' % binary)
        found.add(variant)
    if found != required:
        raise RuntimeError('expected full and bitcoin-only ARM manifests, found: %s' %
                           ', '.join(sorted(found)))
    print('Validated full and bitcoin-only ARM artifact manifests')

def main():
    if not os.path.exists(REPORT_GENERATOR):
        print("ERROR: %s not found — is the python-keepkey submodule initialized?" % REPORT_GENERATOR,
              file=sys.stderr)
        sys.exit(1)

    firmware_sha = subprocess.check_output(
        ['git', 'rev-parse', 'HEAD'], text=True).strip()
    python_sha = subprocess.check_output(
        ['git', 'rev-parse', 'HEAD:deps/python-keepkey'], text=True).strip()
    try:
        validate_arm_manifests(Path('test-reports/arm'), firmware_sha, python_sha)
    except (OSError, RuntimeError, ValueError) as exc:
        print('ERROR: %s' % exc, file=sys.stderr)
        sys.exit(1)

    # The release report is evidence, not a best-effort decoration.  The
    # canonical Python JUnit must exist; otherwise rendering an empty catalog
    # produces a dangerously plausible "all pending" PDF.
    python_junit = 'test-reports/python-keepkey/junit.xml'
    if not os.path.isfile(python_junit) or os.path.getsize(python_junit) == 0:
        print("ERROR: required Python JUnit evidence missing: %s" % python_junit,
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

    if result.returncode != 0:
        print("ERROR: report generator exited %d" % result.returncode, file=sys.stderr)
        sys.exit(result.returncode)

    if os.path.exists('test-report.pdf'):
        size = os.path.getsize('test-report.pdf')
        print("Generated test-report.pdf (%d bytes)" % size)
    else:
        print("ERROR: test-report.pdf not created", file=sys.stderr)
        sys.exit(1)

    # Render first so a failed candidate still has a truthful diagnostic PDF,
    # then fail the job if any catalog entry failed or is missing.  Deliberate
    # feature/policy skips remain valid per the report generator contract.
    #
    # Validate against the SAME merged evidence the PDF was rendered from.  It
    # used to validate against the Python JUnit alone, so any catalog entry
    # naming a native firmware unit test resolved to "missing" and the gate
    # could never accept one -- which is half of why no native test was ever
    # catalogued.  The canonical-Python-evidence requirement is already
    # enforced above, before the merge, so nothing is weakened here.
    # Second run of the screenshot audit, on purpose.
    #
    # python-keepkey-tests.sh already runs it inside the emulator container,
    # immediately after capture.  That one answers "did the firmware draw?".
    # This one answers a different question: "does the PDF being shipped have
    # the screens it claims?"  The report is built from a DOWNLOADED artifact,
    # and a partial upload would render a report with declared-but-absent
    # screens that nothing else checks -- the container gate has already
    # passed and gone.
    #
    # Only when the screenshots artifact actually arrived: its download is
    # continue-on-error, and a flaked upload must not be reported as a firmware
    # that stopped drawing.
    if screenshot_dir:
        audit_cmd = [
            sys.executable,
            REPORT_GENERATOR,
            '--screenshot-audit=%s' % screenshot_dir,
            '--audit-junit=%s' % (merged or python_junit),
        ]
        if fw_version:
            audit_cmd.append('--fw-version=%s' % fw_version)
        print("Auditing screens: %s" % ' '.join(audit_cmd))
        audit = subprocess.run(audit_cmd)
        if audit.returncode != 0:
            print("ERROR: declared OLED screens were not captured", file=sys.stderr)
            sys.exit(audit.returncode)
    else:
        print("WARN: no screenshots artifact -- screen audit not run", file=sys.stderr)

    validate_cmd = [
        sys.executable,
        REPORT_GENERATOR,
        '--junit=%s' % (merged or python_junit),
        '--validate-junit',
    ]
    if fw_version:
        validate_cmd.append('--fw-version=%s' % fw_version)
    print("Validating: %s" % ' '.join(validate_cmd))
    validation = subprocess.run(validate_cmd)
    if validation.returncode != 0:
        print("ERROR: report catalog validation failed", file=sys.stderr)
        sys.exit(validation.returncode)


if __name__ == '__main__':
    main()
