#!/usr/bin/env python3
"""Build fail-closed, self-binding 7.14.2 presign evidence."""

import datetime
import glob
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
REPORT_GENERATOR = (
    ROOT / "deps" / "python-keepkey" / "scripts" /
    "generate-test-report.py"
)
REPORT_DIR = ROOT / "test-report"
REPORT_PDF = REPORT_DIR / "test-report.pdf"
MERGED_JUNIT = REPORT_DIR / "junit-merged.xml"

REQUIRED_CASES = {
    "Ethereum.TransferAmountUsesTheRequestsSigningChain",
    "Osmosis.RequiredValuesRejectEmptyAndNonDecimalAmounts",
    "test_msg_ethereum_signtx_xfer.TestMsgEthereumSigntx."
    "test_transfer_review_uses_signing_chain_asset",
    "test_msg_osmosis_validation.TestOsmosisValidation."
    "test_present_but_empty_amount_is_rejected_before_review",
    "test_msg_osmosis_validation.TestOsmosisValidation."
    "test_ibc_omitted_amount_and_receiver_are_rejected_before_review",
    "test_msg_recoverydevice_cipher.TestDeviceRecovery."
    "test_unknown_word_count_failure_aborts_recovery",
}


def fail(message):
    raise RuntimeError(message)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git(*args):
    return subprocess.check_output(
        ["git"] + list(args), cwd=str(ROOT), text=True).strip()


def case_status(testcase):
    if testcase.find("failure") is not None:
        return "fail"
    if testcase.find("error") is not None:
        return "error"
    if testcase.find("skipped") is not None:
        return "skip"
    return "pass"


def merge_junit(paths):
    root = ET.Element("testsuites")
    cases = []
    inputs = []
    for path in paths:
        try:
            parsed = ET.parse(path)
        except ET.ParseError as exc:
            fail("malformed JUnit %s: %s" % (path, exc))
        source_root = parsed.getroot()
        suites = list(source_root.iter("testsuite"))
        if not suites:
            fail("JUnit contains no suites: %s" % path)
        if source_root.tag == "testsuite":
            root.append(source_root)
        else:
            for suite in source_root.findall("testsuite"):
                root.append(suite)
        for testcase in source_root.iter("testcase"):
            status = case_status(testcase)
            skipped = testcase.find("skipped")
            cases.append({
                "classname": testcase.get("classname", ""),
                "name": testcase.get("name", ""),
                "status": status,
                "skip_reason": (
                    skipped.get("message", "") if skipped is not None else ""
                ),
            })
        inputs.append({
            "path": str(path.relative_to(ROOT)),
            "sha256": sha256_file(path),
        })
    ET.ElementTree(root).write(
        MERGED_JUNIT, xml_declaration=True, encoding="unicode")
    return cases, inputs


def canonical_case_name(case):
    return "%s.%s" % (case["classname"], case["name"])


def validate_cases(cases):
    failures = [case for case in cases
                if case["status"] in ("fail", "error")]
    if failures:
        fail("authoritative JUnit has %d failure/error case(s)" % len(failures))
    passed = {canonical_case_name(case) for case in cases
              if case["status"] == "pass"}
    missing = sorted(required for required in REQUIRED_CASES
                     if not any(name.endswith(required) for name in passed))
    if missing:
        fail("required 7.14.2 controls missing or not passing: %s" %
             ", ".join(missing))


def validate_screenshots(screenshot_root):
    pngs = sorted(screenshot_root.rglob("*.png"))
    if not pngs:
        fail("no OLED PNGs were retained")
    sequences = []
    for manifest_path in sorted(screenshot_root.rglob("frames.json")):
        with open(manifest_path, "r", encoding="utf-8") as handle:
            manifest = json.load(handle)
        directory = manifest_path.parent
        expected = manifest.get("frames", [])
        actual_pngs = sorted(directory.glob("btn*.png"))
        if manifest.get("frame_count") != len(expected):
            fail("frame_count mismatch: %s" % manifest_path)
        if [item.get("file") for item in expected] != [p.name for p in actual_pngs]:
            fail("frame list mismatch: %s" % manifest_path)
        for item, png in zip(expected, actual_pngs):
            if item.get("sha256") != sha256_file(png):
                fail("frame hash mismatch: %s" % png)
        sequences.append({
            "path": str(directory.relative_to(ROOT)),
            "manifest_sha256": sha256_file(manifest_path),
            "frame_count": len(actual_pngs),
        })
    if not sequences:
        fail("OLED frames have no completeness manifests")
    manifested = sum(item["frame_count"] for item in sequences)
    if manifested != len(pngs):
        fail("%d OLED PNGs exist but manifests account for %d" %
             (len(pngs), manifested))
    return pngs, sequences


def validate_arm_manifest(arm_dir, firmware_sha, python_sha):
    manifest_path = arm_dir / "arm-build-manifest.json"
    if not manifest_path.is_file():
        fail("ARM build manifest is missing")
    with open(manifest_path, "r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    if manifest.get("firmware_sha") != firmware_sha:
        fail("ARM manifest firmware SHA does not match checkout")
    if manifest.get("python_sha") != python_sha:
        fail("ARM manifest Python SHA does not match gitlink")
    files = manifest.get("files", [])
    if not files:
        fail("ARM manifest contains no binaries")
    for item in files:
        path = arm_dir / item.get("name", "")
        if not path.is_file() or sha256_file(path) != item.get("sha256"):
            fail("ARM artifact hash mismatch: %s" % path)
    return manifest_path, manifest


def main():
    if not REPORT_GENERATOR.is_file():
        fail("report generator submodule is not initialized")

    firmware_sha = git("rev-parse", "HEAD")
    python_sha = git("rev-parse", "HEAD:deps/python-keepkey")
    expected_firmware = os.environ.get("KK_FIRMWARE_SHA", firmware_sha)
    expected_python = os.environ.get("KK_PYTHON_SHA", python_sha)
    if expected_firmware != firmware_sha or expected_python != python_sha:
        fail("workflow metadata does not match checked-out source")

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    junit_paths = [ROOT / "test-reports" / "python-keepkey" / "junit.xml"]
    junit_paths += [Path(path) for path in sorted(glob.glob(
        str(ROOT / "test-reports" / "firmware-unit" / "*.xml")))]
    junit_paths.append(ROOT / "test-reports" / "dylib-junit.xml")
    missing_junit = [str(path) for path in junit_paths if not path.is_file()]
    if missing_junit:
        fail("required JUnit inputs missing: %s" % ", ".join(missing_junit))

    cases, junit_inputs = merge_junit(junit_paths)
    validate_cases(cases)

    screenshot_root = ROOT / "test-reports" / "screenshots"
    pngs, sequences = validate_screenshots(screenshot_root)

    arm_dir = ROOT / "test-reports" / "arm"
    arm_manifest_path, arm_manifest = validate_arm_manifest(
        arm_dir, firmware_sha, python_sha)

    wrapper_hash = sha256_file(Path(__file__))
    renderer_hash = sha256_file(REPORT_GENERATOR)
    generator_hash = hashlib.sha256(
        (wrapper_hash + renderer_hash).encode("ascii")).hexdigest()
    arm_manifest_hash = sha256_file(arm_manifest_path)
    run_url = os.environ.get("KK_RUN_URL", "")
    fw_version = os.environ.get("FW_VERSION", "")
    if not fw_version:
        fail("FW_VERSION is required")

    screenshot_junit = (
        ROOT / "test-reports" / "python-keepkey" /
        "junit-screenshots.xml")
    if not screenshot_junit.is_file():
        fail("screenshot-selection JUnit is missing")
    subprocess.run([
        sys.executable, str(REPORT_GENERATOR),
        "--screenshot-audit=%s" % screenshot_root,
        "--audit-junit=%s" % screenshot_junit,
        "--fw-version=%s" % fw_version,
    ], cwd=str(ROOT), check=True)

    subprocess.run([
        sys.executable, str(REPORT_GENERATOR),
        "--validate-junit",
        "--junit=%s" % MERGED_JUNIT,
        "--fw-version=%s" % fw_version,
    ], cwd=str(ROOT), check=True)

    subprocess.run([
        sys.executable, str(REPORT_GENERATOR),
        "--output=%s" % REPORT_PDF,
        "--junit=%s" % MERGED_JUNIT,
        "--screenshots=%s" % screenshot_root,
        "--fw-version=%s" % fw_version,
        "--firmware-sha=%s" % firmware_sha,
        "--python-sha=%s" % python_sha,
        "--run-url=%s" % run_url,
        "--generator-sha256=%s" % generator_hash,
        "--arm-manifest-sha256=%s" % arm_manifest_hash,
    ], cwd=str(ROOT), check=True)
    if not REPORT_PDF.is_file() or REPORT_PDF.stat().st_size == 0:
        fail("report PDF was not created")

    counts = {
        status: sum(1 for case in cases if case["status"] == status)
        for status in ("pass", "skip", "fail", "error")
    }
    counts["total"] = len(cases)
    generated_at = datetime.datetime.now(
        datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    evidence = {
        "schema": 1,
        "generated_at": generated_at,
        "firmware_sha": firmware_sha,
        "python_sha": python_sha,
        "firmware_pr": os.environ.get("KK_FIRMWARE_PR", ""),
        "python_pr": os.environ.get("KK_PYTHON_PR", ""),
        "run_url": run_url,
        "workflow_event": os.environ.get("KK_WORKFLOW_EVENT", ""),
        "generators": {
            "combined_sha256": generator_hash,
            "wrapper_sha256": wrapper_hash,
            "renderer_sha256": renderer_hash,
        },
        "junit": {
            "counts": counts,
            "inputs": junit_inputs,
            "merged_sha256": sha256_file(MERGED_JUNIT),
            "skips": [case for case in cases if case["status"] == "skip"],
        },
        "oled": {
            "frame_count": len(pngs),
            "selection_junit_sha256": sha256_file(screenshot_junit),
            "frames": [{
                "path": str(path.relative_to(ROOT)),
                "sha256": sha256_file(path),
            } for path in pngs],
            "sequences": sequences,
        },
        "arm": {
            "manifest_sha256": arm_manifest_hash,
            "files": arm_manifest["files"],
        },
        "pdf": {
            "path": REPORT_PDF.name,
            "sha256": sha256_file(REPORT_PDF),
        },
    }
    manifest_path = REPORT_DIR / "test-report-manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as handle:
        json.dump(evidence, handle, sort_keys=True, indent=2)
        handle.write("\n")
    with open(REPORT_DIR / "test-report.pdf.sha256", "w",
              encoding="ascii") as handle:
        handle.write("%s  test-report.pdf\n" % evidence["pdf"]["sha256"])

    print("presign evidence: %d tests, %d OLED frames, PDF %s" %
          (counts["total"], len(pngs), evidence["pdf"]["sha256"]))


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        sys.exit(1)
