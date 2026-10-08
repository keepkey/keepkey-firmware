"""Exercise the release-evidence gate with complete and corrupted inputs."""

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
import unittest.mock
import xml.etree.ElementTree as ET


SPEC = importlib.util.spec_from_file_location(
    "report", Path(__file__).with_name("generate-test-report.py"))
report = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(report)


class ReleaseCapabilities(unittest.TestCase):
    """A release must not ship with a required capability's controls skipped,
    in either product; a staged block may lack later capabilities."""

    def test_lists_are_known_and_bitcoin_only_is_a_subset(self):
        for lists in report.RELEASE_CAPABILITIES.values():
            self.assertLessEqual(lists["full"], report.KNOWN_CAPABILITIES)
            self.assertLessEqual(lists["bitcoin-only"], lists["full"])

    def test_a_skipped_required_capability_is_a_gap_in_either_product(self):
        for product in ("full", "bitcoin-only"):
            self.assertEqual(
                ["safe-reset-ceremony"],
                report.release_capability_gaps(
                    "7.15.0", product, {"safe-reset-ceremony"}))

    def test_later_release_capabilities_and_full_only_ones_are_not_gaps(self):
        self.assertEqual([], report.release_capability_gaps(
            "7.15.0", "full", {"permit2-review"}))
        self.assertEqual([], report.release_capability_gaps(
            "7.15.0", "bitcoin-only", {"hive-release-review"}))

    def test_a_version_without_a_list_has_no_verdict(self):
        self.assertIsNone(report.release_capability_gaps("9.9.9", "full", set()))


def passed(name):
    classname, method = name.rsplit(".", 1)
    return {"classname": classname, "name": method, "status": "pass",
            "skip_reason": ""}


def census(product):
    return [passed("tests." + report.CENSUS_TEST + c.replace("-", "_"))
            for c in sorted(report.RELEASE_CAPABILITIES["7.15.0"][product])]


class ReleaseControlGaps(unittest.TestCase):
    """A required capability counts only if its census test passed and none of
    its tests skipped on a device flag, which carries no capability prefix."""

    def test_complete_census_has_no_gaps(self):
        for product in ("full", "bitcoin-only"):
            self.assertEqual([], report.release_control_gaps(
                "7.15.0", product, census(product)))

    def test_flag_skip_of_a_required_capability_is_a_gap(self):
        lut = {"classname": "tests.test_msg_solana_lut_attestation.T",
               "name": "test_x", "status": "skip", "skip_reason":
               "Firmware does not report supports_solana_lut_attestation"}
        self.assertEqual(
            ["tests.test_msg_solana_lut_attestation.T.test_x skipped: "
             "supports_solana_lut_attestation"],
            report.release_control_gaps("7.15.0", "full", census("full") + [lut]))
        # Not required of bitcoin-only, so not a gap there.
        self.assertEqual([], report.release_control_gaps(
            "7.15.0", "bitcoin-only", census("bitcoin-only") + [lut]))
        unmapped = dict(lut, skip_reason="Firmware does not report supports_x")
        self.assertEqual(1, len(report.release_control_gaps(
            "7.15.0", "bitcoin-only", census("bitcoin-only") + [unmapped])))

    def test_a_missing_or_duplicated_census_is_a_gap(self):
        cases = census("bitcoin-only")
        self.assertEqual(1, len(report.release_control_gaps(
            "7.15.0", "bitcoin-only", cases[1:])))
        self.assertEqual(1, len(report.release_control_gaps(
            "7.15.0", "bitcoin-only", cases + cases[:1])))

    def test_flag_mapping_names_known_capabilities(self):
        self.assertLessEqual(set(report.SUPPORTS_FLAG_CAPABILITY.values()),
                             report.KNOWN_CAPABILITIES)


class BitcoinOnlyControls(unittest.TestCase):
    """Bitcoin-only must pass the base controls that exist in that product."""

    def test_derivation_drops_only_named_base_cases(self):
        self.assertLessEqual(set(report.BITCOIN_ONLY_EXCLUDED_BASE_CASES),
                             report.BASE_REQUIRED_CASES)
        self.assertEqual(report.BASE_REQUIRED_CASES,
                         report.BITCOIN_ONLY_REQUIRED_CASES |
                         set(report.BITCOIN_ONLY_EXCLUDED_BASE_CASES))
        self.assertIn("DiceCeremonyPrivacy.AbortClearsCanvasBeforeDiagnosticsResume",
                      report.BITCOIN_ONLY_REQUIRED_CASES)

    def test_each_required_case_skipped_missing_or_failed_is_a_gap(self):
        cases = [passed("tests." + n)
                 for n in sorted(report.BITCOIN_ONLY_REQUIRED_CASES)]
        self.assertEqual([], report.bitcoin_only_control_gaps(cases))
        for index in range(len(cases)):
            for status in ("skip", "fail", "remove"):
                altered = [dict(case) for case in cases]
                if status == "remove":
                    del altered[index]
                else:
                    altered[index]["status"] = status
                with self.subTest(case=index, status=status):
                    self.assertTrue(report.bitcoin_only_control_gaps(altered))

    def test_bitcoin_only_merge_keeps_the_full_merged_junit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            full, btc = root / "full.xml", root / "btc.xml"
            for path in (full, btc):
                suite = ET.Element("testsuite")
                ET.SubElement(suite, "testcase",
                              {"classname": path.stem, "name": "t"})
                ET.ElementTree(suite).write(path)
            with unittest.mock.patch.multiple(
                    report, ROOT=root, MERGED_JUNIT=root / "merged.xml",
                    BTC_MERGED_JUNIT=root / "merged-btc.xml"):
                report.merge_junit([full])
                report.merge_junit([btc], report.BTC_MERGED_JUNIT)
            self.assertIn('classname="full"',
                          (root / "merged.xml").read_text())
            self.assertIn('classname="btc"',
                          (root / "merged-btc.xml").read_text())


class ContractEvidence(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.paths = []
        for variant, directory in report.CONTRACT_JUNIT_DIRS.items():
            for filename, variants in report.CONTRACT_JUNIT.items():
                path = self.root / directory / filename
                path.parent.mkdir(parents=True, exist_ok=True)
                suite = ET.Element("testsuite")
                for name, status in variants[variant].items():
                    classname, method = name.rsplit(".", 1)
                    case = ET.SubElement(suite, "testcase", {
                        "classname": classname, "name": method})
                    if status == "skip":
                        ET.SubElement(case, "skipped", {"message": report.CONTRACT_SKIP_REASONS[name]})
                ET.ElementTree(suite).write(path)
                self.paths.append(path)

    def test_complete_variant_contracts_pass(self):
        evidence = report.validate_contract_junit(self.root)
        self.assertEqual(len(self.paths), len(evidence))
        self.assertEqual({"full", "bitcoin-only"},
                         {item["variant"] for item in evidence})

    def test_each_missing_contract_file_is_refused(self):
        for path in self.paths:
            with self.subTest(path=path):
                original = path.read_bytes()
                path.unlink()
                with self.assertRaisesRegex(RuntimeError, "JUnit missing"):
                    report.validate_contract_junit(self.root)
                path.write_bytes(original)

    def test_removed_failed_or_wrong_variant_case_is_refused(self):
        for path in self.paths:
            original = path.read_bytes()
            for mutation in ("remove", "failure", "invert", "duplicate"):
                with self.subTest(path=path, mutation=mutation):
                    tree = ET.parse(path)
                    suite = tree.getroot()
                    case = suite[0]
                    if mutation == "remove":
                        suite.remove(case)
                    elif mutation == "failure":
                        ET.SubElement(case, "failure")
                    elif mutation == "duplicate":
                        suite.append(ET.fromstring(ET.tostring(case)))
                    elif case.find("skipped") is None:
                        ET.SubElement(case, "skipped")
                    else:
                        case.remove(case.find("skipped"))
                    tree.write(path)
                    with self.assertRaises(RuntimeError):
                        report.validate_contract_junit(self.root)
                    path.write_bytes(original)

    def test_a_pass_case_may_skip_only_for_its_own_declared_capability(self):
        path = self.root / report.CONTRACT_JUNIT_DIRS["full"] / "junit-stack12.xml"
        original = path.read_bytes()
        for reason, declared, ok in (
                ("hive-release-review", {"hive-release-review"}, True),
                ("hive-release-review", set(), False),
                ("ripple-memo-policy", {"ripple-memo-policy"}, False),
                ("storage-v19-kdf", {"storage-v19-kdf", "hive-release-review"},
                 False),
                # A bitcoin-only product reason is never full-product evidence.
                ("@Hive signing is unavailable in bitcoin-only firmware",
                 {"hive-release-review"}, False)):
            with self.subTest(reason=reason, declared=declared):
                tree = ET.parse(path)
                ET.SubElement(tree.getroot()[0], "skipped", {
                    "message": reason[1:] if reason.startswith("@") else
                    report.CAPABILITY_SKIP_PREFIX + reason})
                tree.write(path)
                if ok:
                    report.validate_contract_junit(self.root, declared)
                else:
                    with self.assertRaisesRegex(RuntimeError, "contract cases wrong"):
                        report.validate_contract_junit(self.root, declared)
                path.write_bytes(original)

    def test_cases_without_a_capability_can_never_be_waived(self):
        path = (self.root / report.CONTRACT_JUNIT_DIRS["full"] /
                "junit-stack09-integration.xml")
        tree = ET.parse(path)
        ET.SubElement(tree.getroot()[0], "skipped", {
            "message": report.CAPABILITY_SKIP_PREFIX + "erc7730-runtime-review"})
        tree.write(path)
        with self.assertRaisesRegex(RuntimeError, "contract cases wrong"):
            report.validate_contract_junit(self.root, {"erc7730-runtime-review"})

    def test_metadata_absence_is_waived_only_while_declared(self):
        path = (self.root / report.CONTRACT_JUNIT_DIRS["full"] /
                "junit-stack06-contracts.xml")
        tree = ET.parse(path)
        additive = next(case for case in tree.getroot()
                        if "clearsign_additive" in case.get("classname"))
        ET.SubElement(additive, "skipped", {
            "message": "EthereumTxMetadata not supported by this firmware build"})
        tree.write(path)
        report.validate_contract_junit(self.root, {"evm-tx-metadata"})
        with self.assertRaisesRegex(RuntimeError, "contract cases wrong"):
            report.validate_contract_junit(self.root, {"erc7730-runtime-review"})

    def test_every_expected_skip_requires_its_product_reason(self):
        for path in self.paths:
            original = path.read_bytes()
            for index, case in enumerate(ET.parse(path).getroot()):
                if case.find("skipped") is None:
                    continue
                for reason in ("", "unrelated infrastructure failure"):
                    with self.subTest(path=path, case=index, reason=reason):
                        tree = ET.parse(path)
                        tree.getroot()[index].find("skipped").set("message", reason)
                        tree.write(path)
                        with self.assertRaisesRegex(RuntimeError, "contract cases wrong"):
                            report.validate_contract_junit(self.root)
                        path.write_bytes(original)


class NativeContractEvidence(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.paths = {}
        for variant, relative in report.NATIVE_CONTRACT_JUNIT.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            suite = ET.Element("testsuite")
            for name in sorted(report.BLOCK13_NATIVE_CASES[variant]):
                classname, method = name.rsplit(".", 1)
                ET.SubElement(suite, "testcase", {
                    "classname": classname, "name": method, "status": "run"})
            # These survive every corruption: nonempty XML or unrelated green
            # native checks cannot substitute for an owned security contract.
            ET.SubElement(suite, "testcase", {
                "classname": "Unrelated", "name": "StillPasses", "status": "run"})
            ET.ElementTree(suite).write(path)
            self.paths[variant] = path

    def test_complete_product_contracts_pass_and_bind_both_files(self):
        self.assertEqual(55, len(report.BLOCK13_NATIVE_CASES["full"]))
        self.assertEqual(18, len(report.BLOCK13_NATIVE_CASES["bitcoin-only"]))
        evidence = report.validate_native_contract_junit(self.root)
        self.assertEqual({"full", "bitcoin-only"},
                         {item["variant"] for item in evidence})
        for item in evidence:
            path = self.paths[item["variant"]]
            self.assertEqual(str(path.relative_to(self.root)), item["path"])
            self.assertEqual(report.sha256_file(path), item["sha256"])

    def test_a_staged_block_may_omit_only_its_own_native_controls(self):
        path = self.paths["full"]
        original = path.read_bytes()
        osmosis = "Block13OsmosisWire.SendAcceptsCanonicalUint64BoundaryAndZero"
        for mutation, declared, ok in (
                ("remove", {"osmosis-wire-guards"}, True),
                ("remove", set(), False),
                ("remove", {"tendermint-progress"}, False),
                ("failure", {"osmosis-wire-guards"}, False)):
            with self.subTest(mutation=mutation, declared=declared):
                tree = ET.parse(path)
                case = next(c for c in tree.getroot() if "%s.%s" % (
                    c.get("classname"), c.get("name")) == osmosis)
                if mutation == "remove":
                    tree.getroot().remove(case)
                else:
                    ET.SubElement(case, "failure")
                tree.write(path)
                if ok:
                    report.validate_native_contract_junit(self.root, declared)
                else:
                    with self.assertRaises(RuntimeError):
                        report.validate_native_contract_junit(self.root, declared)
                path.write_bytes(original)

    def test_each_missing_native_product_file_is_refused(self):
        for variant, path in self.paths.items():
            original = path.read_bytes()
            with self.subTest(variant=variant):
                path.unlink()
                with self.assertRaisesRegex(RuntimeError, "JUnit missing"):
                    report.validate_native_contract_junit(self.root)
                path.write_bytes(original)

    def test_each_owned_case_must_run_once_and_pass(self):
        for variant, path in self.paths.items():
            original = path.read_bytes()
            owned_count = len(report.BLOCK13_NATIVE_CASES[variant])
            for index in range(owned_count):
                for mutation in ("remove", "skip", "failure", "error",
                                 "duplicate", "notrun", "missing-status"):
                    with self.subTest(variant=variant, case=index,
                                      mutation=mutation):
                        tree = ET.parse(path)
                        suite = tree.getroot()
                        case = suite[index]
                        if mutation == "remove":
                            suite.remove(case)
                        elif mutation == "skip":
                            ET.SubElement(case, "skipped")
                        elif mutation in ("failure", "error"):
                            ET.SubElement(case, mutation)
                        elif mutation == "duplicate":
                            suite.append(ET.fromstring(ET.tostring(case)))
                        elif mutation == "notrun":
                            case.set("status", "notrun")
                        else:
                            case.attrib.pop("status")
                        tree.write(path)
                        self.assertTrue(any(
                            c.get("classname") == "Unrelated"
                            for c in suite))
                        with self.assertRaises(RuntimeError):
                            report.validate_native_contract_junit(self.root)
                        path.write_bytes(original)

    def test_wrong_product_evidence_is_refused(self):
        full = self.paths["full"]
        btc = self.paths["bitcoin-only"]
        full_bytes, btc_bytes = full.read_bytes(), btc.read_bytes()
        full.write_bytes(btc_bytes)
        with self.assertRaisesRegex(RuntimeError, "native contract cases"):
            report.validate_native_contract_junit(self.root)
        full.write_bytes(full_bytes)
        btc.write_bytes(full_bytes)
        with self.assertRaisesRegex(RuntimeError, "full-only cases"):
            report.validate_native_contract_junit(self.root)

    def test_coincident_suffix_cannot_replace_native_identity(self):
        path = self.paths["full"]
        tree = ET.parse(path)
        case = tree.getroot()[0]
        case.set("classname", "Lookalike." + case.get("classname"))
        tree.write(path)
        with self.assertRaisesRegex(RuntimeError, "native contract cases"):
            report.validate_native_contract_junit(self.root)


def skipped(capability):
    return {"status": "skip",
            "skip_reason": report.CAPABILITY_SKIP_PREFIX + capability}


class CapabilitySkips(unittest.TestCase):
    """What a build lacks comes only from the firmware's own capability skips."""

    def test_missing_comes_only_from_capability_skips(self):
        cases = [skipped("evm-max-amount-review"),
                 {"status": "pass", "skip_reason": ""},
                 {"status": "skip", "skip_reason":
                  "Firmware version 7.16.0 or higher is required to run this test"}]
        self.assertEqual({"evm-max-amount-review"},
                         report.release_missing_capabilities(cases))

    def test_environment_cannot_declare_a_capability_missing(self):
        with unittest.mock.patch.dict(
                os.environ,
                {"KK_RELEASE_MISSING_CAPABILITIES": "evm-max-amount-review"}):
            self.assertEqual(set(), report.release_missing_capabilities([]))

    def test_unknown_capability_skip_cannot_shrink_the_gate(self):
        for cases in ([skipped("osmosis-wire-guards extra")],
                      [skipped("")],
                      [skipped("not-a-capability")]):
            with self.assertRaises(RuntimeError):
                report.release_missing_capabilities(cases)

    def test_every_gated_capability_is_known(self):
        named = (set(report.CONTRACT_CAPABILITY.values()) |
                 set(report.NATIVE_CAPABILITY.values()) |
                 {"hive-release-review", "evm-max-amount-review",
                  "ripple-memo-policy", "osmosis-wire-guards"})
        self.assertLessEqual(named, report.KNOWN_CAPABILITIES)


class RequiredCaseMatching(unittest.TestCase):
    REQUIRED = "Ethereum.StructuredEip712IsDisabledForPointRelease"

    def gate(self, passed_name):
        # Only the base set is required when every staged capability is
        # waived, so this exercises the name match alone.
        cases = [{"classname": passed_name.rsplit(".", 1)[0],
                  "name": passed_name.rsplit(".", 1)[1],
                  "status": "pass", "skip_reason": ""}]
        cases += [{"classname": "c", "name": "n", "status": "pass",
                   "skip_reason": ""}]
        original = report.BASE_REQUIRED_CASES
        original_hive = report.HIVE_REQUIRED_CASES
        report.HIVE_REQUIRED_CASES = set()
        report.BASE_REQUIRED_CASES = {self.REQUIRED}
        try:
            with unittest.mock.patch.object(
                    report, "release_missing_capabilities",
                    return_value={"evm-max-amount-review",
                                  "osmosis-wire-guards",
                                  "ripple-memo-policy"}):
                report.validate_cases(cases)
        finally:
            report.BASE_REQUIRED_CASES = original
            report.HIVE_REQUIRED_CASES = original_hive

    def test_exact_and_module_prefixed_names_satisfy(self):
        self.gate(self.REQUIRED)
        self.gate("tests." + self.REQUIRED)

    def test_suffix_coincidence_does_not_satisfy(self):
        with self.assertRaises(RuntimeError):
            self.gate("X" + self.REQUIRED)


class HiveNativeEvidence(unittest.TestCase):
    def test_every_owned_native_identity_is_required(self):
        names = (report.BASE_REQUIRED_CASES | report.HIVE_REQUIRED_CASES |
                 report.RIPPLE_REQUIRED_CASES)
        cases = [{"classname": n.rsplit(".", 1)[0],
                  "name": n.rsplit(".", 1)[1], "status": "pass", "skip_reason": ""}
                 for n in sorted(names)]
        with unittest.mock.patch.object(
                report, "release_missing_capabilities",
                return_value={"evm-max-amount-review", "osmosis-wire-guards"}):
            report.validate_cases(cases)
            for name in report.HIVE_REQUIRED_CASES:
                for status in ("skip", "fail"):
                    altered = [dict(case) for case in cases]
                    for case in altered:
                        if case["classname"] + "." + case["name"] == name:
                            case["status"] = status
                    with self.subTest(name=name, status=status):
                        with self.assertRaises(RuntimeError):
                            report.validate_cases(altered)

    def test_a_duplicated_native_identity_cannot_hide_behind_a_pass(self):
        names = (report.BASE_REQUIRED_CASES | report.HIVE_REQUIRED_CASES |
                 report.RIPPLE_REQUIRED_CASES)
        cases = [{"classname": n.rsplit(".", 1)[0],
                  "name": n.rsplit(".", 1)[1], "status": "pass", "skip_reason": ""}
                 for n in sorted(names)]
        with unittest.mock.patch.object(
                report, "release_missing_capabilities",
                return_value={"evm-max-amount-review", "osmosis-wire-guards"}):
            report.validate_cases(cases)
            for name in sorted(report.HIVE_REQUIRED_CASES):
                for extra_status in ("pass", "skip"):
                    duplicate = dict(next(
                        case for case in cases
                        if case["classname"] + "." + case["name"] == name))
                    duplicate["status"] = extra_status
                    with self.subTest(name=name, extra=extra_status):
                        with self.assertRaises(RuntimeError):
                            report.validate_cases(cases + [duplicate])


if __name__ == "__main__":
    unittest.main()
