#!/usr/bin/env python3
"""Build fail-closed, self-binding 7.14.2 presign evidence."""

import datetime
import glob
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
REPORT_GENERATOR = (
    ROOT / "deps" / "python-keepkey" / "scripts" /
    "generate-test-report.py"
)
REPORT_DIR = ROOT / "test-report"
REPORT_PDF = REPORT_DIR / "test-report.pdf"
MERGED_JUNIT = REPORT_DIR / "junit-merged.xml"
BTC_MERGED_JUNIT = REPORT_DIR / "junit-merged-bitcoin-only.xml"

BASE_REQUIRED_CASES = {
    "DiceCeremonyPrivacy.Mixed128DerivationAndDevicePagesUseIndependentFixture",
    "DiceCeremonyPrivacy.Mixed256DerivationAndDevicePagesUseIndependentFixture",
    "DiceCeremonyPrivacy.Only128DerivationAndDevicePagesUseIndependentFixture",
    "DiceCeremonyPrivacy.Only256DerivationAndDevicePagesUseIndependentFixture",
    "DiceCeremonyPrivacy.AbortAtEveryPhaseWipesAndAllowsOrdinaryRestart",
    "DiceCeremonyPrivacy.AbortClearsCanvasBeforeDiagnosticsResume",
    "test_msg_resetdevice.TestDeviceReset.test_reset_device_dice_mixed_is_verifiable",
    "test_msg_resetdevice.TestDeviceReset.test_reset_device_dice_only_is_verifiable",
    "test_p02_transport.TestP02Transport.test_mixed_entropy_pages_remain_private_and_cancel_clears_state",
    "Ethereum.StructuredEip712IsDisabledForPointRelease",
    "Recovery.DeleteKeepsTypedCipherCharactersNotTheCurrentMapping",
    "Storage.LegacyLanguageIsBoundedAndTerminated",
    "Storage.TruncatedLegacyCacheDoesNotMutateDestination",
    "EmulatorLifecycle.OverflowPreservesUnreadFramesAndRetriesDroppedFrame",
    "EmulatorLifecycle.ConcurrentCaptureNeverTearsOrReordersUnreadSlots",
    "EmulatorLifecycle.ShutdownStopsPollThreadAndAllowsRestart",
    "EmulatorLifecycle.ShutdownWakesConfirmationWaitingForHostDecision",
    "ReviewHandlers.ResetCancellationClearsScratchBeforeAndAfterFormatting",
    "ReviewHandlers.ResetWithoutBackupCommitsAndClearsScratch",
    "ReviewHandlers.ResetBackupCommitsAllStrengthsAndClearsScratch",
    "SetupCeremony.AbortScrubsEveryByteOfSharedMnemonicDisplayScratch",
    "test_msg_recoverydevice_cipher.TestDeviceRecovery."
    "test_unknown_word_count_failure_aborts_recovery",
}

# Bitcoin-only must pass the base controls too. Its set is BASE_REQUIRED_CASES
# minus the cases below, each absent from that product by design; the chain
# sets (RIPPLE/EVM/OSMOSIS/HIVE) are full-only and never apply to it.
BITCOIN_ONLY_EXCLUDED_BASE_CASES = dict(
    [("Ethereum.StructuredEip712IsDisabledForPointRelease",
      "Ethereum is compiled out of bitcoin-only; the native case does not exist")] +
    [("EmulatorLifecycle." + name,
      "emulator harness, run once by python-dylib-tests on the full build")
     for name in (
         "OverflowPreservesUnreadFramesAndRetriesDroppedFrame",
         "ConcurrentCaptureNeverTearsOrReordersUnreadSlots",
         "ShutdownStopsPollThreadAndAllowsRestart",
         "ShutdownWakesConfirmationWaitingForHostDecision")])
BITCOIN_ONLY_REQUIRED_CASES = (
    BASE_REQUIRED_CASES - set(BITCOIN_ONLY_EXCLUDED_BASE_CASES))

RIPPLE_REQUIRED_CASES = {"Ripple.TruncatedBufferFailsWithoutWritingPastEnd"}

EVM_REQUIRED_CASES = {
    "Ethereum.TransferAmountUsesTheRequestsSigningChain",
    "test_msg_ethereum_signtx_xfer.TestMsgEthereumSigntx."
    "test_transfer_review_uses_signing_chain_asset",
}

OSMOSIS_REQUIRED_CASES = {
    "Osmosis.RequiredValuesRejectEmptyAndNonDecimalAmounts",
    "test_msg_osmosis_validation.TestOsmosisValidation."
    "test_present_but_empty_amount_is_rejected_as_invalid",
    "test_msg_osmosis_validation.TestOsmosisValidation."
    "test_ibc_omitted_amount_and_receiver_are_rejected_before_review",
}

OSMOSIS_LEGACY_REQUIRED_CASES = {
    "Osmosis.RequiredValuesRejectEmptyAndNonDecimalAmounts",
    "test_msg_osmosis_validation.TestOsmosisValidation."
    "test_present_but_empty_amount_is_rejected_before_review",
    "test_msg_osmosis_validation.TestOsmosisValidation."
    "test_ibc_omitted_amount_and_receiver_are_rejected_before_review",
}

_STACK07 = "test_stack07_regressions."
_STACK07_COINTABLE = (
    _STACK07 + "TestStack07CoinTableReuse."
    "test_cointable_response_reuses_decoded_request_without_truncation")
_STACK07_EVM = [_STACK07 + "TestStack07Regressions." + name for name in (
    "test_advanced_mode_off_refuses_preload",
    "test_all_typed_fields_are_reviewed_and_signature_is_unchanged",
    "test_calldata_signing_replay_change_is_refused",
    "test_calldata_signing_replay_succeeds_with_arguments",
    "test_certified_approval_refused_before_annotation_screens",
    "test_declining_source_intent_or_either_field_aborts",
    "test_domain_name_version_and_salt_mismatches_are_refused",
    "test_early_typed_failure_clears_preload",
    "test_empty_message_requires_explicit_consent",
    "test_failed_certified_domain_clears_preload",
    "test_intent_only_typed_definition_still_requires_source_and_intent",
    "test_selector_only_call_signs_after_certified_intent",
    "test_tampered_envelope_signature_is_refused_at_preload",
    "test_typed_replay_change_is_refused",
    "test_unknown_signer_is_refused_at_preload",
    "test_verifying_contract_mismatch_is_refused_before_certified_review",
    "test_domain_only_signature_refuses_certified_preload",
    "test_dirty_approval_spender_word_is_refused_before_any_screen",
    "test_preload_survives_get_features_and_is_discarded_by_initialize",
    "test_non_ascii_intent_is_escaped_not_drawn_as_glyphs",
)]
_ADDITIVE = [
    "test_msg_ethereum_clearsign_additive.TestClearSignAdditiveInvariant." + name
    for name in (
        "test_failed_signature_falls_back_to_the_unverified_review",
        "test_no_runtime_slot_can_reach_the_suppression_branch",
        "test_no_slot_verifies_without_a_runtime_load",
        "test_successful_decode_still_runs_the_raw_review",
        "test_v2_schema_decode_still_runs_the_raw_review",
    )]
_SESSION = "test_msg_session_trust_lifetime.TestSessionTrustLifetime."
_SESSION_BOTH = [_SESSION + "test_advanced_mode_survives_initialize_but_not_clear_session"]
_SESSION_FULL = [_SESSION + name for name in (
    "test_disabling_advanced_mode_revokes_the_signer",
    "test_signer_dropped_by_clear_session",
    "test_signer_dropped_by_initialize",
)]
_RIPPLE = [
    "test_msg_ripple_sign_tx.TestMsgRippleSignTx." + name for name in (
        "test_memo_length_prefix_boundaries",
        "test_ripple_sign_invalid_fee",
        "test_sign",
        "test_sign_with_thorchain_memo",
    )]
_STACK09_SLOT = (
    "test_stack09_integration.TestAuthenticatorSlotIntegration."
    "test_account_slot_text_cannot_wrap_or_ignore_suffixes")
_STACK10_EVM = [
    "test_stack10_regressions.TestStack10Disclosure." + name for name in (
        "test_cancel_every_disclosure_page_then_retry",
        "test_contract_substitution_changes_review_and_signature",
        "test_exact_raw_values_contract_and_counterparty",
        "test_noncanonical_transfers_keep_advanced_raw_fallback",
        "test_padded_zero_value_keeps_exact_token_review",
        "test_transfer_account_keeps_raw_review_and_recipient_binding",
        "test_transfer_account_padded_zero_keeps_contract_review",
        "test_transfer_account_rejects_noncanonical_total_length",
        "test_unlimited_approval_warns_and_raw_signing_requires_advanced_mode",
    )]

_STACK12_HIVE = [
    "test_stack12_regressions.TestStack12Hive." + name for name in (
        "test_account_authorities_ignore_host_keys_and_cancel",
        "test_all_operations_reject_malformed_domains_before_consent",
        "test_complete_memo_and_each_consent_cancellation",
        "test_custom_domain_is_disclosed_and_cancellable",
        "test_invalid_amounts_and_labels_before_consent",
    )]
HIVE_REQUIRED_CASES = {
    "Hive.TransferAssetShownIsAssetSigned",
    "Hive.TransferRejectsUnsupportedAssetsAndUntruncatedPrecision",
    "Hive.AllSigningOperationsRejectMalformedExplicitChainIds",
    "Hive.TransferRejectsInvalidAmountAndAccountLabels",
    "Hive.AccountCreateBytesMatchIndependentGrapheneLayout",
    "Hive.AccountUpdateBytesMatchIndependentGrapheneLayout",
}

# Dedicated contract suites run as separate pytest invocations. Each file and
# each named case is REQUIRED with an exact status per product, so deleting a
# CI step, a test, or a variant leg cannot go unnoticed. Bitcoin-only must
# SKIP the EVM/XRP contracts: a pass there would mean the product exposes them.
_STACK13_ENTROPY = [
    "test_block13_entropy.TestBlock13Entropy." + name for name in (
        "test_byte_budget_clamps_sizes_and_survives_session_changes",
        "test_initialized_locked_device_keeps_confirmation_and_budget",
        "test_missing_required_size_fails_decode_without_spending_budget",
        "test_recovery_refuses_entropy_preserves_cipher_and_budget",
        "test_reset_refuses_entropy_without_consuming_pending_ack",
    )]

CONTRACT_JUNIT = {
    "junit-stack12.xml": {
        "full": dict((case, "pass") for case in _STACK12_HIVE),
        "bitcoin-only": dict((case, "skip") for case in _STACK12_HIVE),
    },
    "junit-stack09-integration.xml": {
        "full": {_STACK09_SLOT: "pass"},
        "bitcoin-only": {_STACK09_SLOT: "pass"},
    },
    "junit-stack10.xml": {
        "full": dict((case, "pass") for case in _STACK10_EVM),
        "bitcoin-only": dict((case, "skip") for case in _STACK10_EVM),
    },
    "junit-stack13.xml": {
        variant: dict((case, "pass") for case in _STACK13_ENTROPY)
        for variant in ("full", "bitcoin-only")
    },
    "junit-stack07.xml": {
        "full": dict([(_STACK07_COINTABLE, "pass")] +
                     [(case, "pass") for case in _STACK07_EVM]),
        "bitcoin-only": dict([(_STACK07_COINTABLE, "pass")] +
                             [(case, "skip") for case in _STACK07_EVM]),
    },
    "junit-stack06-contracts.xml": {
        "full": dict((case, "pass") for case in
                     _ADDITIVE + _SESSION_BOTH + _SESSION_FULL + _RIPPLE),
        "bitcoin-only": dict(
            [(case, "pass") for case in _SESSION_BOTH] +
            [(case, "skip") for case in _ADDITIVE + _SESSION_FULL + _RIPPLE]),
    },
}
CONTRACT_JUNIT_DIRS = {
    "full": Path("test-reports") / "python-keepkey",
    "bitcoin-only": Path("test-reports") / "bitcoin-only" / "python-keepkey",
}

# Native identities are fixed independently of discovery and test counts. A
# nonempty firmware.xml must not certify a build that dropped an owned source
# file, one parameterized chain, or the original empty-character regression.
_BLOCK13_NATIVE_BOTH = {
    "AutoLockProgress.EmptyRecoveryCharacterAbortsWithoutRenewingDeadline",
} | {
    "Block13Confirmation." + name for name in (
        "UnknownAndMalformedTinyPacketsUnwindSigningOnce",
        "DeclineCancelAndInitializeDoNotSignAndAllowRetry",
        "RecoveryRejectionRestoresCipherAndPreservesProgress",
        "RecoveryRedrawDoesNotRenewDeadlineOrResurrectAfterLock",
        "AcceptedRecoveryStartRenewsThenEventuallyExpires",
        "DeclinedRecoveryStartDoesNotRenewDeadline",
        "PollingPreservesVisibleCipherAndAnimationProgress",
    )
} | {
    "Block13Entropy." + name for name in (
        "NewerNormalBandWalletRequiresConsent",
        "NewerBitcoinBandWalletRequiresConsent",
        "PendingResetRejectsWithoutRenewingDeadline",
        "NewerNormalBandRefusesAllWalletCreationUntilWipe",
        "NewerBitcoinBandRefusesAllWalletCreationUntilWipe",
        "ActiveRecoveryRejectsAndPreservesCipherUntilDeadline",
        "MissingSizeFailsDecodeAndZeroDoesNotRenewDeadline",
    )
} | {
    "Block13ResetProgress." + name for name in (
        "InitialRequestRenewsThenPollingExpires",
        "EntropyReplyAdvancesOnceIncludingAbsentAndEmpty",
        "InvalidInitialRequestDoesNotRenew",
    )
}
_BLOCK13_NATIVE_FULL_ONLY = {
    "Block13ResetProgress.GenericTendermintWireSurfaceRemainsUnmapped",
} | {
    "Block13OsmosisWire." + name for name in (
        "SendAcceptsCanonicalUint64BoundaryAndZero",
        "SendRejectsOverflowAndNoncanonicalBeforeReview",
        "MissingAmountAndInvalidDenomFailBeforeReview",
        "SwapAndPoolAmountsRemainWiderThanUint64",
        "NonNativeDenominationsAreNotCappedAtUint64",
        "NativeDenominationStaysCappedForWideAmounts",
    )
} | {
    "Chains/Block13CoinProgress.%s/%s" % (case, chain)
    for case in (
        "AcceptedInitialRequestRenewsDeadline",
        "InvalidInitialRequestCannotRenewDeadline",
        "AcceptedContinuationsDeferThenPollingExpires",
        "EmptyAndInvalidContinuationsAbortWithoutRenewal",
        "DeclinedContinuationCannotRenewAndFreshRetryWorks",
    )
    for chain in (
        "Binance", "Cosmos", "Osmosis", "Thorchain", "Mayachain",
        "TendermintDirectHandler",
    )
}
BLOCK13_NATIVE_CASES = {
    "full": _BLOCK13_NATIVE_BOTH | _BLOCK13_NATIVE_FULL_ONLY,
    "bitcoin-only": _BLOCK13_NATIVE_BOTH,
}
NATIVE_CONTRACT_JUNIT = {
    "full": Path("test-reports") / "firmware-unit" / "firmware.xml",
    "bitcoin-only": (Path("test-reports") / "bitcoin-only" /
                     "firmware-unit" / "firmware.xml"),
}

# These are the actual product guards, not arbitrary reasons for missing tests.
CONTRACT_SKIP_REASONS = dict(
    [(case, "Hive signing is unavailable in bitcoin-only firmware")
     for case in _STACK12_HIVE] +
    [(case, "Stack 10 EVM signing is absent from bitcoin-only")
     for case in _STACK10_EVM] +
    [(case, "Stack 07 EVM contracts are intentionally absent from bitcoin-only")
     for case in _STACK07_EVM] +
    [(case, "EthereumTxMetadata not supported by this firmware build")
     for case in _ADDITIVE] +
    [(case, "Full feature firmware required to run this test")
     for case in _SESSION_FULL + _RIPPLE])

CAPABILITY_SKIP_PREFIX = (
    "Staged release tree does not yet provide capability: "
)

# The only contract cases a staged block may skip, each for its own capability.
CONTRACT_CAPABILITY = dict(
    [(case, "evm-tx-metadata") for case in _ADDITIVE] +
    [(case, "erc7730-runtime-review") for case in _STACK07_EVM] +
    [(case, "evm-unknown-token-review") for case in _STACK10_EVM] +
    [(case, "hive-release-review") for case in _STACK12_HIVE] +
    [(case, "session-trust-lifetime") for case in _SESSION_BOTH + _SESSION_FULL] +
    [(case, "ripple-memo-policy") for case in _RIPPLE
     if case.endswith(("_memo_length_prefix_boundaries", "_with_thorchain_memo"))])

# Native controls a staged block may omit entirely, each for its own capability.
NATIVE_CAPABILITY = dict(
    [(case, "osmosis-wire-guards") for case in _BLOCK13_NATIVE_FULL_ONLY
     if case.startswith("Block13OsmosisWire.")] +
    [(case, "tendermint-progress") for case in _BLOCK13_NATIVE_FULL_ONLY
     if not case.startswith("Block13OsmosisWire.")])


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


def merge_junit(paths, output=None):
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
        output or MERGED_JUNIT, xml_declaration=True, encoding="unicode")
    return cases, inputs


def canonical_case_name(case):
    return "%s.%s" % (case["classname"], case["name"])


def firmware_version_tuple():
    raw = os.environ.get("FW_VERSION", "")
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", raw)
    if match is None:
        fail("FW_VERSION is missing or malformed: %r" % raw)
    return tuple(int(value) for value in match.groups())


# Every Features.Capability the firmware can report (device-protocol), as the
# names capability-gated python-keepkey tests skip with.
KNOWN_CAPABILITIES = frozenset((
    "eip712-chunked-values", "entropy-audit-budget", "erc20-unlimited-approve-review",
    "erc20-unlimited-permit-review", "erc7730-runtime-review",
    "evm-certified-intent", "evm-max-amount-review", "evm-tx-metadata",
    "evm-unknown-token-review", "hive-release-review",
    "legacy-evm-router-signing", "maya-single-message", "osmosis-wire-guards",
    "permit2-review", "prompt-workflow-unwind", "protected-ping-presence",
    "ripple-memo-policy", "session-trust-lifetime", "solana-certified-review",
    "solana-lut-attestation", "solana-runtime-review", "storage-v19-kdf",
    "tendermint-progress", "safe-reset-ceremony", "thor-deposit-review",
    "tron-trc20-review",
))


def release_missing_capabilities(cases):
    """Capabilities the firmware under test did not report.

    The firmware reports what it implements (Features.capabilities); a
    capability-gated python-keepkey test, including one census test per
    capability, skips with CAPABILITY_SKIP_PREFIX + name when the device does
    not report it. Nothing declared outside the firmware can add to this set.
    """
    missing_capabilities = {
        case["skip_reason"][len(CAPABILITY_SKIP_PREFIX):]
        for case in cases
        if case["status"] == "skip" and
        case["skip_reason"].startswith(CAPABILITY_SKIP_PREFIX)
    }
    unknown = sorted(missing_capabilities - KNOWN_CAPABILITIES)
    if unknown:
        fail("capability skips name unknown capabilities: %s" %
             ", ".join(repr(name) for name in unknown))
    return missing_capabilities


# What each release must report, per product. Defined here, reviewed with the
# release, and NOT read from the firmware: a build that drops a capability
# from its own list must not also drop it from what the release requires.
# Capabilities of later releases (e.g. 7.16's permit2-review) are absent.
RELEASE_CAPABILITIES = {
    "7.15.0": {
        "bitcoin-only": frozenset((
            "entropy-audit-budget", "prompt-workflow-unwind",
            "protected-ping-presence", "safe-reset-ceremony",
            "session-trust-lifetime",
        )),
        "full": frozenset((
            "eip712-chunked-values", "entropy-audit-budget", "prompt-workflow-unwind",
            "protected-ping-presence", "safe-reset-ceremony",
            "session-trust-lifetime", "legacy-evm-router-signing",
            "thor-deposit-review", "evm-max-amount-review",
            "evm-unknown-token-review", "evm-tx-metadata",
            "erc7730-runtime-review", "osmosis-wire-guards",
            "ripple-memo-policy", "hive-release-review",
            "solana-runtime-review", "maya-single-message",
            "tendermint-progress", "tron-trc20-review",
            "solana-lut-attestation",
        )),
    },
}


def release_capability_gaps(fw_version, product, missing):
    """Required capabilities whose controls were skipped. None when this
    version has no release list, which release.yml also refuses."""
    required = RELEASE_CAPABILITIES.get(fw_version, {}).get(product)
    if required is None:
        return None
    return sorted(required & missing)


CENSUS_TEST = "test_firmware_capabilities.TestFirmwareCapabilities.test_"
SUPPORTS_FLAG_SKIP = re.compile(r"Firmware does not report (supports_\w+)$")
# Device feature flags that belong to a capability. A test can pass the
# capability gate and still skip on the flag (requires_solana_lut_attestation),
# and that skip carries no capability prefix.
SUPPORTS_FLAG_CAPABILITY = {
    "supports_solana_lut_attestation": "solana-lut-attestation",
}


def release_control_gaps(fw_version, product, cases):
    """Everything that keeps this product's required capabilities from
    counting as tested; None when the version has no release list.

    Absence of a capability skip is not evidence, so each required
    capability's census test must appear once and pass. A test that skipped on
    a device flag is a gap unless the flag belongs to a capability this
    product does not require; an unmapped flag is a gap (fail closed).
    """
    gaps = release_capability_gaps(
        fw_version, product, release_missing_capabilities(cases))
    if gaps is None:
        return None
    required = RELEASE_CAPABILITIES[fw_version][product]
    for capability in sorted(required):
        census = CENSUS_TEST + capability.replace("-", "_")
        found = [case["status"] for case in cases
                 if canonical_case_name(case) == census or
                 canonical_case_name(case).endswith("." + census)]
        if found != ["pass"]:
            gaps.append("census %s: %s" % (capability, found or "missing"))
    for case in cases:
        match = SUPPORTS_FLAG_SKIP.match(case["skip_reason"])
        if case["status"] != "skip" or match is None:
            continue
        capability = SUPPORTS_FLAG_CAPABILITY.get(match.group(1))
        if capability is None or capability in required:
            gaps.append("%s skipped: %s" % (
                canonical_case_name(case), match.group(1)))
    return gaps


def bitcoin_only_control_gaps(cases):
    """Bitcoin-only failures and BITCOIN_ONLY_REQUIRED_CASES not passing."""
    gaps = ["failed: " + canonical_case_name(case) for case in cases
            if case["status"] in ("fail", "error")]
    passed = {canonical_case_name(case) for case in cases
              if case["status"] == "pass"}
    gaps += ["not passing: " + required
             for required in sorted(BITCOIN_ONLY_REQUIRED_CASES)
             if not any(name == required or name.endswith("." + required)
                        for name in passed)]
    return gaps


def validate_cases(cases):
    failures = [case for case in cases
                if case["status"] in ("fail", "error")]
    if failures:
        fail("authoritative JUnit has %d failure/error case(s)" % len(failures))
    passed = {canonical_case_name(case) for case in cases
              if case["status"] == "pass"}
    missing_capabilities = release_missing_capabilities(cases)
    required_cases = set(BASE_REQUIRED_CASES)
    if "hive-release-review" not in missing_capabilities:
        required_cases.update(HIVE_REQUIRED_CASES)
    if "evm-max-amount-review" not in missing_capabilities:
        required_cases.update(EVM_REQUIRED_CASES)
    if "ripple-memo-policy" not in missing_capabilities:
        required_cases.update(RIPPLE_REQUIRED_CASES)
    if "osmosis-wire-guards" not in missing_capabilities:
        if firmware_version_tuple() >= (7, 15, 0):
            required_cases.update(OSMOSIS_REQUIRED_CASES)
        else:
            required_cases.update(OSMOSIS_LEGACY_REQUIRED_CASES)
    missing = sorted(required for required in required_cases
                     if not any(name == required or
                                name.endswith("." + required)
                                for name in passed))
    if missing:
        fail("required release controls missing or not passing: %s" %
             ", ".join(missing))
    # The Hive identities are owned by one native suite. A second copy with
    # another status (a pass beside a skip, say) must not be able to satisfy
    # the gate through the set above, so each must appear exactly once.
    if "hive-release-review" not in missing_capabilities:
        for required in sorted(HIVE_REQUIRED_CASES):
            found = [case["status"] for case in cases
                     if canonical_case_name(case) == required or
                     canonical_case_name(case).endswith("." + required)]
            if found != ["pass"]:
                fail("Hive control %s must appear exactly once and pass, "
                     "found %s" % (required, found or "nothing"))


def read_junit_cases(path):
    try:
        parsed = ET.parse(path)
    except ET.ParseError as exc:
        fail("malformed JUnit %s: %s" % (path, exc))
    cases = {}
    for testcase in parsed.getroot().iter("testcase"):
        name = "%s.%s" % (testcase.get("classname", ""),
                          testcase.get("name", ""))
        # A second copy could mask a failing one; evidence must be unambiguous.
        if name in cases:
            fail("duplicate JUnit testcase %s in %s" % (name, path))
        skipped = testcase.find("skipped")
        cases[name] = (case_status(testcase),
                       skipped.get("message", "") if skipped is not None else "")
    return cases


def validate_contract_junit(root, missing_capabilities=frozenset()):
    """Require every dedicated contract JUnit with exact per-case statuses.

    A case in CONTRACT_CAPABILITY expected to pass may instead skip with its
    capability's skip reason, but only if the firmware did not report that
    capability (missing_capabilities, derived from the capability skips).
    """
    inputs = []
    for variant, directory in sorted(CONTRACT_JUNIT_DIRS.items()):
        for filename, by_variant in sorted(CONTRACT_JUNIT.items()):
            path = Path(root) / directory / filename
            if not path.is_file() or path.stat().st_size == 0:
                fail("required %s contract JUnit missing: %s" % (variant, path))
            cases = read_junit_cases(path)
            if not cases:
                fail("contract JUnit contains no test cases: %s" % path)
            broken = sorted(name for name, (status, reason) in cases.items()
                            if status in ("fail", "error"))
            if broken:
                fail("%s %s has failing case(s): %s" %
                     (variant, filename, ", ".join(broken)))
            wrong = []
            for required, expected in sorted(by_variant[variant].items()):
                found = [result for name, result in cases.items()
                         if name == required or name.endswith("." + required)]
                expected_reason = CONTRACT_SKIP_REASONS[required] if expected == "skip" else ""
                capability = CONTRACT_CAPABILITY.get(required)
                if found != [(expected, expected_reason)] and not (
                        expected == "pass" and
                        capability in missing_capabilities and
                        len(found) == 1 and found[0] in (
                            ("skip", CAPABILITY_SKIP_PREFIX + capability),
                            ("skip", CONTRACT_SKIP_REASONS[required]
                             if required in _ADDITIVE else None))):
                    wrong.append("%s (expected %s, found %s)" % (
                        required, expected + ":" + expected_reason, repr(found) if found else "missing"))
            if wrong:
                fail("%s %s contract cases wrong: %s" %
                     (variant, filename, "; ".join(wrong)))
            inputs.append({
                "variant": variant,
                "path": str(path.relative_to(root)),
                "sha256": sha256_file(path),
            })
    return inputs


def validate_native_contract_junit(root, missing_capabilities=frozenset()):
    """Bind owned native controls to each product's actual GoogleTest run.

    A NATIVE_CAPABILITY case may be absent (never failed) only if the firmware
    did not report its capability.
    """
    inputs = []
    for variant, relative in sorted(NATIVE_CONTRACT_JUNIT.items()):
        path = Path(root) / relative
        if not path.is_file() or path.stat().st_size == 0:
            fail("required %s native contract JUnit missing: %s" %
                 (variant, path))
        # Retain duplicate detection and reject errors before inspecting the
        # GoogleTest status attribute (disabled cases lack a failure node).
        cases = read_junit_cases(path)
        broken = sorted(name for name, (status, _) in cases.items()
                        if status in ("fail", "error"))
        if broken:
            fail("%s native contract JUnit has failing case(s): %s" %
                 (variant, ", ".join(broken)))
        statuses = {
            "%s.%s" % (case.get("classname", ""), case.get("name", "")):
            case.get("status", "")
            for case in ET.parse(path).getroot().iter("testcase")
        }
        wrong = sorted(
            name for name in BLOCK13_NATIVE_CASES[variant]
            if (cases.get(name) != ("pass", "") or statuses.get(name) != "run")
            and not (name not in cases and
                     NATIVE_CAPABILITY.get(name) in missing_capabilities))
        if wrong:
            fail("%s native contract cases missing or not passing/run: %s" %
                 (variant, ", ".join(wrong)))
        if variant == "bitcoin-only":
            unexpected = sorted(_BLOCK13_NATIVE_FULL_ONLY.intersection(cases))
            if unexpected:
                fail("bitcoin-only native evidence contains full-only cases: " +
                     ", ".join(unexpected))
        inputs.append({
            "variant": variant,
            "path": str(relative),
            "sha256": sha256_file(path),
        })
    return inputs


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


def validate_arm_manifests(arm_dir, firmware_sha, python_sha):
    required = {"full", "bitcoin-only"}
    manifests = {}
    for manifest_path in sorted(arm_dir.glob("*/arm-build-manifest.json")):
        artifact = manifest_path.parent.name
        matches = [variant for variant in required
                   if artifact.endswith("-" + variant)]
        if len(matches) != 1:
            fail("unrecognized ARM artifact directory: %s" % artifact)
        variant = matches[0]
        if variant in manifests:
            fail("duplicate ARM manifest for %s" % variant)
        with open(manifest_path, "r", encoding="utf-8") as handle:
            manifest = json.load(handle)
        if manifest.get("firmware_sha") != firmware_sha:
            fail("ARM manifest firmware SHA does not match checkout: %s" %
                 artifact)
        if manifest.get("python_sha") != python_sha:
            fail("ARM manifest Python SHA does not match gitlink: %s" %
                 artifact)
        if manifest.get("variant") != variant:
            fail("ARM manifest variant does not match artifact: %s" % artifact)
        files = manifest.get("files", [])
        if not files:
            fail("ARM manifest contains no binaries: %s" % artifact)
        for item in files:
            path = manifest_path.parent / item.get("name", "")
            if not path.is_file() or sha256_file(path) != item.get("sha256"):
                fail("ARM artifact hash mismatch: %s" % path)
        manifests[variant] = {
            "artifact": artifact,
            "manifest_path": manifest_path,
            "manifest": manifest,
            "manifest_sha256": sha256_file(manifest_path),
        }
    if set(manifests) != required:
        fail("expected full and bitcoin-only ARM manifests, found: %s" %
             ", ".join(sorted(manifests)))
    return manifests


def require_native_junit(root, product_dir=Path("test-reports")):
    """Require each native suite before discovering any additional XML inputs."""
    native_dir = Path(root) / product_dir / "firmware-unit"
    required = ("firmware.xml", "board.xml", "crypto.xml")
    missing = [name for name in required
               if not (native_dir / name).is_file()
               or (native_dir / name).stat().st_size == 0]
    if missing:
        raise SystemExit("ERROR: required native JUnit inputs missing or empty: " +
                         ", ".join(missing))
    for name in required:
        try:
            parsed = ET.parse(native_dir / name)
        except ET.ParseError as exc:
            raise SystemExit("ERROR: malformed native JUnit %s: %s" % (name, exc))
        if next(parsed.iter("testcase"), None) is None:
            raise SystemExit("ERROR: native JUnit contains no test cases: " + name)
    return sorted(native_dir.glob("*.xml"))


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
    junit_paths += require_native_junit(ROOT)
    junit_paths.append(ROOT / "test-reports" / "dylib-junit.xml")
    junit_paths.append(ROOT / "test-reports" / "emulator" / "lifecycle.xml")
    missing_junit = [str(path) for path in junit_paths if not path.is_file()]
    if missing_junit:
        fail("required JUnit inputs missing: %s" % ", ".join(missing_junit))

    cases, junit_inputs = merge_junit(junit_paths)
    validate_cases(cases)
    # The capabilities the firmware did not report, from the JUnit skips.
    missing_capabilities = release_missing_capabilities(cases)
    # The bitcoin-only product's own evidence: its python suite and the same
    # native suites the full product requires. Merged to its own file so the
    # full product's merged JUnit (and so the PDF) is not overwritten.
    btc_dir = Path("test-reports") / "bitcoin-only"
    btc_junit = ROOT / btc_dir / "python-keepkey" / "junit.xml"
    if not btc_junit.is_file():
        fail("bitcoin-only JUnit missing: %s" % btc_junit)
    btc_cases, btc_inputs = merge_junit(
        [btc_junit] + require_native_junit(ROOT, btc_dir), BTC_MERGED_JUNIT)
    btc_missing_capabilities = release_missing_capabilities(btc_cases)
    contract_inputs = validate_contract_junit(ROOT, missing_capabilities)
    contract_inputs += validate_native_contract_junit(ROOT, missing_capabilities)

    screenshot_root = ROOT / "test-reports" / "screenshots"
    pngs, sequences = validate_screenshots(screenshot_root)

    arm_dir = ROOT / "test-reports" / "arm"
    arm_manifests = validate_arm_manifests(
        arm_dir, firmware_sha, python_sha)

    wrapper_hash = sha256_file(Path(__file__))
    renderer_hash = sha256_file(REPORT_GENERATOR)
    generator_hash = hashlib.sha256(
        (wrapper_hash + renderer_hash).encode("ascii")).hexdigest()
    arm_manifest_hash = hashlib.sha256(json.dumps({
        variant: item["manifest_sha256"]
        for variant, item in sorted(arm_manifests.items())
    }, sort_keys=True).encode("ascii")).hexdigest()
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
            "contract_inputs": contract_inputs,
            "merged_sha256": sha256_file(MERGED_JUNIT),
            "skips": [case for case in cases if case["status"] == "skip"],
        },
        # A staged block may lack capabilities; a release may not.
        # release.yml refuses evidence where this list is non-empty.
        "missing_capabilities": sorted(missing_capabilities),
        "missing_capabilities_bitcoin_only": sorted(btc_missing_capabilities),
        # Required capabilities skipped (by prefix or by a device flag) or
        # whose census test did not pass, per product.
        "release_capability_gaps": {
            "full": release_control_gaps(fw_version, "full", cases),
            "bitcoin-only": release_control_gaps(
                fw_version, "bitcoin-only", btc_cases),
        },
        # Base controls per product; release.yml refuses any entry. The full
        # product's are enforced above (validate_cases), so it is empty here.
        "required_controls": {
            "full": [],
            "bitcoin-only": bitcoin_only_control_gaps(btc_cases),
        },
        "bitcoin_only_junit": {
            "inputs": btc_inputs,
            "merged_sha256": sha256_file(BTC_MERGED_JUNIT),
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
            "manifest_set_sha256": arm_manifest_hash,
            "variants": {
                variant: {
                    "artifact": item["artifact"],
                    "manifest_sha256": item["manifest_sha256"],
                    "files": item["manifest"]["files"],
                }
                for variant, item in sorted(arm_manifests.items())
            },
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
