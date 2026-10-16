"""Stack 07 protocol regressions; run against an isolated full-feature emulator.

PYTHONPATH must include deps/python-keepkey and deps/python-keepkey/tests.
Uses only the public test mnemonic and a throwaway catalog signing key.
"""

import copy
import os

import common
from keepkeylib import erc7730_compiler
from keepkeylib import messages_ethereum_pb2 as eth
from keepkeylib import messages_pb2 as proto
from keepkeylib import types_pb2 as types
from keepkeylib.signed_metadata import test_signer_compressed_pubkey as signer_pubkey
from test_msg_ethereum_erc7730_runtime import (
    ADDRESS, OTHER_ADDRESS, PATH, UNKNOWN_SIGNER_KEY, Erc7730Harness,
    assert_failure)


# The product under test is declared by the caller (python-keepkey-tests.sh),
# never inferred from the device: a regressed full build that answered like
# the bitcoin-only product must fail here, not select the smaller contract.
VARIANTS = {"full": ("Emulator", "KeepKey"),
            "bitcoin-only": ("EmulatorBTC", "KeepKeyBTC")}
BITCOIN_ONLY_SKIP = "Stack 07 EVM contracts are intentionally absent from bitcoin-only"


# Uncertified Mail fixture, ButtonRequest by ButtonRequest: five domain leaves
# ("EIP-712 Domain"; the bytes32 salt body pages once, so six requests), two
# message leaves ("Mail"), then the final "Sign Typed Data" screen, whose
# "from <address>?" body pages once (SignTx, then one continuation page).
MAIL_UNCERTIFIED_BUTTONS = 10
# Certified order: domain (1-6), message pass one (7-8), runtime signer (9),
# unverified-data warning (10), contract action (11), first field (12),
# replayed message leaves (13-14), second field (15), final screen (16-17).
MAIL_CERTIFIED_DECLINABLE = (9, 10, 11, 12, 15)
# Empty Mail: six domain requests, then the final screen (two requests).
EMPTY_MAIL_FINAL_SCREEN = 7
EMPTY_MAIL_BUTTONS = 8


def assert_single_final_sign_screen(test):
    """Exactly one SignTx request -- the final "Sign Typed Data" screen --
    and nothing after it except its own continuation page(s)."""
    codes = test.button_codes
    test.assertEqual(codes.count(types.ButtonRequest_SignTx), 1)
    final = codes.index(types.ButtonRequest_SignTx)
    test.assertTrue(all(code == types.ButtonRequest_Other
                        for code in codes[final + 1:]))
    return final


def expected_variant(test):
    variant = os.environ.get("KK_STACK07_FIRMWARE_VARIANT")
    if variant not in VARIANTS:
        test.fail("KK_STACK07_FIRMWARE_VARIANT must be full or bitcoin-only, got %r"
                  % variant)
    test.assertIn(test.client.features.firmware_variant, VARIANTS[variant])
    return variant


class TestStack07CoinTableReuse(common.KeepKeyTest):
    def setUp(self):
        super().setUp()
        self.setup_mnemonic_nopin_nopassphrase()

    def test_cointable_response_reuses_decoded_request_without_truncation(self):
        variant = expected_variant(self)
        inventory = self.client.call(proto.GetCoinTable())
        self.assertEqual(inventory.chunk_size, 24)
        if variant == "bitcoin-only":
            self.assertEqual(inventory.num_coins, 2)
            count, ends = 2, [2]
        else:
            self.assertGreater(inventory.num_coins, 24)
            count, ends = 24, [10, 24]
        for end in ends:
            page = self.client.call(proto.GetCoinTable(start=0, end=end))
            self.assertIsInstance(page, proto.CoinTable)
            self.assertEqual(page.chunk_size, 24)
            self.assertEqual(len(page.table), end)
            self.assertEqual(page.num_coins, inventory.num_coins)
        invalid = self.client.call_raw(proto.GetCoinTable(start=0, end=25))
        assert_failure(self, invalid, types.Failure_Other,
                       "Incorrect GetCoinTable parameters")
        recovered = self.client.call(proto.GetCoinTable(start=0, end=count))
        self.assertEqual(len(recovered.table), count)


class TestStack07Regressions(Erc7730Harness, common.KeepKeyTest):
    def setUp(self):
        super().setUp()
        if expected_variant(self) == "bitcoin-only":
            self.skipTest(BITCOIN_ONLY_SKIP)
        self.requires_release_capability("erc7730-runtime-review")
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy("AdvancedMode", 1)

    def _typed_fixture(self, fields=True):
        doc = {
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                    {"name": "salt", "type": "bytes32"}],
                "Mail": [{"name": "first", "type": "uint256"},
                         {"name": "second", "type": "uint256"}]},
            "primaryType": "Mail",
            "domain": {"name": "Audit app", "version": "1", "chainId": 1,
                       "verifyingContract": "0x" + ADDRESS.hex(), "salt": "0x" + "22" * 32},
            "message": {"first": 42, "second": 7}}
        descriptor = {"display": {"formats": {"Mail(uint256 first,uint256 second)": {
            "intent": "Audit action", "fields": [
                {"path": name, "label": label, "format": "raw"}
                for name, label in (("first", "First value"), ("second", "Second value"))
            ] if fields else []}}}}
        return doc, erc7730_compiler.compile_eip712(descriptor, doc)

    def _typed_start(self):
        return eth.EthereumSignTypedData(address_n=PATH, primary_type="Mail", metamask_v4_compat=True)

    def test_all_typed_fields_are_reviewed_and_signature_is_unchanged(self):
        doc, program = self._typed_fixture()
        baseline, baseline_buttons, _, _ = self._walk(self._typed_start(), doc=doc)
        self.assertIsInstance(baseline, eth.EthereumTypedDataSignature)
        envelope = self._preload(program)
        result, buttons, _, passes = self._walk(self._typed_start(), envelope, doc)
        self.assertIsInstance(result, eth.EthereumTypedDataSignature)
        self.assertEqual(result.signature, baseline.signature)
        self.assertEqual(passes, 2)
        self.assertEqual(baseline_buttons, MAIL_UNCERTIFIED_BUTTONS)
        self.assertEqual(buttons, baseline_buttons + 7)  # identity/warning/intent, two fields, two replayed leaves
        assert_single_final_sign_screen(self)

    def test_typed_replay_change_is_refused(self):
        doc, program = self._typed_fixture()
        envelope = self._preload(program)
        result, _, _, passes = self._walk(self._typed_start(), envelope, doc, change_pass=2)
        assert_failure(self, result, types.Failure_SyntaxError,
                       "Certified EIP-712 value was not found")
        self.assertEqual(passes, 2)

    def test_declining_source_intent_or_either_field_aborts(self):
        for declined in MAIL_CERTIFIED_DECLINABLE:
            doc, program = self._typed_fixture()
            envelope = self._preload(program)
            result, buttons, _, _ = self._walk(
                self._typed_start(), envelope, doc, cancel_button=declined)
            assert_failure(self, result, types.Failure_ActionCancelled,
                           "Signing cancelled by user")
            self.assertEqual(buttons, declined)
            self.client.init_device()
            result, buttons, _, _ = self._walk(self._typed_start(), doc=doc)
            self.assertIsInstance(result, eth.EthereumTypedDataSignature)
            self.assertEqual(buttons, MAIL_UNCERTIFIED_BUTTONS)

    def test_domain_name_version_and_salt_mismatches_are_refused(self):
        for field, changed in (("name", "Different app"), ("version", "2"), ("salt", "0x" + "33" * 32)):
            doc, program = self._typed_fixture()
            envelope = self._preload(program)
            doc["domain"][field] = changed
            result, buttons, _, passes = self._walk(self._typed_start(), envelope, doc)
            assert_failure(self, result, types.Failure_SyntaxError,
                           "ERC-7730 domain constraint does not match")
            self.assertEqual(passes, 0)

    def test_failed_certified_domain_clears_preload(self):
        doc, program = self._typed_fixture()
        envelope = self._preload(program)
        changed = copy.deepcopy(doc)
        changed["domain"]["chainId"] = 2
        result, _, _, _ = self._walk(self._typed_start(), envelope, changed)
        assert_failure(self, result, types.Failure_SyntaxError,
                       "ERC-7730 definition does not match typed data")
        self.assertEqual(self.definition_requests, 0)
        result, buttons, _, _ = self._walk(self._typed_start(), doc=doc)
        self.assertIsInstance(result, eth.EthereumTypedDataSignature)
        self.assertEqual(buttons, MAIL_UNCERTIFIED_BUTTONS)

    def test_early_typed_failure_clears_preload(self):
        doc, program = self._typed_fixture()
        self._preload(program)
        result = self.client.call_raw(eth.EthereumSignTypedData(
            address_n=PATH, primary_type="", metamask_v4_compat=True))
        assert_failure(self, result, types.Failure_SyntaxError,
                       "EIP-712 primary type missing or too long")
        result, buttons, _, _ = self._walk(self._typed_start(), doc=doc)
        self.assertIsInstance(result, eth.EthereumTypedDataSignature)
        self.assertEqual(buttons, MAIL_UNCERTIFIED_BUTTONS)

    def test_empty_message_requires_explicit_consent(self):
        doc, _ = self._typed_fixture()
        doc["types"]["Mail"] = []
        doc["message"] = {}
        result, buttons, _, _ = self._walk(self._typed_start(), doc=doc,
                                           cancel_button=EMPTY_MAIL_FINAL_SCREEN)
        # The stream's own empty-message screen is gone: the explicit consent
        # is the final "Sign EMPTY Mail" screen, and declining it signs nothing.
        assert_failure(self, result, types.Failure_ActionCancelled,
                       "Signing cancelled by user")
        self.assertEqual(buttons, EMPTY_MAIL_FINAL_SCREEN)
        self.assertEqual(self.button_codes[-1], types.ButtonRequest_SignTx)
        result, buttons, _, _ = self._walk(self._typed_start(), doc=doc)
        self.assertIsInstance(result, eth.EthereumTypedDataSignature)
        self.assertEqual(buttons, EMPTY_MAIL_BUTTONS)
        assert_single_final_sign_screen(self)

    def test_intent_only_typed_definition_still_requires_source_and_intent(self):
        doc, program = self._typed_fixture(fields=False)
        envelope = self._preload(program)
        result, buttons, _, _ = self._walk(self._typed_start(), envelope, doc)
        self.assertIsInstance(result, eth.EthereumTypedDataSignature)
        # six domain requests, three source/intent screens, two message
        # leaves, two final-screen requests
        self.assertEqual(buttons, 13)
        assert_single_final_sign_screen(self)

    def test_calldata_signing_replay_change_is_refused(self):
        signature = "audit(uint256 first,uint256 second)"
        descriptor = {"display": {"formats": {signature: {
            "intent": "Audit action", "fields": [
                {"path": "first", "label": "First value", "format": "raw"},
                {"path": "second", "label": "Second value", "format": "raw"}]}}}}
        program = erc7730_compiler.compile_calldata(descriptor, signature, 1, ADDRESS)
        envelope = self._preload(program)
        start = eth.EthereumSignTx(address_n=PATH, nonce=b"", gas_price=b"\x01",
            gas_limit=b"\xff\xff", to=ADDRESS, value=b"", chain_id=1,
            data_length=68, data_initial_chunk=program[38:42])
        result, _, passes, _ = self._walk(start, envelope, change_pass=4)
        assert_failure(self, result, types.Failure_SyntaxError,
                       "ERC-7730 calldata does not match definition")
        self.assertEqual(passes, 4)

    def test_calldata_signing_replay_succeeds_with_arguments(self):
        signature = "audit(uint256 first,uint256 second)"
        descriptor = {"display": {"formats": {signature: {
            "intent": "Audit action", "fields": [
                {"path": "first", "label": "First value", "format": "raw"},
                {"path": "second", "label": "Second value", "format": "raw"}]}}}}
        program = erc7730_compiler.compile_calldata(descriptor, signature, 1, ADDRESS)
        start = eth.EthereumSignTx(address_n=PATH, nonce=b"", gas_price=b"\x01",
            gas_limit=b"\xff\xff", to=ADDRESS, value=b"", chain_id=1,
            data_length=68, data_initial_chunk=program[38:42])
        baseline, _, baseline_passes, _ = self._walk(start)
        self.assertIsInstance(baseline, eth.EthereumTxRequest)
        self.assertTrue(baseline.HasField("signature_r"))
        self.assertEqual(baseline_passes, 1)
        envelope = self._preload(program)
        result, _, passes, _ = self._walk(start, envelope)
        self.assertIsInstance(result, eth.EthereumTxRequest)
        self.assertEqual(result.signature_r, baseline.signature_r)
        self.assertEqual(result.signature_s, baseline.signature_s)
        self.assertEqual(passes, 4)

    def test_selector_only_call_signs_after_certified_intent(self):
        signature = "audit()"
        descriptor = {"display": {"formats": {signature: {
            "intent": "Audit action", "fields": []}}}}
        program = erc7730_compiler.compile_calldata(descriptor, signature, 1, ADDRESS)
        start = eth.EthereumSignTx(address_n=PATH, nonce=b"", gas_price=b"\x01",
            gas_limit=b"\xff\xff", to=ADDRESS, value=b"", chain_id=1,
            data_length=4, data_initial_chunk=program[38:42])
        baseline, baseline_buttons, _, _ = self._walk(start)
        self.assertIsInstance(baseline, eth.EthereumTxRequest)
        self.assertTrue(baseline.HasField("signature_r"))
        envelope = self._preload(program)
        result, buttons, passes, _ = self._walk(start, envelope)
        self.assertIsInstance(result, eth.EthereumTxRequest)
        self.assertEqual(result.signature_r, baseline.signature_r)
        self.assertEqual(result.signature_s, baseline.signature_s)
        self.assertEqual(buttons, baseline_buttons + 3)
        self.assertEqual(passes, 0)

    def test_non_ascii_intent_is_escaped_not_drawn_as_glyphs(self):
        # The OLED draws every non-ASCII byte as one identical glyph, so signer
        # strings are escaped like values. Drawn raw, 64 x U+00E9 (128 bytes)
        # pages exactly like 128 ASCII bytes; escaped it is 512 characters and
        # needs more screens. Equal counts would mean raw glyphs were shown.
        def certified_buttons(intent):
            signature = "audit()"
            descriptor = {"display": {"formats": {signature: {
                "intent": intent, "fields": []}}}}
            program = erc7730_compiler.compile_calldata(
                descriptor, signature, 1, ADDRESS)
            start = eth.EthereumSignTx(address_n=PATH, nonce=b"",
                gas_price=b"\x01", gas_limit=b"\xff\xff", to=ADDRESS,
                value=b"", chain_id=1, data_length=4,
                data_initial_chunk=program[38:42])
            baseline, baseline_buttons, _, _ = self._walk(start)
            result, buttons, passes, _ = self._walk(
                start, self._preload(program))
            self.assertIsInstance(result, eth.EthereumTxRequest)
            self.assertEqual(result.signature_r, baseline.signature_r)
            self.assertEqual(result.signature_s, baseline.signature_s)
            self.assertEqual(passes, 0)
            return buttons - baseline_buttons

        self.assertGreater(certified_buttons("\u00e9" * 64),
                           certified_buttons("e" * 128))

    def test_certified_approval_refused_before_annotation_screens(self):
        signature = "approve(address spender,uint256 amount)"
        descriptor = {"display": {"formats": {signature: {
            "intent": "Approve tokens", "fields": [
                {"path": "amount", "label": "Allowance", "format": "raw"}]}}}}
        program = erc7730_compiler.compile_calldata(descriptor, signature, 1, ADDRESS)
        envelope = self._preload(program)
        selector = program[38:42]
        start = eth.EthereumSignTx(address_n=PATH, nonce=b"", gas_price=b"\x01",
            gas_limit=b"\xff\xff", to=ADDRESS, value=b"", chain_id=1,
            data_length=68, data_initial_chunk=selector)
        result, buttons, _, _ = self._walk(start, envelope)
        assert_failure(self, result, types.Failure_SyntaxError,
                       "ERC-7730 approval not supported")
        self.assertEqual(buttons, 0)

        # A finite approval with all 68 bytes supplied up front still reaches
        # the established ordinary review and signing path.
        data = selector + b"\x00" * 12 + ADDRESS + (42).to_bytes(32, "big")
        ordinary = eth.EthereumSignTx(address_n=PATH, nonce=b"", gas_price=b"\x01",
            gas_limit=b"\xff\xff", to=ADDRESS, value=b"", chain_id=1,
            data_length=68, data_initial_chunk=data)
        result, buttons, _, _ = self._walk(ordinary)
        self.assertIsInstance(result, eth.EthereumTxRequest)
        self.assertTrue(result.HasField("signature_r"))
        self.assertGreater(buttons, 0)

    def test_verifying_contract_mismatch_is_refused_before_certified_review(self):
        doc, program = self._typed_fixture()
        envelope = self._preload(program)
        doc["domain"]["verifyingContract"] = "0x" + OTHER_ADDRESS.hex()
        result, buttons, _, passes = self._walk(self._typed_start(), envelope, doc)
        # Firmware contract (eip712_pump, EIP712_REQ_DEFINITION): the catalog
        # identity is matched once the domain has been walked, so the ordinary
        # domain review precedes the refusal, but no certified definition byte
        # is requested and no message leaf is ever streamed or shown.
        assert_failure(self, result, types.Failure_SyntaxError,
                       "ERC-7730 definition does not match typed data")
        self.assertEqual(self.definition_requests, 0)
        self.assertEqual(passes, 0)

    def test_tampered_envelope_signature_is_refused_at_preload(self):
        _, program = self._typed_fixture()
        self._load_signer()
        envelope = bytearray(self._envelope(program))
        envelope[-2] ^= 0x01  # last byte of the 64-byte compact signature
        result = self._raw_preload(bytes(envelope))
        assert_failure(self, result, types.Failure_SyntaxError,
                       "Invalid certified ERC-7730 definition")

    def test_unknown_signer_is_refused_at_preload(self):
        from ecdsa import SigningKey, SECP256k1
        _, program = self._typed_fixture()
        self._load_signer()
        unknown_pub = SigningKey.from_string(
            UNKNOWN_SIGNER_KEY, curve=SECP256k1).get_verifying_key().to_string(
                "compressed")
        self.assertNotEqual(unknown_pub, signer_pubkey())
        envelope = self._envelope(program, UNKNOWN_SIGNER_KEY, unknown_pub)
        result = self._raw_preload(envelope)
        assert_failure(self, result, types.Failure_SyntaxError,
                       "Invalid certified ERC-7730 definition")

    def test_advanced_mode_off_refuses_preload(self):
        _, program = self._typed_fixture()
        self._load_signer()
        envelope = self._envelope(program)
        self.client.apply_policy("AdvancedMode", 0)
        result = self._raw_preload(envelope)
        assert_failure(self, result, types.Failure_Other,
                       "AdvancedMode required for ERC-7730")

    def test_domain_only_signature_refuses_certified_preload(self):
        doc, program = self._typed_fixture()
        envelope = self._preload(program)
        result, _, _, passes = self._walk(eth.EthereumSignTypedData(
            address_n=PATH, primary_type="EIP712Domain",
            metamask_v4_compat=True), envelope, doc)
        assert_failure(self, result, types.Failure_SyntaxError,
                       "ERC-7730 cannot describe a domain-only signature")
        self.assertNotIn(types.ButtonRequest_SignTx, self.button_codes)
        self.assertEqual(passes, 0)

    def test_dirty_approval_spender_word_is_refused_before_any_screen(self):
        clean = (bytes.fromhex("095ea7b3") + bytes(12) + ADDRESS +
                 (42).to_bytes(32, "big"))
        for offset in (4, 15):  # first and last padding byte of the spender word
            data = bytearray(clean)
            data[offset] = 0x01
            start = eth.EthereumSignTx(address_n=PATH, nonce=b"",
                gas_price=b"\x01", gas_limit=b"\xff\xff", to=ADDRESS,
                value=b"", chain_id=1, data_length=68,
                data_initial_chunk=bytes(data))
            # call_raw: the refusal must be the FIRST response, i.e. no
            # ButtonRequest precedes it.
            result = self.client.call_raw(start)
            assert_failure(self, result, types.Failure_SyntaxError,
                           "Malformed ERC20 approval")
        result, buttons, _, _ = self._walk(eth.EthereumSignTx(
            address_n=PATH, nonce=b"", gas_price=b"\x01",
            gas_limit=b"\xff\xff", to=ADDRESS, value=b"", chain_id=1,
            data_length=68, data_initial_chunk=clean))
        self.assertIsInstance(result, eth.EthereumTxRequest)
        self.assertTrue(result.HasField("signature_r"))
        self.assertGreater(buttons, 0)

    def test_preload_survives_get_features_and_is_discarded_by_initialize(self):
        signature = "audit(uint256 first,uint256 second)"
        descriptor = {"display": {"formats": {signature: {
            "intent": "Audit action", "fields": [
                {"path": "first", "label": "First value", "format": "raw"},
                {"path": "second", "label": "Second value", "format": "raw"}]}}}}
        program = erc7730_compiler.compile_calldata(descriptor, signature, 1, ADDRESS)
        start = eth.EthereumSignTx(address_n=PATH, nonce=b"", gas_price=b"\x01",
            gas_limit=b"\xff\xff", to=ADDRESS, value=b"", chain_id=1,
            data_length=68, data_initial_chunk=program[38:42])
        baseline, baseline_buttons, baseline_passes, _ = self._walk(start)
        self.assertTrue(baseline.HasField("signature_r"))
        self.assertEqual((baseline_passes, self.definition_requests), (1, 0))

        # GetFeatures and Ping pass through without touching the preload.
        envelope = self._preload(program)
        self.assertIsInstance(self.client.call_raw(proto.GetFeatures()),
                              proto.Features)
        self.assertIsInstance(self.client.call_raw(proto.Ping(message="x")),
                              proto.Success)
        result, _, passes, _ = self._walk(start, envelope)
        self.assertEqual(result.signature_r, baseline.signature_r)
        self.assertEqual(passes, 4)
        self.assertGreater(self.definition_requests, 0)

        # Initialize discards it: the same transaction takes the ordinary,
        # uncertified path and signs exactly as the baseline did.
        envelope = self._preload(program)
        self.client.init_device()
        result, buttons, passes, _ = self._walk(start, envelope)
        self.assertIsInstance(result, eth.EthereumTxRequest)
        self.assertEqual((result.signature_r, result.signature_s),
                         (baseline.signature_r, baseline.signature_s))
        self.assertEqual((passes, self.definition_requests), (1, 0))
        self.assertEqual(buttons, baseline_buttons)
