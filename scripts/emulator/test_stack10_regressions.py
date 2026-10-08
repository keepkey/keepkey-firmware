"""Stack 10 disclosure contract, using only the public test mnemonic."""
import os

import common
from keepkeylib import messages_ethereum_pb2 as eth
from keepkeylib import messages_pb2 as proto
from keepkeylib import types_pb2 as types
from test_msg_ethereum_erc7730_runtime import Erc7730Harness, assert_failure


class TestStack10Disclosure(Erc7730Harness, common.KeepKeyTest):
    def setUp(self):
        super().setUp()
        variant = os.environ.get("KK_FIRMWARE_VARIANT")
        self.assertIn(variant, ("full", "bitcoin-only"))
        self.assertIn(self.client.features.firmware_variant,
                      ("EmulatorBTC", "KeepKeyBTC") if variant == "bitcoin-only"
                      else ("Emulator", "KeepKey"))
        if variant == "bitcoin-only":
            self.skipTest("Stack 10 EVM signing is absent from bitcoin-only")
        self.requires_release_capability("evm-unknown-token-review")
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.apply_policy("AdvancedMode", 1)

    def _tx(self, approve=False, amount=1, contract=b"\x42" * 20,
            recipient=b"\x24" * 20, **fields):
        data = bytes.fromhex("095ea7b3" if approve else "a9059cbb")
        data += b"\0" * 12 + recipient + amount.to_bytes(32, "big")
        tx = eth.EthereumSignTx(address_n=[0, 0], nonce=b"", gas_price=b"\x14",
                                gas_limit=b"\xea\x60", value=b"", to=contract,
                                chain_id=1, data_length=len(data),
                                data_initial_chunk=data)
        for key, value in fields.items():
            setattr(tx, key, value)
        return tx

    def _signed(self, tx, **kwargs):
        result, _, _, _ = self._walk(tx, **kwargs)
        self.assertIsInstance(result, eth.EthereumTxRequest)
        self.assertTrue(result.HasField("signature_r"))
        return result

    def test_exact_raw_values_contract_and_counterparty(self):
        for approve in (False, True):
            for amount in (0, 1, (1 << 256) - (2 if approve else 1)):
                self._signed(self._tx(approve, amount))
                title, body = self._first_pages()[0]
                self.assertEqual(title, "Approve" if approve else "Send")
                expected = "Unknown token contract 0x" + "42" * 20 + "\n"
                expected += ("Allow 0x" + "24" * 20 + " to withdraw up to " +
                             str(amount) + " base units?" if approve else
                             "Send " + str(amount) + " base units to 0x" +
                             "24" * 20 + "?")
                self.assertEqual(body, expected)
                self.assertTrue(any("data" in t.lower() for t, _ in self.screens))

    def test_padded_zero_value_keeps_exact_token_review(self):
        for approve in (False, True):
            reference = self._signed(self._tx(approve))
            expected = self._first_pages()[0]
            for zero in (b"\0", b"\0" * 32):
                signed = self._signed(self._tx(approve, value=zero))
                self.assertEqual(self._first_pages()[0], expected)
                self.assertEqual(signed.signature_r, reference.signature_r)
                self.assertEqual(signed.signature_s, reference.signature_s)

    def test_noncanonical_transfers_keep_advanced_raw_fallback(self):
        canonical = self._tx()
        data = canonical.data_initial_chunk
        for representation in ("split", "trailing", "streamed_trailing",
                               "dirty_address"):
            tx = self._tx()
            arguments = None
            if representation == "split":
                tx.data_initial_chunk = data[:4]
                arguments = data[4:]
            elif representation == "trailing":
                tx.data_initial_chunk = data + b"\0"
                tx.data_length += 1
            elif representation == "streamed_trailing":
                tx.data_length += 1
                arguments = b"\0"
            else:
                tx.data_initial_chunk = data[:4] + b"\1" + data[5:]
            self.client.apply_policy("AdvancedMode", 1)
            self._signed(tx, arguments=arguments)
            title, body = self._first_pages()[0]
            self.assertEqual(title, "Send")
            self.assertIn("0x" + "42" * 20, body)
            self.assertNotIn("Unknown token contract", body)
            self.assertTrue(any("data" in t.lower() for t, _ in self.screens))
            self.client.apply_policy("AdvancedMode", 0)
            result, _, _, _ = self._walk(tx, arguments=arguments)
            assert_failure(self, result, types.Failure_ActionCancelled,
                           "Arbitrary contract data signing disabled by policy")

    def test_contract_substitution_changes_review_and_signature(self):
        first = self._signed(self._tx())
        first_body = self._first_pages()[0][1]
        second = self._signed(self._tx(contract=b"\x43" * 20))
        second_body = self._first_pages()[0][1]
        self.assertNotEqual(first_body, second_body)
        self.assertIn("0x" + "43" * 20, second_body)
        self.assertNotEqual(first.signature_r, second.signature_r)

    def test_transfer_account_keeps_raw_review_and_recipient_binding(self):
        self.client.apply_policy("ShapeShift", 1)
        path = [0x8000002c, 0x8000003c, 0x80000001, 0, 0]
        recipient = self.client.ethereum_get_address(path)
        tx = self._tx(recipient=recipient, address_type=types.TRANSFER)
        tx.to_address_n.extend(path)
        self._signed(tx)
        title, body = self._first_pages()[0]
        self.assertEqual(title, "Transfer")
        self.assertIn("Unknown token contract 0x" + "42" * 20, body)
        self.assertIn("Send 1 base units to 0x", body)
        self.assertIn(recipient.hex(), body.lower())
        wrong = self._tx(address_type=types.TRANSFER)
        wrong.to_address_n.extend(path)
        result, buttons, _, _ = self._walk(wrong)
        self.assertIsInstance(result, proto.Failure)
        self.assertEqual(buttons, 0)

    def test_transfer_account_padded_zero_keeps_contract_review(self):
        self.client.apply_policy("ShapeShift", 1)
        path = [0x8000002c, 0x8000003c, 0x80000001, 0, 0]
        recipient = self.client.ethereum_get_address(path)
        reference = self._tx(amount=0, recipient=recipient,
                             address_type=types.TRANSFER)
        reference.to_address_n.extend(path)
        signed_reference = self._signed(reference)
        expected_review = self._first_pages()[0]
        self.assertIn("Unknown token contract", expected_review[1])
        for value in (b"\0", b"\0" * 32):
            tx = self._tx(amount=0, recipient=recipient, value=value,
                          address_type=types.TRANSFER)
            tx.to_address_n.extend(path)
            signed = self._signed(tx)
            self.assertEqual(self._first_pages()[0], expected_review)
            self.assertEqual(signed.signature_r, signed_reference.signature_r)
            self.assertEqual(signed.signature_s, signed_reference.signature_s)

    def test_transfer_account_rejects_noncanonical_total_length(self):
        self.client.apply_policy("ShapeShift", 1)
        path = [0x8000002c, 0x8000003c, 0x80000001, 0, 0]
        recipient = self.client.ethereum_get_address(path)
        dai = bytes.fromhex("6b175474e89094c44da98b954eedeac495271d0f")
        for contract in (b"\x42" * 20, dai):
            canonical = self._tx(contract=contract, recipient=recipient,
                                 address_type=types.TRANSFER)
            canonical.to_address_n.extend(path)
            reference = self._signed(canonical)
            self.assertIn("DAI" if contract == dai else "Unknown token contract",
                          self._first_pages()[0][1])
            for representation in ("trailing", "streamed_trailing", "short",
                                   "zero", "absent"):
                tx = eth.EthereumSignTx()
                tx.CopyFrom(canonical)
                arguments = None
                if representation == "trailing":
                    tx.data_initial_chunk += b"\0"
                    tx.data_length = 69
                elif representation == "streamed_trailing":
                    tx.data_length = 69
                    arguments = b"\0"
                elif representation == "short":
                    tx.data_length = 67
                elif representation == "zero":
                    tx.data_length = 0
                else:
                    tx.ClearField("data_length")
                with self.subTest(contract=contract.hex(), shape=representation):
                    result, buttons, _, _ = self._walk(tx, arguments=arguments)
                    self.assertIsInstance(result, proto.Failure)
                    self.assertEqual(buttons, 0)
                    retried = self._signed(canonical)
                    self.assertEqual(retried.signature_r, reference.signature_r)
                    self.assertEqual(retried.signature_s, reference.signature_s)

    def test_cancel_every_disclosure_page_then_retry(self):
        tx = self._tx(approve=True, amount=(1 << 256) - 2)
        baseline = self._signed(tx)
        count = len(self.screens)
        self.assertGreater(count, 3)
        for button in range(1, count + 1):
            result, seen, _, _ = self._walk(tx, cancel_button=button)
            self.assertIsInstance(result, proto.Failure)
            self.assertEqual(result.code, types.Failure_ActionCancelled)
            self.assertEqual(seen, button)
            retried = self._signed(tx)
            self.assertEqual(retried.signature_r, baseline.signature_r)
            self.assertEqual(retried.signature_s, baseline.signature_s)

    def test_unlimited_approval_warns_and_raw_signing_requires_advanced_mode(self):
        tx = self._tx(True, (1 << 256) - 1)
        # Unlimited approvals are allowed after the explicit warning. Pin its
        # spender and unknown token contract, and prove it cannot be bypassed
        # by declining the first screen.
        self._signed(tx)
        self.assertEqual(self._first_pages()[0], (
            "UNLIMITED approval", "Allow 0x" + "24" * 20 +
            " to spend ALL your 0x" + "42" * 20))
        result, buttons, _, _ = self._walk(tx, cancel_button=1)
        assert_failure(self, result, types.Failure_ActionCancelled,
                       "Signing cancelled by user")
        self.assertEqual(buttons, 1)
        self.client.apply_policy("AdvancedMode", 0)
        result, _, _, _ = self._walk(self._tx())
        assert_failure(self, result, types.Failure_ActionCancelled,
                       "Arbitrary contract data signing disabled by policy")
