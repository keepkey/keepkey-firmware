"""Hive consent and validation through the disposable emulator transport."""
import os
import struct

import common
from keepkeylib import messages_pb2 as proto
from keepkeylib import messages_hive_pb2 as hive
from keepkeylib import types_pb2 as types

MAINNET = bytes.fromhex("beeab0de" + "00" * 28)


def requests():
    common_fields = dict(ref_block_num=1, ref_block_prefix=2, expiration=3)
    owner = [0x80000030, 0x8000000d, 0x80000000, 0x80000000, 0x80000000]
    active = owner[:]
    active[2] += 1
    return [
        (hive.HiveSignTx(address_n=active, **dict(common_fields, **{
            "from": "alice", "to": "bob", "amount": 1000})), hive.HiveSignedTx),
        (hive.HiveSignAccountCreate(address_n=owner, creator="alice",
                                   new_account_name="bob", **common_fields),
         hive.HiveSignedAccountCreate),
        (hive.HiveSignAccountUpdate(address_n=owner, account="alice", **common_fields),
         hive.HiveSignedAccountUpdate),
    ]


class TestStack12Hive(common.KeepKeyTest):
    def setUp(self):
        super().setUp()
        variant = os.environ.get("KK_FIRMWARE_VARIANT")
        self.assertIn(variant, ("full", "bitcoin-only"))
        self.assertIn(self.client.features.firmware_variant,
                      ("EmulatorBTC", "KeepKeyBTC") if variant == "bitcoin-only"
                      else ("Emulator", "KeepKey"))
        if variant == "bitcoin-only":
            self.skipTest("Hive signing is unavailable in bitcoin-only firmware")
        self.requires_release_capability("hive-release-review")
        self.setup_mnemonic_nopin_nopassphrase()

    def walk(self, request, cancel=None):
        self.screens = []
        response = self.client.call_raw(request)
        for index in range(100):
            if not isinstance(response, proto.ButtonRequest):
                return response
            self.screens.append(self.client.debug.read_confirm_text())
            if index == cancel:
                self.client.debug.press_no()
            else:
                self.client.debug.press_yes()
            response = self.client.call_raw(proto.ButtonAck())
        self.fail("confirmation did not terminate")

    def refused(self, request):
        response = self.client.call_raw(request)
        if isinstance(response, proto.ButtonRequest):
            self.client.call_raw(proto.Cancel())
        self.assertIsInstance(response, proto.Failure)
        self.assertEqual(response.code, types.Failure_SyntaxError)

    def test_all_operations_reject_malformed_domains_before_consent(self):
        for request, response_type in requests():
            for size in range(32):
                request.chain_id = b"\xa5" * size
                self.refused(request)
            request.ClearField("chain_id")
            self.assertIsInstance(self.walk(request), response_type)

    def test_invalid_amounts_and_labels_before_consent(self):
        for request, response_type in requests():
            fields = [f for f in ("from", "to", "creator", "new_account_name", "account")
                      if f in request.DESCRIPTOR.fields_by_name]
            for field in fields:
                saved = getattr(request, field)
                for name in ("", "ab", "Alice", "alice\nbob", "alice bob", "@alice",
                             "alice-", "alice..bob", "a.bob", "alice.1bob"):
                    setattr(request, field, name)
                    self.refused(request)
                setattr(request, field, saved)
            field = "amount" if isinstance(request, hive.HiveSignTx) else "fee_amount"
            if field in request.DESCRIPTOR.fields_by_name:
                saved = getattr(request, field)
                amounts = [1 << 63, (1 << 64) - 1]
                if field == "amount":
                    amounts.append(0)
                for amount in amounts:
                    setattr(request, field, amount)
                    self.refused(request)
                setattr(request, field, saved if field == "amount" else 3000)
            self.assertIsInstance(self.walk(request), response_type)

    def test_custom_domain_is_disclosed_and_cancellable(self):
        domain = bytes(range(32))
        for request, response_type in requests():
            baseline = self.walk(request)
            self.assertIsInstance(baseline, response_type)
            self.assertFalse(any("chain" in title.lower() for title, _ in self.screens))
            request.chain_id = MAINNET
            explicit = self.walk(request)
            self.assertEqual(baseline.signature, explicit.signature)
            request.chain_id = domain
            custom = self.walk(request)
            self.assertIsInstance(custom, response_type)
            pages = [body for title, body in self.screens if title.startswith("Custom Hive chain")]
            self.assertEqual("".join(pages), domain.hex())
            self.assertEqual(custom.serialized_tx, baseline.serialized_tx)
            self.assertNotEqual(custom.signature, baseline.signature)
            cancelled = self.walk(request, cancel=0)
            self.assertIsInstance(cancelled, proto.Failure)
            self.assertEqual(cancelled.code, types.Failure_ActionCancelled)
            self.assertIsInstance(self.walk(request), response_type)

    def test_complete_memo_and_each_consent_cancellation(self):
        request, response_type = requests()[0]
        request.memo = "m" * 419 + "END-OF-MEMO-123456789"
        self.assertEqual(len(request.memo), 440)
        signed = self.walk(request)
        self.assertIsInstance(signed, response_type)
        pages = [body for title, body in self.screens if title.startswith("Memo")]
        self.assertGreater(len(pages), 1)
        self.assertEqual("".join(pages), request.memo)
        expected = (struct.pack("<HII", 1, 2, 3) + b"\x01\x02\x05alice\x03bob" +
                    struct.pack("<qB", 1000, 3) + b"STEEM\x00\x00" +
                    b"\xb8\x03" + request.memo.encode() + b"\x00")
        self.assertEqual(signed.serialized_tx, expected)
        count = len(self.screens)
        for index in range(count):
            result = self.walk(request, cancel=index)
            self.assertIsInstance(result, proto.Failure)
            self.assertEqual(result.code, types.Failure_ActionCancelled)
        retry = self.walk(request)
        self.assertEqual(signed.signature, retry.signature)

    def test_account_authorities_ignore_host_keys_and_cancel(self):
        for request, response_type in requests()[1:]:
            baseline = self.walk(request)
            self.assertIsInstance(baseline, response_type)
            baseline_screens = list(self.screens)
            count = len(self.screens)
            for field in request.DESCRIPTOR.fields_by_name:
                if field.endswith("_key"):
                    setattr(request, field, "HOST CONTROLLED KEY")
            signed = self.walk(request)
            self.assertEqual(signed.serialized_tx, baseline.serialized_tx)
            self.assertEqual(signed.signature, baseline.signature)
            self.assertEqual(self.screens, baseline_screens)
            self.assertTrue(any("Owner Key" in title for title, _ in self.screens))
            for index in range(count):
                cancelled = self.walk(request, cancel=index)
                self.assertIsInstance(cancelled, proto.Failure)
                self.assertEqual(cancelled.code, types.Failure_ActionCancelled)
            self.assertEqual(self.walk(request).signature, baseline.signature)
