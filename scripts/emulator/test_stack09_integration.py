"""Combined 8/9 audit: numeric account slots must not alias other slots."""
import os

import common
from keepkeylib import messages_pb2 as proto
from keepkeylib import types_pb2 as types


class TestAuthenticatorSlotIntegration(common.KeepKeyTest):
    def test_account_slot_text_cannot_wrap_or_ignore_suffixes(self):
        variant = os.environ.get("KK_FIRMWARE_VARIANT")
        self.assertIn(variant, ("full", "bitcoin-only"))
        self.assertIn(self.client.features.firmware_variant,
                      ("EmulatorBTC", "KeepKeyBTC") if variant == "bitcoin-only"
                      else ("Emulator", "KeepKey"))
        self.setup_mnemonic_nopin_nopassphrase()
        self.client.call(proto.Ping(message='\x19wipeAuthdata:'))
        self.client.call(proto.Ping(message=(
            '\x15initializeAuth:example:alice:'
            'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP')))
        valid = '\x17getAccount:0'
        self.assertEqual(self.client.call(proto.Ping(message=valid)).message,
                         'example:alice')
        # Slot parsing is unit-tested (Authenticator.AccountSlotRejects...);
        # this pins the wire mapping of a rejected slot.
        response = self.client.call_raw(proto.Ping(message='\x17getAccount:256'))
        self.assertIsInstance(response, proto.Failure)
        self.assertEqual(response.code, types.Failure_ActionCancelled)
        self.assertEqual(response.message, 'Slot request out of range')
        last = self.client.call_raw(proto.Ping(message='\x17getAccount:9'))
        self.assertIsInstance(last, proto.Failure)
        self.assertEqual(last.message, 'Account not found')
