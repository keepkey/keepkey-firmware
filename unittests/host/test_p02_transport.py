"""P02 wire regressions; run with the pinned python-keepkey tests on PYTHONPATH."""
import common
from keepkeylib import messages_pb2 as proto
from keepkeylib import types_pb2 as types


class TestP02Transport(common.KeepKeyTest):
    def assert_terminal_rejection(self, request, expected_prompt, wrong_reply):
        self.setup_mnemonic_pin_passphrase()
        self.client.clear_session()
        response = self.client.call_raw(request)
        self.assertIsInstance(response, expected_prompt)
        response = self.client.call_raw(wrong_reply)
        self.assertIsInstance(response, proto.Failure)
        self.assertEqual(response.code, types.Failure_UnexpectedMessage)
        # An unwinding handler must not enqueue another Failure or Success.
        response = self.client.call_raw(proto.Initialize())
        self.assertIsInstance(response, proto.Features)

    def test_button_wait_rejects_normal_request(self):
        self.assert_terminal_rejection(
            proto.Ping(button_protection=True), proto.ButtonRequest,
            proto.GetFeatures())

    def assert_dice_entropy_hidden(self, dice_only):
        self.client.wipe_device()
        response = self.client.call_raw(proto.ResetDevice(
            strength=128, dice_entropy=True, dice_only=dice_only))
        self.assertIsInstance(response, proto.ButtonRequest)
        self.assertEqual(response.code, types.ButtonRequest_DiceRoll)
        state = self.client.debug._call(proto.DebugLinkGetState())
        self.assertEqual([], state.ListFields())
        self.assertIsInstance(self.client.call_raw(proto.Cancel()), proto.Failure)
        self.assertIsInstance(self.client.call_raw(proto.Initialize()), proto.Features)

        # Control: DebugLink remains functional for ordinary reset diagnostics.
        response = self.client.call_raw(proto.ResetDevice(strength=128))
        self.assertIsInstance(response, proto.EntropyRequest)
        state = self.client.debug._call(proto.DebugLinkGetState())
        self.assertTrue(state.HasField('reset_entropy'))
        self.assertEqual(len(state.reset_entropy), 32)
        self.assertIsInstance(self.client.call_raw(proto.Cancel()), proto.Failure)

    def test_dice_mixed_consent_does_not_expose_raw_entropy(self):
        self.assert_dice_entropy_hidden(False)

    def test_dice_only_consent_does_not_expose_raw_entropy(self):
        self.assert_dice_entropy_hidden(True)

    def test_mixed_entropy_pages_remain_private_and_cancel_clears_state(self):
        self.client.wipe_device()
        response = self.client.call_raw(proto.ResetDevice(
            strength=256, dice_entropy=True))
        # Consent followed by two actual entropy display subpages, the phase
        # the old consent-only regression never reached.
        for page in range(3):
            self.assertIsInstance(response, proto.ButtonRequest)
            self.assertEqual(response.code, types.ButtonRequest_DiceRoll)
            state = self.client.debug._call(proto.DebugLinkGetState())
            self.assertEqual([], state.ListFields())
            if page < 2:
                self.client.debug.press_yes()
                response = self.client.call_raw(proto.ButtonAck())
        self.assertIsInstance(self.client.call_raw(proto.Cancel()), proto.Failure)
        self.assertIsInstance(self.client.call_raw(proto.Initialize()), proto.Features)
        state = self.client.debug._call(proto.DebugLinkGetState())
        self.assertFalse(state.HasField('mnemonic'))
        self.assertEqual('', state.reset_word)
        self.assertEqual(b'', state.dice_digest)
        self.assertEqual(bytes(32), state.reset_entropy)
