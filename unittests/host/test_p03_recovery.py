"""Block 3 wire checks for on-device BIP-85 disclosure."""

import common
from keepkeylib import messages_pb2 as proto


class TestP03Recovery(common.KeepKeyTest):
    def test_omitted_wordlist_flag_still_rejects_non_bip39_word(self):
        # The wire flag is ignored: a host that omits enforce_wordlist (the
        # proto default, false) must not be able to store a non-BIP-39 seed.
        response = self.client.call_raw(proto.RecoveryDevice(
            word_count=12, pin_protection=False,
            passphrase_protection=False, use_character_cipher=True))
        self.assertIsInstance(response, proto.ButtonRequest)
        self.client.debug.press_yes()
        response = self.client.call_raw(proto.ButtonAck())
        for letter in 'zzzz':
            self.assertIsInstance(response, proto.CharacterRequest)
            cipher = self.client.debug.read_recovery_cipher()
            response = self.client.call_raw(proto.CharacterAck(
                character=cipher[ord(letter) - ord('a')]))
        response = self.client.call_raw(proto.CharacterAck(character=' '))
        self.assertIsInstance(response, proto.Failure)
        self.assertIn('Word not found', response.message)
        self.client.init_device()
        self.assertFalse(self.client.features.initialized)

    def test_enforced_wordlist_rejects_non_bip39_word(self):
        response = self.client.call_raw(proto.RecoveryDevice(
            word_count=12, pin_protection=False,
            passphrase_protection=False, enforce_wordlist=True,
            use_character_cipher=True))
        self.assertIsInstance(response, proto.ButtonRequest)
        self.client.debug.press_yes()
        response = self.client.call_raw(proto.ButtonAck())
        for letter in 'zzzz':
            self.assertIsInstance(response, proto.CharacterRequest)
            cipher = self.client.debug.read_recovery_cipher()
            response = self.client.call_raw(proto.CharacterAck(
                character=cipher[ord(letter) - ord('a')]))
        response = self.client.call_raw(proto.CharacterAck(character=' '))
        self.assertIsInstance(response, proto.Failure)
        self.assertIn('Word not found', response.message)

    def test_bip85_18_word_flow_completes(self):
        self.setup_mnemonic_allallall()
        response = self.client.call(proto.GetBip85Mnemonic(word_count=18, index=0))
        self.assertIsInstance(response, proto.Success)

    def test_bip85_24_word_and_second_index_flows_complete(self):
        self.setup_mnemonic_allallall()
        for words, index in ((24, 0), (12, 1)):
            response = self.client.call(
                proto.GetBip85Mnemonic(word_count=words, index=index))
            self.assertIsInstance(response, proto.Success)

    def test_bip85_invalid_parameters_fail_before_private_display(self):
        self.setup_mnemonic_allallall()
        for words, index in ((15, 0), (12, 0x80000000)):
            response = self.client.call_raw(
                proto.GetBip85Mnemonic(word_count=words, index=index))
            self.assertIsInstance(response, proto.Failure)
            state = self.client.debug._call(proto.DebugLinkGetState())
            self.assertTrue(state.HasField('layout'))

    def test_bip85_child_words_stay_off_debuglink_through_completion(self):
        self.setup_mnemonic_allallall()
        home_layout = self.client.debug._call(proto.DebugLinkGetState()).layout
        response = self.client.call_raw(
            proto.GetBip85Mnemonic(word_count=12, index=0))
        self.assertIsInstance(response, proto.ButtonRequest)
        self.client.debug.press_yes()
        response = self.client.call_raw(proto.ButtonAck())

        # This is the first child-word page, before its ButtonAck.
        self.assertIsInstance(response, proto.ButtonRequest)
        self.assertEqual(
            [], self.client.debug._call(proto.DebugLinkGetState()).ListFields())
        pages = 1
        while isinstance(response, proto.ButtonRequest):
            self.assertLess(pages, 10)
            self.client.debug.press_yes()
            response = self.client.call_raw(proto.ButtonAck())
            if isinstance(response, proto.ButtonRequest):
                pages += 1
                self.assertEqual(
                    [], self.client.debug._call(
                        proto.DebugLinkGetState()).ListFields())

        self.assertGreater(pages, 1)
        self.assertIsInstance(response, proto.Success)
        state = self.client.debug._call(proto.DebugLinkGetState())
        self.assertTrue(state.HasField('layout'))
        self.assertEqual(home_layout, state.layout)

    def test_bip85_cancel_clears_private_page_before_debug_resumes(self):
        self.setup_mnemonic_allallall()
        home_layout = self.client.debug._call(proto.DebugLinkGetState()).layout
        response = self.client.call_raw(
            proto.GetBip85Mnemonic(word_count=24, index=1))
        self.assertIsInstance(response, proto.ButtonRequest)
        self.client.debug.press_yes()
        response = self.client.call_raw(proto.ButtonAck())
        self.assertIsInstance(response, proto.ButtonRequest)
        self.assertEqual(
            [], self.client.debug._call(proto.DebugLinkGetState()).ListFields())

        self.client.debug.press_no()
        response = self.client.call_raw(proto.ButtonAck())
        self.assertIsInstance(response, proto.Failure)
        state = self.client.debug._call(proto.DebugLinkGetState())
        self.assertTrue(state.HasField('layout'))
        self.assertEqual(home_layout, state.layout)
