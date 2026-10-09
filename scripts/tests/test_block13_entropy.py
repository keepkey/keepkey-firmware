"""Block13 entropy contract against a disposable UDP emulator only."""
import os
from pathlib import Path
import sys
import struct

if os.environ.get("KK_FORCE_UDP") != "1":
    raise RuntimeError("This test wipes its emulator; set KK_FORCE_UDP=1")
ROOT = Path(__file__).resolve().parents[2]
PYTHON = ROOT / "deps" / "python-keepkey"
sys.path[:0] = [str(PYTHON / "tests"), str(PYTHON)]
import common
from keepkeylib import messages_pb2 as proto
from keepkeylib import types_pb2 as types


class TestBlock13Entropy(common.KeepKeyTest):
    def free_sample(self, size, expected=None):
        response = self.client.call_raw(proto.GetEntropy(size=size))
        if isinstance(response, proto.ButtonRequest):
            self.client.call_raw(proto.Cancel())
        self.assertIsInstance(response, proto.Entropy)
        self.assertEqual(len(response.entropy), min(size, 1024) if expected is None else expected)

    def refused_sample(self):
        response = self.client.call_raw(proto.GetEntropy(size=1))
        if isinstance(response, proto.ButtonRequest):
            self.client.call_raw(proto.Cancel())
        self.assertIsInstance(response, proto.ButtonRequest)
        self.assertEqual(response.code, types.ButtonRequest_GetEntropy)

    def test_byte_budget_clamps_sizes_and_survives_session_changes(self):
        # Zero is not progress or a charge; requests larger than the wire
        # output capacity consume the 1024 bytes actually returned.
        self.free_sample(0)
        self.free_sample(0xffffffff, 1024)
        self.client.init_device()
        self.client.clear_session()
        for _ in range(62):
            self.free_sample(1024)
        self.free_sample(1023)
        self.free_sample(0)
        self.free_sample(1)
        # Exactly 65536 bytes have now been returned, across 67 requests.
        self.refused_sample()
        self.free_sample(0)
        response = self.client.call_raw(proto.WipeDevice())
        self.assertIsInstance(response, proto.ButtonRequest)
        self.client.call_raw(proto.Cancel())
        self.refused_sample()
        self.client.init_device()
        self.client.clear_session()
        self.refused_sample()
        with self.client:
            self.client.set_expected_responses([
                proto.ButtonRequest(code=types.ButtonRequest_GetEntropy),
                proto.Entropy(),
            ])
            self.assertEqual(len(self.client.get_entropy(1024)), 1024)
        self.refused_sample()
        self.client.wipe_device()
        self.free_sample(1024)

    def test_missing_required_size_fails_decode_without_spending_budget(self):
        # Bypass client protobuf initialization checks; this is the real empty
        # GetEntropy frame a hostile host can send.
        self.client.transport._write(b"##" + struct.pack(">HL", 9, 0), None)
        response = self.client.transport.read_blocking()
        self.assertIsInstance(response, proto.Failure)
        self.assertEqual(response.code, types.Failure_UnexpectedMessage)
        for _ in range(64):
            self.free_sample(1024)
        self.refused_sample()

    def test_initialized_locked_device_keeps_confirmation_and_budget(self):
        self.setup_mnemonic_pin_passphrase()
        self.client.clear_session()
        self.refused_sample()
        with self.client:
            self.client.set_expected_responses([
                proto.ButtonRequest(code=types.ButtonRequest_GetEntropy),
                proto.Entropy(),
            ])
            self.assertEqual(len(self.client.get_entropy(1024)), 1024)
        self.client.wipe_device()
        for _ in range(64):
            self.free_sample(1024)
        self.refused_sample()

    def test_recovery_refuses_entropy_preserves_cipher_and_budget(self):
        response = self.client.call_raw(proto.RecoveryDevice(
            word_count=12, passphrase_protection=False, pin_protection=False,
            label="entropy guard", language="english", enforce_wordlist=True,
            use_character_cipher=True,
        ))
        self.assertIsInstance(response, proto.ButtonRequest)
        self.client.debug.press_yes()
        response = self.client.call_raw(proto.ButtonAck())
        self.assertIsInstance(response, proto.CharacterRequest)
        before = self.client.debug.read_recovery_state()
        response = self.client.call_raw(proto.GetEntropy(size=1024))
        if isinstance(response, proto.ButtonRequest):
            self.client.call_raw(proto.Cancel())
        self.assertIsInstance(response, proto.Failure)
        self.assertEqual(response.code, types.Failure_UnexpectedMessage)
        after = self.client.debug.read_recovery_state()
        self.assertEqual(before["cipher"], after["cipher"])
        self.assertEqual(before["auto_completed_word"], after["auto_completed_word"])
        # Pixel preservation is covered by the native fixed-clock test;
        # live emulator layout includes a blinking cursor.
        # The original ceremony still accepts a real cipher character.
        response = self.client.call_raw(proto.CharacterAck(character="a"))
        self.assertIsInstance(response, proto.CharacterRequest)
        self.client.call_raw(proto.Cancel())
        for _ in range(64):
            self.free_sample(1024)
        self.refused_sample()

    def test_reset_refuses_entropy_without_consuming_pending_ack(self):
        response = self.client.call_raw(proto.ResetDevice(
            strength=128, display_random=False, passphrase_protection=False,
            pin_protection=False, label="entropy guard", language="english",
        ))
        while isinstance(response, proto.ButtonRequest):
            self.client.debug.press_yes()
            response = self.client.call_raw(proto.ButtonAck())
        self.assertIsInstance(response, proto.EntropyRequest)
        response = self.client.call_raw(proto.GetEntropy(size=1024))
        if isinstance(response, proto.ButtonRequest):
            self.client.call_raw(proto.Cancel())
        self.assertIsInstance(response, proto.Failure)
        self.assertEqual(response.code, types.Failure_UnexpectedMessage)
        # A valid setup continuation is still outstanding, not silently reset.
        response = self.client.call_raw(proto.EntropyAck(entropy=b"\x73" * 32))
        self.assertIsInstance(response, proto.ButtonRequest)
        self.client.call_raw(proto.Cancel())
        for _ in range(64):
            self.free_sample(1024)
        self.refused_sample()
