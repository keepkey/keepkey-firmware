# Gate-3 evidence for PR #373: capture the ApplyPolicies confirm screen for
# AdvancedMode, which now states the session lifetime. Measured at 3 lines /
# 1 page with zero headroom, so the actual bitmap is the proof, not the maths.
from __future__ import print_function
import unittest
import common


class TestGate3AdvancedMode(common.KeepKeyTest):
    def test_advancedmode_confirm_screen(self):
        self.setup_mnemonic_allallall()
        self._drop_setup_screenshots()
        self.client.apply_policy('AdvancedMode', 1)
        print("captured to", getattr(self.client, 'screenshot_dir', '?'))


if __name__ == '__main__':
    unittest.main()
