/* Setup-ceremony transaction tests — GH #429.
 *
 * The defect: a host could send
 *   ResetDevice -> RecoveryDevice{pin_protection:false} -> Cancel -> EntropyAck
 * and the seed committed with the PIN and passphrase the user had just chosen
 * on-device silently discarded. Steps 2-4 needed no button press, because
 * recovery_cipher_init() wrote host-chosen settings to shadow_config before its
 * first confirm, and nothing disarmed the reset that was already in flight.
 *
 * These tests exercise the two invariants the fix is built on rather than the
 * one known message sequence:
 *   I1  no staged setting reaches storage before the ceremony's single commit
 *   I2  an armed ceremony cannot outlive a foreign persist
 *
 * None of these call confirm(), so the suite runs in the fast filtered mode:
 *   ./firmware-unit --gtest_filter=SetupCeremony.*
 *
 * COVERAGE GAP, STATED DELIBERATELY. These cover the ceremony STATE MACHINE
 * only. The two invariants the fix actually rests on —
 *   I1  no staged setting is observable through storage before commit
 *   I2  a foreign storage_commit() disarms an armed ceremony
 * — cannot be asserted here: firmware-unit has no flash emulation, and no test
 * in this tree calls storage_init(), storage_commit() or storage_setLabel().
 * Attempting it segfaults. So the parts of #429 that touch storage are NOT
 * covered by automated tests and must be proven on hardware or in an emulator
 * run with real flash. Do not read a green run here as #429 being verified.
 */

#include "gtest/gtest.h"

#include <string>

extern "C" {
#include "keepkey/board/keepkey_board.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/recovery_cipher.h"
#include "keepkey/firmware/reset.h"
#include "trezor/crypto/bip39.h"
}

namespace {

// A ceremony left armed by one test must not leak into the next.
class SetupCeremony : public ::testing::Test {
 protected:
  void SetUp() override {
    // setup_require() reports a mismatch through fsm_sendFailure(), which
    // asserts on MessagesMap. Same reason usb_rx.cpp calls this.
    static bool fsm_ready = false;
    if (!fsm_ready) {
      fsm_init();
      fsm_ready = true;
    }
    setup_abort();
  }

  void TearDown() override { setup_abort(); }
};

// #429 step 2, directly: a second ceremony cannot start on top of an armed one.
TEST_F(SetupCeremony, StageRefusesWhileArmed) {
  ASSERT_TRUE(setup_stage(false, "english", "first", 0, 0, false));
  setup_arm(SETUP_RESET);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RESET));

  EXPECT_FALSE(setup_stage(true, "english", "second", 0, 0, false))
      << "a RecoveryDevice must not be able to restage over an armed reset";
  EXPECT_TRUE(setup_isArmedAs(SETUP_RESET))
      << "the refused stage must leave the original ceremony intact";
}

// Every abort path shares one implementation, so it must tolerate being
// reached from any state, including twice.
TEST_F(SetupCeremony, AbortIsIdempotent) {
  setup_abort();
  EXPECT_FALSE(setup_isArmed());

  ASSERT_TRUE(setup_stage(false, "english", "x", 0, 0, false));
  setup_abort();
  setup_abort();
  EXPECT_FALSE(setup_isArmed());

  ASSERT_TRUE(setup_stage(false, "english", "y", 0, 0, false));
  setup_arm(SETUP_RECOVERY);
  setup_abort();
  setup_abort();
  EXPECT_FALSE(setup_isArmed());
  EXPECT_FALSE(setup_isArmedAs(SETUP_RECOVERY));
}

// BIP39 owns a static output buffer.  Once setup is abandoned, retaining the
// generated sentence there is retaining an otherwise unowned device seed.
TEST_F(SetupCeremony, AbortScrubsGeneratedMnemonic) {
  const uint8_t entropy[16] = {};
  const char* generated = mnemonic_from_data(entropy, sizeof(entropy));
  ASSERT_NE(nullptr, generated);
  ASSERT_NE('\0', generated[0]);

  setup_abort();

  for (size_t i = 0; i < 24u * 10u; ++i) {
    EXPECT_EQ('\0', generated[i]);
  }
}

// setup_require() is the gate every continuation message uses. A mismatch must
// abort rather than fall through.
TEST_F(SetupCeremony, RequireRejectsTheWrongKind) {
  ASSERT_TRUE(setup_stage(false, "english", "z", 0, 0, false));
  setup_arm(SETUP_RESET);

  EXPECT_FALSE(setup_require(SETUP_RECOVERY, "wrong kind"));
  EXPECT_FALSE(setup_isArmed())
      << "a mismatched continuation must abort the ceremony, not ignore it";
}

// Nothing is armed before arm(), so every early return in a ceremony's setup
// phase is inert by construction rather than by remembering to call abort.
TEST_F(SetupCeremony, StagedButNotArmedIsInert) {
  ASSERT_TRUE(setup_stage(true, "english", "inert", 0, 0, false));
  EXPECT_FALSE(setup_isArmed());
  EXPECT_FALSE(setup_require(SETUP_RESET, "not armed"));

  // A later ceremony may stage freely over an un-armed one.
  EXPECT_TRUE(setup_stage(false, "english", "second", 0, 0, false));
}

// The permutation coverage the release gate asks for: the orderings a host can
// actually drive, not just the one reported sequence. In every case the device
// must end with nothing armed and nothing half-applied.
TEST_F(SetupCeremony, MessagePermutationsLeaveNothingArmed) {
  struct Step {
    const char* name;
    SetupKind kind;
  };
  const Step kinds[] = {{"reset", SETUP_RESET}, {"recovery", SETUP_RECOVERY}};

  for (const Step& first : kinds) {
    for (const Step& second : kinds) {
      SCOPED_TRACE(std::string(first.name) + " then " + second.name);

      ASSERT_TRUE(setup_stage(false, "english", "a", 0, 0, false));
      setup_arm(first.kind);

      // A second ceremony start must be refused while the first is armed.
      EXPECT_FALSE(setup_stage(true, "english", "b", 0, 0, false));
      EXPECT_TRUE(setup_isArmedAs(first.kind));

      // A continuation for the other kind must abort rather than proceed.
      if (first.kind != second.kind) {
        EXPECT_FALSE(setup_require(second.kind, "mismatch"));
        EXPECT_FALSE(setup_isArmed());
      } else {
        setup_abort();
        EXPECT_FALSE(setup_isArmed());
      }
    }
  }
}

TEST_F(SetupCeremony, AbortWipesBip39MnemonicAndRecoveryFragments) {
  const uint8_t entropy[16] = {0};
  const char* mnemonic = mnemonic_from_data(entropy, sizeof(entropy));
  ASSERT_NE(nullptr, mnemonic);
  ASSERT_NE('\0', mnemonic[0]);
  recovery_cipher_test_set_word_fragments();
  ASSERT_FALSE(recovery_cipher_test_word_fragments_are_zero());

  setup_abort();

  EXPECT_EQ('\0', mnemonic[0]);
  EXPECT_TRUE(recovery_cipher_test_word_fragments_are_zero());
  EXPECT_FALSE(setup_isArmed());
}

TEST_F(SetupCeremony, InvalidRecoveryWordCountDisarmsCeremony) {
  ASSERT_TRUE(setup_stage(false, "english", "recovery", 0, 0, false));
  setup_arm(SETUP_RECOVERY);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));

  recovery_cipher_finalize();

  EXPECT_FALSE(setup_isArmed());
  EXPECT_TRUE(recovery_cipher_test_word_fragments_are_zero());
}

}  // namespace
