#include "gtest/gtest.h"

#include <cstring>

extern "C" {
#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/timer.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/firmware/reset.h"
#include "keepkey/transport/interface.h"
#include "keepkey/emulator/setup.h"
#include "trezor/crypto/bip39.h"
#include "trezor/crypto/curves.h"
#include "trezor/crypto/memzero.h"
}

namespace {
const char kMnemonic[] = "all all all all all all all all all all all all";
const char kHidden[] = "hidden wallet";

class PassphraseTransition : public ::testing::Test {
 protected:
  void SetUp() override {
    static bool initialized = false;
    if (!initialized) {
      setup();
      if (layout_get_canvas() == nullptr) {
        timer_init();
        layout_init(display_canvas_init());
      }
      storage_init();
      initialized = true;
    }
    LoadDevice load = {};
    load.has_mnemonic = true;
    std::strcpy(load.mnemonic, kMnemonic);
    storage_loadDevice(&load);
    storage_commit();
  }

  void TearDown() override {
    setup_abort();
    session_clear(true);
  }

  void ExpectWallet(const char* passphrase, const HDNode& actual) {
    uint8_t seed[64] = {};
    HDNode expected = {};
    mnemonic_to_seed(kMnemonic, passphrase, seed, nullptr);
    ASSERT_EQ(1,
              hdnode_from_seed(seed, sizeof(seed), SECP256K1_NAME, &expected));
    EXPECT_EQ(0, std::memcmp(actual.private_key, expected.private_key, 32));
    EXPECT_EQ(0, std::memcmp(actual.chain_code, expected.chain_code, 32));
    memzero(seed, sizeof(seed));
    memzero(&expected, sizeof(expected));
  }
};

TEST_F(PassphraseTransition, DisableSelectsPlainWallet) {
  storage_setPassphraseProtected(true);
  session_cachePassphrase(kHidden);
  HDNode node = {};
  ASSERT_TRUE(storage_getRootNode(SECP256K1_NAME, true, &node));
  ExpectWallet(kHidden, node);

  storage_setPassphraseProtected(false);
  EXPECT_FALSE(session_isPassphraseCached());
  ASSERT_TRUE(storage_getRootNode(SECP256K1_NAME, true, &node));
  ExpectWallet("", node);
  memzero(&node, sizeof(node));
}

TEST_F(PassphraseTransition, EnableSelectsNewlyConfirmedWallet) {
  HDNode node = {};
  ASSERT_TRUE(storage_getRootNode(SECP256K1_NAME, true, &node));
  ExpectWallet("", node);

  storage_setPassphraseProtected(true);
  EXPECT_FALSE(session_isPassphraseCached());
  session_cachePassphrase(kHidden);
  ASSERT_TRUE(storage_getRootNode(SECP256K1_NAME, true, &node));
  ExpectWallet(kHidden, node);
  memzero(&node, sizeof(node));
}

TEST_F(PassphraseTransition, UnchangedSettingPreservesConfirmedPassphrase) {
  storage_setPassphraseProtected(true);
  session_cachePassphrase(kHidden);
  HDNode node = {};
  ASSERT_TRUE(storage_getRootNode(SECP256K1_NAME, true, &node));
  storage_setPassphraseProtected(true);
  EXPECT_TRUE(session_isPassphraseCached());
  ASSERT_TRUE(storage_getRootNode(SECP256K1_NAME, true, &node));
  ExpectWallet(kHidden, node);
  memzero(&node, sizeof(node));
}
TEST_F(PassphraseTransition, SettingChangePreservesPinAuthorization) {
  storage_setPin("1234");
  ASSERT_TRUE(session_isPinCached());
  storage_setPassphraseProtected(true);
  EXPECT_TRUE(session_isPinCached());
  storage_setPassphraseProtected(false);
  EXPECT_TRUE(session_isPinCached());
}

TEST_F(PassphraseTransition, SettingChangePreservesStagedSetup) {
  ASSERT_TRUE(setup_stage(true, "english", "staged label", 0, 0, false));
  setup_arm(SETUP_RESET);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RESET));
  storage_setPassphraseProtected(true);
  EXPECT_TRUE(setup_isArmedAs(SETUP_RESET));
}

TEST_F(PassphraseTransition, StagingIsInertAndForeignCommitAborts) {
  storage_setLabel("original");
  storage_commit();
  ASSERT_FALSE(storage_getPassphraseProtected());
  ASSERT_FALSE(storage_hasPin());

  ASSERT_TRUE(setup_stage(true, "english", "pending", 0, 37, false));
  ASSERT_TRUE(setup_stagePin(false));
  setup_arm(SETUP_RESET);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RESET));
  EXPECT_STREQ("original", storage_getLabel());
  EXPECT_FALSE(storage_getPassphraseProtected());
  EXPECT_FALSE(storage_hasPin());

  storage_commit();

  EXPECT_FALSE(setup_isArmed());
  EXPECT_STREQ("original", storage_getLabel());
  EXPECT_FALSE(storage_getPassphraseProtected());
  EXPECT_FALSE(storage_hasPin());
  EXPECT_FALSE(setup_stagePin(false));
  setup_arm(SETUP_RESET);
  EXPECT_FALSE(setup_isArmed());
}

}  // namespace
