#include "gtest/gtest.h"

#include <cstring>
#include <cstdlib>

extern "C" {
#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/keepkey_flash.h"
#include "keepkey/board/memory.h"
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

static bool corrupt_commit_tail;
static unsigned payload_writes;
extern "C" bool emulator_flash_write_completed(Allocation group,
                                               uint32_t offset, uint32_t len) {
  if (offset == STORAGE_MAGIC_LEN && len > 2564) {
    ++payload_writes;
    if (corrupt_commit_tail) {
      reinterpret_cast<uint8_t*>(flash_write_helper(group))[2568] ^= 1;
      corrupt_commit_tail = false;
    }
  }
  return true;
}

void kk_test_board_init(void);

namespace {
const char kMnemonic[] = "all all all all all all all all all all all all";
const char kHidden[] = "hidden wallet";

class PassphraseTransition : public ::testing::Test {
 protected:
  void SetUp() override {
    static bool initialized = false;
    if (!initialized) {
      setup();
      kk_test_board_init();
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

TEST_F(PassphraseTransition, FreshWalletSurvivesCommitAndReload) {
  storage_wipe();
  LoadDevice load = {};
  load.has_mnemonic = true;
  std::strcpy(load.mnemonic, kMnemonic);
  storage_loadDevice(&load);
  storage_commit();

  storage_init();
  ASSERT_TRUE(storage_hasMnemonic());
  EXPECT_STREQ(kMnemonic, storage_getMnemonic());
}

TEST_F(PassphraseTransition, CommitDetectsCorruptionOfFinalSecretByte) {
  payload_writes = 0;
  corrupt_commit_tail = true;
  storage_commit();
  EXPECT_EQ(2u, payload_writes) << "the corrupted last byte must force a retry";
  storage_init();
  ASSERT_TRUE(storage_hasMnemonic());
  EXPECT_STREQ(kMnemonic, storage_getMnemonic());
}

TEST_F(PassphraseTransition, ZeroCrcIsAValidCommittedRecord) {
  // The U2F counter is a legitimate caller-controlled field. Solve its 32
  // bits against the CRC of an otherwise fixed, already committed V17 record.
  // This exercises the full commit path rather than mocking calc_crc32().
  alignas(uint32_t) uint8_t record[2572] = {};
  bool found = false;
  for (int sector = FLASH_STORAGE1; sector <= FLASH_STORAGE3; ++sector) {
    const auto* flash = reinterpret_cast<const uint8_t*>(
        flash_write_helper(static_cast<Allocation>(sector)));
    if (std::memcmp(flash, STORAGE_MAGIC_STR, STORAGE_MAGIC_LEN) == 0) {
      std::memcpy(record, flash, sizeof(record));
      found = true;
      break;
    }
  }
  ASSERT_TRUE(found);

  // Metadata occupies 44 bytes; V17's U2F counter is at public-data offset
  // 401. Keep the rest of the serialized wallet byte-for-byte unchanged.
  constexpr size_t kCounterOffset = 44 + 401;
  auto checksum = [&](uint32_t counter) {
    for (int byte = 0; byte < 4; ++byte)
      record[kCounterOffset + byte] =
          static_cast<uint8_t>(counter >> (8 * byte));
    return calc_crc32(record, sizeof(record) / sizeof(uint32_t));
  };
  const uint32_t baseline = checksum(0);
  uint32_t pivots[32] = {}, masks[32] = {};
  for (int bit = 0; bit < 32; ++bit) {
    uint32_t delta = checksum(uint32_t{1} << bit) ^ baseline;
    uint32_t mask = uint32_t{1} << bit;
    for (int row = 31; row >= 0; --row) {
      if (!(delta & (uint32_t{1} << row))) continue;
      if (!pivots[row]) {
        pivots[row] = delta;
        masks[row] = mask;
        break;
      }
      delta ^= pivots[row];
      mask ^= masks[row];
    }
  }
  uint32_t target = baseline, zeroCrcCounter = 0;
  for (int row = 31; row >= 0; --row) {
    if (!(target & (uint32_t{1} << row))) continue;
    ASSERT_NE(0u, pivots[row]);
    target ^= pivots[row];
    zeroCrcCounter ^= masks[row];
  }
  ASSERT_EQ(0u, target);
  ASSERT_EQ(0u, checksum(zeroCrcCounter));

  storage_stageU2FCounter(zeroCrcCounter);
  storage_commit();
  storage_init();
  ASSERT_TRUE(storage_hasMnemonic());
  EXPECT_STREQ(kMnemonic, storage_getMnemonic());
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
