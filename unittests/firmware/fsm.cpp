extern "C" {
#include "keepkey/transport/interface.h"
#include "keepkey/board/usb.h"
#include "keepkey/board/keepkey_display.h"
#include "keepkey/board/memory.h"
#include "keepkey/board/keepkey_flash.h"
#include "keepkey/board/keepkey_board.h"
#include "pb_encode.h"
#include "trezor/crypto/sha2.h"
#include "trezor/crypto/bip32.h"
#include "trezor/crypto/bip39.h"
#include "keepkey/firmware/authenticator.h"
#include "keepkey/firmware/bip85.h"
#include "keepkey/firmware/binance.h"
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/eos.h"
#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/ethereum_tokens.h"
#include "keepkey/firmware/recovery_cipher.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/mayachain.h"
#include "keepkey/firmware/osmosis.h"
#include "keepkey/firmware/reset.h"
#include "keepkey/firmware/signing.h"
#include "keepkey/firmware/signtx_tendermint.h"
#include "keepkey/firmware/tendermint.h"
#include "keepkey/firmware/storage.h"
#include "storage.h"
#include "keepkey/firmware/thorchain.h"
#include "trezor/crypto/secp256k1.h"

bool keepkey_before_message_dispatch(MessageType msg_id);
}

#include "gtest/gtest.h"

#include <cstring>
#include <algorithm>
#include <vector>

// After the C++ headers: confirm_sm.h defines an isprint() macro.
extern "C" {
#include "keepkey/board/confirm_sm.h"
}

// The shared bootstrap initializes the canvas and timer queues exactly once.
// Calling timer_init() again relinks the static runnable nodes into a cycle.
#include "test_board.h"
bool kkconfirm_preload(int nYes, int nNo);
int kkconfirm_drain(void);
bool kkconfirm_openDebugPeer(void);
bool kkconfirm_readDebugFrame(uint8_t frame[64]);

TEST(Fsm, CoinTableRetainsPredecessorPageCapacity) {
  const CoinTable response = {};
  EXPECT_EQ(24u, sizeof(response.table) / sizeof(response.table[0]));
#if !BITCOIN_ONLY
  kk_test_board_init();
  fsm_init();
  for (uint32_t count : {10u, 24u}) {
    fsm_test_clearLastFailure();
    GetCoinTable request = {};
    request.has_start = request.has_end = true;
    request.start = 0;
    request.end = count;
    fsm_msgGetCoinTable(&request);
    EXPECT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()));
  }
#endif
}

TEST(Fsm, AuthenticatorCredentialSourceIsWipedOnEveryExit) {
  char credential[] = "site:user:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  ASSERT_EQ(LARGESEED, addAuthAccount(credential));

  for (size_t i = 0; i < sizeof(credential); ++i) {
    EXPECT_EQ('\0', credential[i]);
  }
}

TEST(Fsm, Bip85WireSurfaceIsPresentInBothVariants) {
  fsm_init();
  EXPECT_NE(nullptr,
            message_fields(NORMAL_MSG, MessageType_MessageType_GetBip85Mnemonic,
                           IN_MSG));
}

TEST(Fsm, Bip85PrivateDisplayRefusesDebugMemoryReads) {
  kk_test_board_init();
  fsm_init();
  DebugLinkFlashDump dump = {};
  dump.has_address = dump.has_length = true;
  dump.address = 0x20000000;
  dump.length = 32;
  bip85_set_private_display(true);
  fsm_test_clearLastFailure();
  fsm_msgDebugLinkFlashDump(&dump);
  EXPECT_EQ(FailureType_Failure_UnexpectedMessage, fsm_test_lastFailureCode());
  bip85_set_private_display(false);
}

TEST(Fsm, Bip85DerivationMatchesPublishedVectors) {
  // BIP-85 BIP-39 English vectors, m/83696968'/39'/0'/words'/0'.
  const char* root_xprv =
      "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLL"
      "HRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb";
  HDNode root = {};
  ASSERT_EQ(0, hdnode_deserialize_private(root_xprv, 0x0488ade4, SECP256K1_NAME,
                                          &root, nullptr));
  struct Vector {
    uint32_t words;
    const char* mnemonic;
  };
  const Vector vectors[] = {
      {12,
       "girl mad pet galaxy egg matter matrix prison refuse sense ordinary "
       "nose"},
      {18,
       "near account window bike charge season chef number sketch tomorrow "
       "excuse sniff circle vital hockey outdoor supply token"},
      {24,
       "puppy ocean match cereal symbol another shed magic wrap hammer bulb "
       "intact gadget divorce twin tonight reason outdoor destroy simple truth "
       "cigar social volcano"},
  };
  char child[256] = {};
  for (const Vector& vector : vectors) {
    ASSERT_TRUE(bip85_derive_from_root_for_test(&root, vector.words, 0, child,
                                                sizeof(child)));
    EXPECT_STREQ(vector.mnemonic, child);
  }
  ASSERT_TRUE(
      bip85_derive_from_root_for_test(&root, 12, 1, child, sizeof(child)));
  EXPECT_STRNE(vectors[0].mnemonic, child);
  ASSERT_TRUE(
      bip85_derive_from_root_for_test(&root, 12, 0, child, sizeof(child)));
  EXPECT_STREQ(vectors[0].mnemonic, child);
  EXPECT_FALSE(
      bip85_derive_from_root_for_test(&root, 15, 0, child, sizeof(child)));
  EXPECT_FALSE(bip85_derive_from_root_for_test(&root, 12, 0x80000000, child,
                                               sizeof(child)));
}

#if !BITCOIN_ONLY
static void expectSigningSessionsCleared(bool initialize) {
  HDNode node = {};
  node.curve = &secp256k1_info;

  BinanceSignTx binance = {};
  binance.has_msg_count = true;
  binance.msg_count = 1;
  binance.has_account_number = true;
  binance.has_chain_id = true;
  std::strcpy(binance.chain_id, "Binance-Chain-Nile");
  binance.has_sequence = true;
  binance.has_source = true;
  ASSERT_TRUE(binance_signTxInit(&node, &binance));

  TendermintSignTx tendermint = {};
  tendermint.has_msg_count = true;
  tendermint.msg_count = 1;
  tendermint.has_chain_id = true;
  std::strcpy(tendermint.chain_id, "chain-1");
  tendermint.has_chain_name = true;
  std::strcpy(tendermint.chain_name, "Cosmos");
  tendermint.has_denom = true;
  std::strcpy(tendermint.denom, "uatom");
  tendermint.has_message_type_prefix = true;
  std::strcpy(tendermint.message_type_prefix, "cosmos-sdk");
  ASSERT_TRUE(tendermint_signTxInit(&node, &tendermint, sizeof(tendermint),
                                    "uatom", TENDERMINT_SIGNING_GENERIC));

  OsmosisSignTx osmosis = {};
  osmosis.has_msg_count = true;
  osmosis.msg_count = 1;
  osmosis.has_chain_id = true;
  std::strcpy(osmosis.chain_id, "osmosis-1");
  ASSERT_TRUE(osmosis_signTxInit(&node, &osmosis));

  ThorchainSignTx thorchain = {};
  thorchain.has_msg_count = true;
  thorchain.msg_count = 1;
  thorchain.has_chain_id = true;
  std::strcpy(thorchain.chain_id, "thorchain-1");
  ASSERT_TRUE(thorchain_signTxInit(&node, &thorchain));

  MayachainSignTx mayachain = {};
  mayachain.has_msg_count = true;
  mayachain.msg_count = 1;
  mayachain.has_chain_id = true;
  std::strcpy(mayachain.chain_id, "mayachain-mainnet-v1");
  ASSERT_TRUE(mayachain_signTxInit(&node, &mayachain));

  uint8_t eos_chain_id[32] = {};
  EosTxHeader eos_header = {};
  uint32_t eos_path[8] = {};
  eos_signingInit(eos_chain_id, 1, &eos_header, &node, eos_path, 0);

  ASSERT_TRUE(binance_signingIsInited());
  ASSERT_TRUE(tendermint_signingIsInited(TENDERMINT_SIGNING_GENERIC));
  ASSERT_TRUE(osmosis_signingIsInited());
  ASSERT_TRUE(thorchain_signingIsInited());
  ASSERT_TRUE(mayachain_signingIsInited());
  ASSERT_TRUE(eos_signingIsInited());

  if (initialize) {
    kk_test_board_init();
    fsm_init();
    fsm_msgInitialize(nullptr);
  } else {
    fsm_abort_workflows();
  }

  EXPECT_FALSE(binance_signingIsInited());
  EXPECT_FALSE(tendermint_signingIsInited(TENDERMINT_SIGNING_GENERIC));
  EXPECT_FALSE(osmosis_signingIsInited());
  EXPECT_FALSE(thorchain_signingIsInited());
  EXPECT_FALSE(mayachain_signingIsInited());
  EXPECT_FALSE(eos_signingIsInited());
}

TEST(Fsm, AbortWorkflowsClearsEveryObservableSigningSession) {
  expectSigningSessionsCleared(false);
}

TEST(Fsm, InitializeClearsEveryObservableSigningSession) {
  expectSigningSessionsCleared(true);
}

#endif

TEST(Fsm, MissingBitcoinAckPayloadTerminatesSigning) {
  fsm_init();

  SignTx start = {};
  start.inputs_count = 1;
  start.outputs_count = 1;
  HDNode root = {};
  const CoinType* coin = coinByName("Bitcoin");
  ASSERT_NE(nullptr, coin);

  signing_init(&start, coin, &root);
  ASSERT_TRUE(signing_is_active());

  TxAck missing = {};
  fsm_msgTxAck(&missing);
  EXPECT_FALSE(signing_is_active());

  TxAck stale = {};
  stale.has_tx = true;
  fsm_msgTxAck(&stale);
  EXPECT_FALSE(signing_is_active());
}

TEST(Fsm, AutoLockTerminatesSigningWhileWaitingAwayFromHome) {
  /* Production initializes the OLED before the main loop can auto-lock. Use
   * the firmware suite's one-time board bootstrap to mirror that precondition
   * without reinitializing and corrupting the static timer queues. */
  kk_test_board_init();

  fsm_init();
  layoutHomeForced();
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);

  SignTx start = {};
  start.inputs_count = 1;
  start.outputs_count = 1;
  HDNode root = {};
  const CoinType* coin = coinByName("Bitcoin");
  ASSERT_NE(nullptr, coin);
  signing_init(&start, coin, &root);
  ASSERT_TRUE(signing_is_active());

  leave_home();
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  toggle_screensaver();
  EXPECT_TRUE(signing_is_active());

  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(signing_is_active());

  /* Restore a deterministic home state for subsequent tests. */
  layoutHomeForced();
}

/* The lock path aborts signing, and signing_abort() draws the home screen,
 * which resets the idle timer. If that reset stands, the very next tick sees
 * an idle device and replaces the screensaver with the home screen. */
TEST(Fsm, AutoLockKeepsTheScreensaverAfterAbortingSigning) {
  kk_test_board_init();
  fsm_init();
  layoutHomeForced();
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);

  SignTx start = {};
  start.inputs_count = 1;
  start.outputs_count = 1;
  HDNode root = {};
  const CoinType* coin = coinByName("Bitcoin");
  ASSERT_NE(nullptr, coin);
  signing_init(&start, coin, &root);
  ASSERT_TRUE(signing_is_active());

  leave_home();
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT);
  toggle_screensaver();
  ASSERT_FALSE(signing_is_active());
  ASSERT_EQ(SCREENSAVER, home_get_state());

  increment_idle_time(1000);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state())
      << "a locked device must stay on the screensaver, not wake to home";

  // ~49.7 days of further idling must not wrap the counter into "activity".
  // It holds STORAGE_MIN_SCREENSAVER_TIMEOUT + 1000 here; this brings an
  // unsaturated counter to exactly 0.
  increment_idle_time(UINT32_MAX - (STORAGE_MIN_SCREENSAVER_TIMEOUT + 1000) + 1);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state())
      << "the idle counter wrapped and woke the locked screen";

  layoutHomeForced();
}

namespace {
void receiveMessage(MessageType type, const pb_field_t* fields,
                    const void* msg) {
  uint8_t encoded[4096] = {};
  pb_ostream_t stream = pb_ostream_from_buffer(encoded, sizeof(encoded));
  ASSERT_TRUE(pb_encode(&stream, fields, msg));
  uint8_t frame[64] = {'?', '#', '#'};
  frame[3] = type >> 8;
  frame[4] = type & 0xff;
  const size_t size = stream.bytes_written;
  frame[5] = size >> 24;
  frame[6] = size >> 16;
  frame[7] = size >> 8;
  frame[8] = size;
  size_t sent = std::min(size, sizeof(frame) - 9);
  std::memcpy(frame + 9, encoded, sent);
  usb_test_receive(frame, sizeof(frame));
  while (sent < size) {
    std::memset(frame + 1, 0, sizeof(frame) - 1);
    const size_t chunk = std::min(size - sent, sizeof(frame) - 1);
    std::memcpy(frame + 1, encoded + sent, chunk);
    usb_test_receive(frame, sizeof(frame));
    sent += chunk;
  }
}

// firmware-unit never maps emulated flash; tests whose handlers commit storage
// borrow a zeroed image for their duration.
struct ScopedFlash {
  std::vector<uint8_t> bytes = std::vector<uint8_t>(FLASH_TOTAL_SIZE, 0xff);
  uint8_t* previous = emulator_flash_base;
  ScopedFlash() {
    emulator_flash_base = bytes.data();
    storage_init();
  }
  ~ScopedFlash() {
    storage_reset();
    emulator_flash_base = previous;
  }
};

LoadDevice allLoad() {
  LoadDevice load = {};
  load.has_mnemonic = true;
  std::strcpy(load.mnemonic, "all all all all all all all all all all all all");
  return load;
}

// The "all" wallet, signing idle, minimum auto-lock delay.
void loadAllWallet() {
  signing_abort();
  LoadDevice load = allLoad();
  storage_loadDevice(&load);
  storage_commit();
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);
}

// Boot from a future-format sector, using the real loader rather than a test
// setter for either lock flag. Every refusal below traverses the USB decoder.
class IncompatibleStorage : public ::testing::TestWithParam<uint32_t> {
 protected:
  std::vector<uint8_t> bytes = std::vector<uint8_t>(FLASH_TOTAL_SIZE, 0xff);
  std::vector<uint8_t> original;
  uint8_t* previous = nullptr;

  void SetUp() override {
    kk_test_board_init();
    fsm_init();
    previous = emulator_flash_base;
    emulator_flash_base = bytes.data();
    storage_wipe();  // Clear state left by another test, in this scratch image.
    auto* sector =
        reinterpret_cast<uint8_t*>(flash_write_helper(FLASH_STORAGE1));
    std::memset(sector, 0xa7, FLASH_STORAGE_LEN);
    std::memcpy(sector, "stor", 4);
    for (size_t i = 0; i < 4; ++i) sector[44 + i] = GetParam() >> (8 * i);
    original = bytes;
    storage_init();
    ASSERT_EQ(GetParam() < STORAGE_VERSION_BTC_ONLY_BASE,
              storage_isFirmwareTooOld());
    ASSERT_EQ(GetParam() >= STORAGE_VERSION_BTC_ONLY_BASE,
              storage_isBitcoinOnlyLocked());
    ASSERT_EQ(BITCOIN_ONLY && GetParam() >= STORAGE_VERSION_BTC_ONLY_BASE,
              storage_isBitcoinOnlyTooNew());
    ASSERT_FALSE(storage_isInitialized());
    ExpectUntouched();
  }

  void TearDown() override {
    setup_abort();
    storage_wipe();
    storage_reset();
    session_clear(true);
    emulator_flash_base = previous;
  }

  void ExpectUntouched() {
    EXPECT_EQ(0, std::memcmp(original.data(), bytes.data(), bytes.size()));
    EXPECT_FALSE(storage_isInitialized());
    EXPECT_FALSE(setup_isArmed());
    EXPECT_FALSE(storage_hasPin());
    EXPECT_FALSE(storage_hasWipeCode());
    EXPECT_EQ(nullptr, storage_getLabel());
    EXPECT_FALSE(storage_getPassphraseProtected());
    EXPECT_FALSE(storage_isPolicyEnabled("Experimental"));
  }

  // Expected guidance follows from the image and build, not from the flags
  // under test. Only a foreign bitcoin-only wallet may be recoverable by
  // nothing but a wipe; a too-new bitcoin-only wallet needs an upgrade.
  bool NormalBandTooNew() const {
    return GetParam() < STORAGE_VERSION_BTC_ONLY_BASE;
  }
  bool BitcoinOnlyTooNew() const {
    return BITCOIN_ONLY && GetParam() >= STORAGE_VERSION_BTC_ONLY_BASE;
  }

  void ExpectRecoverByUpgrade() {
    EXPECT_STREQ(
        "Storage needs newer firmware. Upgrade firmware to recover this "
        "wallet.",
        fsm_test_lastFailureMessage());
    EXPECT_EQ(nullptr, std::strstr(fsm_test_lastFailureMessage(), "Wipe"));
  }

  void ExpectWriteRefusalMessage() {
    if (NormalBandTooNew()) {
      EXPECT_STREQ(
          "Storage needs newer firmware. Upgrade firmware or use Wipe first.",
          fsm_test_lastFailureMessage());
    } else if (BitcoinOnlyTooNew()) {
      ExpectRecoverByUpgrade();
    } else {
      EXPECT_STREQ("Bitcoin-only wallet present. Use Wipe first.",
                   fsm_test_lastFailureMessage());
    }
  }

  // Continuations have no storage guard of their own: with every ceremony
  // start refused, nothing is armed and they fail as out-of-sequence.
  void ExpectRejected(MessageType type, const pb_field_t* fields,
                      const void* msg, const char* unarmed = nullptr) {
    // A deliberately unused Yes proves refusal happened before user work.
    // The trailing No also makes the old vulnerable handler terminate safely.
    ASSERT_TRUE(kkconfirm_preload(1, 0));
    fsm_test_clearLastFailure();
    receiveMessage(type, fields, msg);
    EXPECT_EQ(FailureType_Failure_UnexpectedMessage,
              fsm_test_lastFailureCode());
    if (unarmed) {
      EXPECT_STREQ(unarmed, fsm_test_lastFailureMessage());
    } else {
      ExpectWriteRefusalMessage();
    }
    EXPECT_EQ(2, kkconfirm_drain());
    ExpectUntouched();
    // Isolate the next entry path even in a negative-control build where this
    // request changed the RAM shadow or armed a ceremony before failing.
    setup_abort();
    storage_init();
  }

  void ConfirmWipe() {
    ASSERT_TRUE(kkconfirm_preload(1, 0));
    fsm_test_clearLastFailure();
    WipeDevice wipe = {};
    receiveMessage(MessageType_MessageType_WipeDevice, WipeDevice_fields,
                   &wipe);
    ASSERT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()));
    ASSERT_EQ(0, kkconfirm_drain());
    ASSERT_FALSE(storage_isFirmwareTooOld());
    ASSERT_FALSE(storage_isBitcoinOnlyLocked());
    ASSERT_FALSE(storage_isBitcoinOnlyTooNew());
    ASSERT_FALSE(storage_isInitialized());
    EXPECT_NE(0, std::memcmp(original.data(), bytes.data(), bytes.size()));
  }
};

TEST_P(IncompatibleStorage, CreationRefusesBeforeStagingOrConfirmation) {
  LoadDevice load = allLoad();
  // Load/Reset preserve the established Failure_Other for bitcoin-only locks.
  if (storage_isBitcoinOnlyLocked()) {
    for (MessageType type : {MessageType_MessageType_LoadDevice,
                             MessageType_MessageType_ResetDevice}) {
      ASSERT_TRUE(kkconfirm_preload(1, 0));
      fsm_test_clearLastFailure();
      if (type == MessageType_MessageType_LoadDevice) {
        receiveMessage(type, LoadDevice_fields, &load);
      } else {
        ResetDevice reset = {};
        receiveMessage(type, ResetDevice_fields, &reset);
      }
      EXPECT_EQ(FailureType_Failure_Other, fsm_test_lastFailureCode());
      if (BitcoinOnlyTooNew()) {
        ExpectRecoverByUpgrade();
      } else {
        EXPECT_STREQ(
            "Device holds a bitcoin-only wallet. Wipe the device to use "
            "multi-chain firmware.",
            fsm_test_lastFailureMessage());
      }
      EXPECT_EQ(2, kkconfirm_drain());
      ExpectUntouched();
    }
  } else {
    ExpectRejected(MessageType_MessageType_LoadDevice, LoadDevice_fields,
                   &load);
    ResetDevice reset = {};
    ExpectRejected(MessageType_MessageType_ResetDevice, ResetDevice_fields,
                   &reset);
  }
  RecoveryDevice recovery = {};
  recovery.has_word_count = true;
  recovery.word_count = 12;
  ExpectRejected(MessageType_MessageType_RecoveryDevice, RecoveryDevice_fields,
                 &recovery);

  EntropyAck entropy = {};
  entropy.has_entropy = true;
  entropy.entropy.size = 32;
  ExpectRejected(MessageType_MessageType_EntropyAck, EntropyAck_fields,
                 &entropy, "Not in Reset mode");
  CharacterAck character = {};
  character.has_done = character.done = true;
  ExpectRejected(MessageType_MessageType_CharacterAck, CharacterAck_fields,
                 &character, "Not in Recovery mode");
}

TEST_P(IncompatibleStorage, SettingsRefuseBeforeMutationOrConfirmation) {
  ChangePin pin = {};
  pin.has_remove = pin.remove = true;
  ExpectRejected(MessageType_MessageType_ChangePin, ChangePin_fields, &pin);
  ChangeWipeCode wipe_code = {};
  wipe_code.has_remove = wipe_code.remove = true;
  ExpectRejected(MessageType_MessageType_ChangeWipeCode, ChangeWipeCode_fields,
                 &wipe_code);

  ApplySettings settings = {};
  settings.has_label = true;
  std::strcpy(settings.label, "must not be staged");
  ExpectRejected(MessageType_MessageType_ApplySettings, ApplySettings_fields,
                 &settings);
  ApplyPolicies policies = {};
  policies.policy_count = 1;
  policies.policy[0].has_policy_name = policies.policy[0].has_enabled = true;
  policies.policy[0].enabled = true;
  std::strcpy(policies.policy[0].policy_name, "Experimental");
  ExpectRejected(MessageType_MessageType_ApplyPolicies, ApplyPolicies_fields,
                 &policies);
}

TEST_P(IncompatibleStorage, AuthenticatorCommandsCannotBypassWriteRefusal) {
  for (const char* command : {"\x15"
                              "initializeAuth:site:user:AAAAAAAA",
                              "\x16"
                              "generateOTPFrom:site:user:0:30",
                              "\x17"
                              "getAccount:0",
                              "\x18"
                              "removeAccount:site:user",
                              "\x19"
                              "wipeAuthdata:"}) {
    SCOPED_TRACE(command);
    Ping ping = {};
    ping.has_message = true;
    std::strcpy(ping.message, command);
    ExpectRejected(MessageType_MessageType_Ping, Ping_fields, &ping);
  }
}

TEST_P(IncompatibleStorage, ReadOnlyRequestsAndCancelledWipePreserveLock) {
  Ping ping = {};
  ping.has_message = true;
  std::strcpy(ping.message, "ordinary ping");
  fsm_test_clearLastFailure();
  receiveMessage(MessageType_MessageType_Ping, Ping_fields, &ping);
  EXPECT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()));
  Initialize initialize = {};
  receiveMessage(MessageType_MessageType_Initialize, Initialize_fields,
                 &initialize);
  EXPECT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()));
  ExpectUntouched();

  RecoveryDevice recovery = {};
  recovery.has_dry_run = recovery.dry_run = true;
  receiveMessage(MessageType_MessageType_RecoveryDevice, RecoveryDevice_fields,
                 &recovery);
  EXPECT_EQ(FailureType_Failure_NotInitialized, fsm_test_lastFailureCode());
  ExpectUntouched();
  ASSERT_TRUE(kkconfirm_preload(0, 1));
  WipeDevice wipe = {};
  receiveMessage(MessageType_MessageType_WipeDevice, WipeDevice_fields, &wipe);
  EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
  EXPECT_EQ(0, kkconfirm_drain());
  storage_init();
  EXPECT_EQ(GetParam() < STORAGE_VERSION_BTC_ONLY_BASE,
            storage_isFirmwareTooOld());
  EXPECT_EQ(GetParam() >= STORAGE_VERSION_BTC_ONLY_BASE,
            storage_isBitcoinOnlyLocked());
  EXPECT_EQ(BITCOIN_ONLY && GetParam() >= STORAGE_VERSION_BTC_ONLY_BASE,
            storage_isBitcoinOnlyTooNew());
  ExpectUntouched();
}

// A reinitialized emulator (libkkemu, test fixtures) can load a different
// flash image without a wipe. The previous image's locks must not follow it.
TEST_P(IncompatibleStorage, ReinitializingOnFreshFlashClearsIncompatibleLocks) {
  std::fill(bytes.begin(), bytes.end(), 0xff);
  storage_init();
  EXPECT_FALSE(storage_isFirmwareTooOld());
  EXPECT_FALSE(storage_isBitcoinOnlyLocked());
  EXPECT_FALSE(storage_isBitcoinOnlyTooNew());

  ASSERT_TRUE(kkconfirm_preload(1, 0));
  fsm_test_clearLastFailure();
  LoadDevice load = allLoad();
  receiveMessage(MessageType_MessageType_LoadDevice, LoadDevice_fields, &load);
  EXPECT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()));
  ASSERT_EQ(0, kkconfirm_drain());
  storage_init();
  EXPECT_TRUE(storage_isInitialized());
}

TEST_P(IncompatibleStorage, ConfirmedWipeAllowsPersistentLoadAndSettings) {
  ConfirmWipe();
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  LoadDevice load = allLoad();
  receiveMessage(MessageType_MessageType_LoadDevice, LoadDevice_fields, &load);
  EXPECT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()));
  ASSERT_EQ(0, kkconfirm_drain());
  ASSERT_TRUE(storage_isInitialized());

  ASSERT_TRUE(kkconfirm_preload(1, 0));
  ApplySettings settings = {};
  settings.has_label = true;
  std::strcpy(settings.label, "persist after wipe");
  receiveMessage(MessageType_MessageType_ApplySettings, ApplySettings_fields,
                 &settings);
  EXPECT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()));
  ASSERT_EQ(0, kkconfirm_drain());
  storage_init();
  EXPECT_TRUE(storage_isInitialized());
  EXPECT_STREQ("persist after wipe", storage_getLabel());
  EXPECT_FALSE(storage_isFirmwareTooOld());
  EXPECT_FALSE(storage_isBitcoinOnlyLocked());
  EXPECT_FALSE(storage_isBitcoinOnlyTooNew());
}

TEST_P(IncompatibleStorage, ConfirmedWipeAllowsResetAndRecoveryStarts) {
  ConfirmWipe();
  ResetDevice reset = {};
  receiveMessage(MessageType_MessageType_ResetDevice, ResetDevice_fields,
                 &reset);
  EXPECT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()));
  EXPECT_TRUE(setup_isArmedAs(SETUP_RESET));
  Cancel cancel = {};
  receiveMessage(MessageType_MessageType_Cancel, Cancel_fields, &cancel);
  ASSERT_FALSE(setup_isArmed());

  ASSERT_TRUE(kkconfirm_preload(1, 0));
  fsm_test_clearLastFailure();
  RecoveryDevice recovery = {};
  recovery.has_word_count = true;
  recovery.word_count = 12;
  receiveMessage(MessageType_MessageType_RecoveryDevice, RecoveryDevice_fields,
                 &recovery);
  EXPECT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()));
  EXPECT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  EXPECT_EQ(0, kkconfirm_drain());
  receiveMessage(MessageType_MessageType_Cancel, Cancel_fields, &cancel);
  EXPECT_FALSE(setup_isArmed());
  EXPECT_FALSE(storage_isInitialized());
}

INSTANTIATE_TEST_CASE_P(
    FutureFormats, IncompatibleStorage,
    ::testing::Values(uint32_t(STORAGE_VERSION + 1),
                      uint32_t(STORAGE_VERSION_BTC_ONLY_BASE - 1),
#if !BITCOIN_ONLY
                      uint32_t(STORAGE_VERSION_BTC_ONLY),
#endif
                      uint32_t(STORAGE_VERSION_BTC_ONLY + 1), UINT32_MAX));

class AutoLockProgress : public ::testing::Test {
 protected:
  void SetUp() override {
    kk_test_board_init();
    fsm_init();
    setup_abort();
    layoutHomeForced();
    storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);
    SignTx start = {};
    start.inputs_count = start.outputs_count = 1;
    HDNode root = {};
    const uint8_t seed[32] = {1};
    ASSERT_TRUE(hdnode_from_seed(seed, sizeof(seed), "secp256k1", &root));
    signing_init(&start, coinByName("Bitcoin"), &root);
    ASSERT_TRUE(signing_is_active());
    leave_home();
  }
  void TearDown() override {
    fsm_abort_workflows();
    setup_abort();
  }
};
}  // namespace

TEST_F(AutoLockProgress, FeaturePollingCannotKeepStalledSigningUnlocked) {
  GetFeatures poll = {};
  for (int i = 0; i < 4; ++i) {
    increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT / 4);
    receiveMessage(MessageType_MessageType_GetFeatures, GetFeatures_fields,
                   &poll);
    ASSERT_EQ(AWAY_FROM_HOME, home_get_state());
    ASSERT_TRUE(signing_is_active());
    toggle_screensaver();
  }
  EXPECT_FALSE(signing_is_active());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST(Fsm, DispatchScrubsDerivedKeyScratchAfterHandler) {
  fsm_init();
  fsm_test_seedDerivedNode();
  ASSERT_FALSE(fsm_test_derivedNodeIsZero());

  GetFeatures request = {};
  receiveMessage(MessageType_MessageType_GetFeatures, GetFeatures_fields,
                 &request);

  EXPECT_TRUE(fsm_test_derivedNodeIsZero());
}

TEST(Fsm, InactiveBitcoinAckGetsATerminalResponse) {
  fsm_init();
  fsm_abort_workflows();
  fsm_test_clearLastFailure();

  TxAck stale = {};
  stale.has_tx = true;
  receiveMessage(MessageType_MessageType_TxAck, TxAck_fields, &stale);

  EXPECT_EQ(FailureType_Failure_UnexpectedMessage, fsm_test_lastFailureCode())
      << "silently dropping an inactive ACK leaves the host blocked";
  EXPECT_FALSE(signing_is_active());
}

TEST_F(AutoLockProgress, IncompleteFrameCannotKeepStalledSigningUnlocked) {
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  // Valid Ping header, but its 60-byte payload has not arrived in full.
  uint8_t frame[64] = {'?', '#', '#', 0, 1, 0, 0, 0, 60};
  usb_test_receive(frame, sizeof(frame));
  ASSERT_TRUE(signing_is_active());
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(signing_is_active());
  EXPECT_EQ(SCREENSAVER, home_get_state());
  // Finish the pending transport message so it cannot affect later tests.
  uint8_t tail[64] = {'?'};
  usb_test_receive(tail, sizeof(tail));
}

TEST_F(AutoLockProgress, ValidBitcoinStreamProgressRenewsTheIdleDeadline) {
  TxAck ack = {};
  ack.has_tx = true;
  ack.tx.inputs_count = 1;
  ack.tx.inputs[0].prev_hash.size = 32;
  ack.tx.inputs[0].has_script_type = true;
  ack.tx.inputs[0].script_type = InputScriptType_SPENDADDRESS;
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  receiveMessage(MessageType_MessageType_TxAck, TxAck_fields, &ack);
  ASSERT_TRUE(signing_is_active());
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  toggle_screensaver();
  ASSERT_TRUE(signing_is_active());

  // Real next stage: supply metadata for the requested previous transaction.
  ack = {};
  ack.has_tx = true;
  ack.tx.has_inputs_cnt = ack.tx.has_outputs_cnt = true;
  ack.tx.inputs_cnt = ack.tx.outputs_cnt = 1;
  receiveMessage(MessageType_MessageType_TxAck, TxAck_fields, &ack);
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  toggle_screensaver();
  ASSERT_TRUE(signing_is_active());
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(signing_is_active());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, FeaturePollingAtHomeDoesNotRenewTheIdleDeadline) {
  signing_abort();
  layoutHomeForced();
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  GetFeatures poll = {};
  receiveMessage(MessageType_MessageType_GetFeatures, GetFeatures_fields,
                 &poll);
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, PingCannotRenewAStalledSigningDeadline) {
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  Ping ping = {};
  receiveMessage(MessageType_MessageType_Ping, Ping_fields, &ping);
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(signing_is_active());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, ProtectedPingCannotSuspendAnOlderSigningSession) {
  Ping ping = {};
  ping.has_pin_protection = true;
  ping.pin_protection = true;
  fsm_test_clearLastFailure();
  receiveMessage(MessageType_MessageType_Ping, Ping_fields, &ping);

  EXPECT_FALSE(signing_is_active());
}

// 7.14.3 end-to-end form of the test above: a button-protected Ping that the
// user cancels must still have ended the older signing stream first.
TEST_F(AutoLockProgress, ButtonProtectedPingCancelEndsAnOlderSigningSession) {
  ASSERT_TRUE(kkconfirm_preload(0, 1));
  Ping ping = {};
  ping.has_button_protection = true;
  ping.button_protection = true;
  fsm_test_clearLastFailure();
  receiveMessage(MessageType_MessageType_Ping, Ping_fields, &ping);

  EXPECT_FALSE(signing_is_active());
  EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
  EXPECT_EQ(0, kkconfirm_drain());
}

TEST_F(AutoLockProgress, TopLevelConfirmationEndsAnOlderSigningSession) {
  ASSERT_TRUE(kkconfirm_preload(0, 1));
  ChangePin request = {};
  fsm_test_clearLastFailure();
  receiveMessage(MessageType_MessageType_ChangePin, ChangePin_fields, &request);

  EXPECT_FALSE(signing_is_active());
  EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
  EXPECT_EQ(0, kkconfirm_drain());
}

TEST_F(AutoLockProgress, TopLevelBoundaryEndsSigningButIsNotALock) {
  // AdvancedMode is the observable here: without a PIN, session_clear()
  // re-caches the empty PIN, so a PIN-cache check would pass even under a lock.
  storage_reset();
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", true));
  EXPECT_TRUE(
      keepkey_before_message_dispatch(MessageType_MessageType_ChangePin));
  EXPECT_FALSE(signing_is_active());

  EXPECT_TRUE(storage_isPolicyEnabled("AdvancedMode"))
      << "an ordinary request must not disarm AdvancedMode before signing";
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", false));
  storage_reset();
}

// 7.14.3 end-to-end form of the test above: a real ChangePin and a
// PIN-protected Ping through the decoder still leave AdvancedMode armed.
TEST_F(AutoLockProgress, DecodedRequestsEndSigningButAreNotALock) {
  ScopedFlash flash;
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", true));
  ASSERT_TRUE(kkconfirm_preload(0, 1));
  ChangePin request = {};
  receiveMessage(MessageType_MessageType_ChangePin, ChangePin_fields, &request);
  EXPECT_FALSE(signing_is_active());
  EXPECT_EQ(0, kkconfirm_drain());

  Ping ping = {};
  ping.has_pin_protection = true;
  ping.pin_protection = true;
  receiveMessage(MessageType_MessageType_Ping, Ping_fields, &ping);

  EXPECT_TRUE(storage_isPolicyEnabled("AdvancedMode"))
      << "an ordinary request must not disarm AdvancedMode before signing";
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", false));
}

TEST_F(AutoLockProgress, NewSigningRequestCannotCoexistWithRecovery) {
  signing_abort();
  setup_abort();
  ASSERT_TRUE(setup_stage(false, "english", "recovery", 0, 0, false));
  setup_arm(SETUP_RECOVERY);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));

  EXPECT_TRUE(keepkey_before_message_dispatch(MessageType_MessageType_SignTx));

  EXPECT_FALSE(setup_isArmed());
  EXPECT_FALSE(signing_is_active());
  layoutHomeForced();
}

// 7.14.3 end-to-end form of the test above, through the USB decoder.
TEST_F(AutoLockProgress, DecodedSigningRequestEndsAnArmedRecovery) {
  signing_abort();
  setup_abort();
  ASSERT_TRUE(setup_stage(false, "english", "recovery", 0, 0, false));
  setup_arm(SETUP_RECOVERY);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));

  SignTx invalid = {};
  receiveMessage(MessageType_MessageType_SignTx, SignTx_fields, &invalid);

  EXPECT_FALSE(setup_isArmed());
  EXPECT_FALSE(signing_is_active());
  layoutHomeForced();
}

TEST_F(AutoLockProgress, Bip85RequestEndsAnArmedCeremonyInBothVariants) {
  signing_abort();
  setup_abort();
  for (SetupKind kind : {SETUP_RECOVERY, SETUP_RESET}) {
    ASSERT_TRUE(setup_stage(false, "english", "bip85", 0, 0, false));
    setup_arm(kind);
    ASSERT_TRUE(setup_isArmedAs(kind));

    EXPECT_TRUE(keepkey_before_message_dispatch(
        MessageType_MessageType_GetBip85Mnemonic));
    EXPECT_FALSE(setup_isArmed());
    EXPECT_FALSE(signing_is_active());
  }
  layoutHomeForced();
}

TEST_F(AutoLockProgress, HostDrivenLayoutChangesDoNotRenewTheDeadline) {
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  layoutHome();
  leave_home();
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(signing_is_active());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

#if !BITCOIN_ONLY
TEST(Fsm, SolanaCertificateIsRejectedAtTheProductionHandler) {
  kk_test_board_init();
  fsm_init();
  fsm_test_clearLastFailure();

  SolanaSignTx request = {};
  request.has_clearsign_certificate = true;
  request.clearsign_certificate.size = 1;
  request.clearsign_certificate.bytes[0] = 0x01;
  receiveMessage(MessageType_MessageType_SolanaSignTx, SolanaSignTx_fields,
                 &request);

  EXPECT_EQ(FailureType_Failure_UnexpectedMessage, fsm_test_lastFailureCode())
      << "a decoded certificate must not fall through to ordinary signing";
  layoutHomeForced();
}
#endif

TEST_F(AutoLockProgress, InvalidBitcoinAckEndsTheStream) {
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  TxAck invalid = {};
  invalid.has_tx = true;
  // Decodable protobuf, but the required 32-byte previous hash is missing.
  invalid.tx.inputs_count = 1;
  receiveMessage(MessageType_MessageType_TxAck, TxAck_fields, &invalid);
  EXPECT_FALSE(signing_is_active());
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, EmptyRecoveryCharacterAbortsWithoutRenewingDeadline) {
  signing_abort();
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  recovery_cipher_init(12, false, false, "english", "empty character", false,
                       STORAGE_MIN_SCREENSAVER_TIMEOUT, 0, false);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  ASSERT_EQ(0, kkconfirm_drain());
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  fsm_test_clearLastFailure();
  CharacterAck character = {};
  character.has_character = true;
  receiveMessage(MessageType_MessageType_CharacterAck, CharacterAck_fields,
                 &character);
  EXPECT_EQ(FailureType_Failure_SyntaxError, fsm_test_lastFailureCode());
  EXPECT_FALSE(setup_isArmed());
  EXPECT_FALSE(storage_isInitialized());
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, RecoveryEditsRenewButPollingAndEmptyDeleteDoNot) {
  signing_abort();
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  recovery_cipher_init(12, false, false, "english", "idle test", false,
                       STORAGE_MIN_SCREENSAVER_TIMEOUT, 0, false);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  ASSERT_EQ(0, kkconfirm_drain());
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  CharacterAck character = {};
  character.has_character = true;
  character.character[0] = 'a';  // Every a-z character belongs to the cipher.
  receiveMessage(MessageType_MessageType_CharacterAck, CharacterAck_fields,
                 &character);
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  toggle_screensaver();
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  character = {};
  character.has_delete = character.del = true;
  receiveMessage(MessageType_MessageType_CharacterAck, CharacterAck_fields,
                 &character);
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  toggle_screensaver();
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  // The mnemonic is now empty: another delete makes no progress.
  receiveMessage(MessageType_MessageType_CharacterAck, CharacterAck_fields,
                 &character);
  GetFeatures poll = {};
  receiveMessage(MessageType_MessageType_GetFeatures, GetFeatures_fields,
                 &poll);
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(setup_isArmed());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

#if !BITCOIN_ONLY
TEST_F(AutoLockProgress, EthereumChunksRenewButFeaturePollingDoesNot) {
  signing_abort();
  storage_reset();
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", true));
  struct RestorePolicy {
    ~RestorePolicy() { storage_setPolicy("AdvancedMode", false); }
  } restore;
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  EthereumSignTx start = {};
  start.has_chain_id = true;
  start.chain_id = 1;
  start.has_gas_price = start.has_gas_limit = true;
  start.gas_price.size = start.gas_limit.size = 1;
  start.gas_price.bytes[0] = start.gas_limit.bytes[0] = 1;
  start.has_to = true;
  start.to.size = 20;
  start.to.bytes[0] = 1;
  start.has_data_initial_chunk = start.has_data_length = true;
  start.data_initial_chunk.size = 1;
  start.data_initial_chunk.bytes[0] = 1;
  start.data_length = 4096;
  HDNode node = {};
  const uint8_t seed[32] = {1};
  ASSERT_TRUE(hdnode_from_seed(seed, sizeof(seed), "secp256k1", &node));
  ethereum_signing_init(&start, &node, false);
  ASSERT_TRUE(ethereum_signing_isInProgress());
  ASSERT_EQ(0, kkconfirm_drain());
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);
  for (int i = 0; i < 2; ++i) {
    increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
    EthereumTxAck chunk = {};
    chunk.has_data_chunk = true;
    chunk.data_chunk.size = 128;  // Requires multiple USB frames.
    receiveMessage(MessageType_MessageType_EthereumTxAck, EthereumTxAck_fields,
                   &chunk);
    toggle_screensaver();
    ASSERT_TRUE(ethereum_signing_isInProgress());
  }
  GetFeatures poll = {};
  for (int i = 0; i < 4; ++i) {
    increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT / 4);
    receiveMessage(MessageType_MessageType_GetFeatures, GetFeatures_fields,
                   &poll);
    toggle_screensaver();
  }
  EXPECT_FALSE(ethereum_signing_isInProgress());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, EosDataProgressRenewsButEmptyChunksDoNot) {
  signing_abort();
  storage_reset();
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", true));
  struct RestorePolicy {
    ~RestorePolicy() { storage_setPolicy("AdvancedMode", false); }
  } restore;
  HDNode node = {};
  node.curve = &secp256k1_info;
  uint8_t chain_id[32] = {};
  EosTxHeader header = {};
  uint32_t path[8] = {};
  eos_signingInit(chain_id, 1, &header, &node, path, 0);
  ASSERT_TRUE(eos_signingIsInited());
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);
  leave_home();
  EosTxActionAck ack = {};
  ack.has_common = ack.has_unknown = true;
  ack.common.has_account = ack.common.has_name = true;
  ack.common.account = 0x1111;
  ack.common.name = 0x2222;
  ack.common.authorization_count = 1;
  ack.common.authorization[0].has_actor = true;
  ack.common.authorization[0].actor = 0x3333;
  ack.common.authorization[0].has_permission = true;
  ack.common.authorization[0].permission = 0x4444;
  ack.unknown.has_data_size = ack.unknown.has_data_chunk = true;
  ack.unknown.data_size = 256;
  ack.unknown.data_chunk.size = 1;
  for (int i = 0; i < 2; ++i) {
    increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
    receiveMessage(MessageType_MessageType_EosTxActionAck,
                   EosTxActionAck_fields, &ack);
    toggle_screensaver();
    ASSERT_TRUE(eos_signingIsInited());
  }
  ack.unknown.data_chunk.size = 0;
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  receiveMessage(MessageType_MessageType_EosTxActionAck, EosTxActionAck_fields,
                 &ack);
  ASSERT_TRUE(eos_signingIsInited());
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(eos_signingIsInited());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}
#endif

// Drive the real protobuf dispatch at the old deadline. Each initial request
// must buy a fresh interval; polling during the next interval must not.
TEST_F(AutoLockProgress, ResetEntropyRequestRenewsButPollingDoesNot) {
  ScopedFlash flash;
  signing_abort();
  storage_reset();
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);
  leave_home();
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  ResetDevice start = {};
  start.has_strength = true;
  start.strength = 128;
  receiveMessage(MessageType_MessageType_ResetDevice, ResetDevice_fields,
                 &start);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RESET));
  increment_idle_time(1);
  toggle_screensaver();
  ASSERT_TRUE(setup_isArmedAs(SETUP_RESET));
  GetFeatures poll = {};
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 2);
  receiveMessage(MessageType_MessageType_GetFeatures, GetFeatures_fields,
                 &poll);
  toggle_screensaver();
  ASSERT_TRUE(setup_isArmedAs(SETUP_RESET));
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(setup_isArmed());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

#if !BITCOIN_ONLY
// A signer's start renews the idle deadline; a GetFeatures poll does not.
static void expectStartRenewsButPollingDoesNot(MessageType type,
                                               const pb_field_t* fields,
                                               const void* start,
                                               bool (*inited)()) {
  ScopedFlash flash;
  loadAllWallet();
  leave_home();
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  receiveMessage(type, fields, start);
  ASSERT_TRUE(inited());
  increment_idle_time(1);
  toggle_screensaver();
  ASSERT_TRUE(inited());
  GetFeatures poll = {};
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 2);
  receiveMessage(MessageType_MessageType_GetFeatures, GetFeatures_fields,
                 &poll);
  toggle_screensaver();
  ASSERT_TRUE(inited());
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(inited());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, BinanceStartRenewsButPollingDoesNot) {
  BinanceSignTx start = {};
  start.has_msg_count = true;
  start.msg_count = 2;
  start.has_account_number = start.has_chain_id = start.has_sequence = true;
  start.has_source = true;
  std::strcpy(start.chain_id, "Binance-Chain-Nile");
  expectStartRenewsButPollingDoesNot(MessageType_MessageType_BinanceSignTx,
                                     BinanceSignTx_fields, &start,
                                     binance_signingIsInited);
}

TEST_F(AutoLockProgress, CosmosStartRenewsButPollingDoesNot) {
  CosmosSignTx start = {};
  start.has_msg_count = true;
  start.msg_count = 2;
  start.has_account_number = start.has_chain_id = start.has_sequence = true;
  std::strcpy(start.chain_id, "chain-1");
  start.has_fee_amount = start.has_gas = true;
  expectStartRenewsButPollingDoesNot(
      MessageType_MessageType_CosmosSignTx, CosmosSignTx_fields, &start,
      [] { return tendermint_signingIsInited(TENDERMINT_SIGNING_COSMOS); });
}

// Generic Tendermint is compiled but has no message-map entries. Do not
// enable a dormant protocol merely to exercise its internal renewal hook.
TEST_F(AutoLockProgress, UnregisteredTendermintCannotRenewTheDeadline) {
  EXPECT_EQ(nullptr,
            message_fields(NORMAL_MSG, MessageType_MessageType_TendermintSignTx,
                           IN_MSG));
  EXPECT_EQ(nullptr,
            message_fields(NORMAL_MSG, MessageType_MessageType_TendermintMsgAck,
                           IN_MSG));
  EXPECT_EQ(
      nullptr,
      message_fields(NORMAL_MSG, MessageType_MessageType_TendermintMsgRequest,
                     OUT_MSG));
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  TendermintSignTx start = {};
  receiveMessage(MessageType_MessageType_TendermintSignTx,
                 TendermintSignTx_fields, &start);
  EXPECT_FALSE(tendermint_signingIsInited(TENDERMINT_SIGNING_GENERIC));
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, OsmosisStartRenewsButPollingDoesNot) {
  OsmosisSignTx start = {};
  start.has_msg_count = true;
  start.msg_count = 2;
  start.has_account_number = start.has_chain_id = start.has_sequence = true;
  std::strcpy(start.chain_id, "chain-1");
  start.has_fee_amount = start.has_gas = true;
  expectStartRenewsButPollingDoesNot(MessageType_MessageType_OsmosisSignTx,
                                     OsmosisSignTx_fields, &start,
                                     osmosis_signingIsInited);
}

TEST_F(AutoLockProgress, ThorchainStartRenewsButPollingDoesNot) {
  ThorchainSignTx start = {};
  start.has_msg_count = true;
  start.msg_count = 2;
  start.has_account_number = start.has_chain_id = start.has_sequence = true;
  std::strcpy(start.chain_id, "chain-1");
  start.has_fee_amount = start.has_gas = true;
  expectStartRenewsButPollingDoesNot(MessageType_MessageType_ThorchainSignTx,
                                     ThorchainSignTx_fields, &start,
                                     thorchain_signingIsInited);
}

TEST_F(AutoLockProgress, MayachainStartRenewsButPollingDoesNot) {
  MayachainSignTx start = {};
  start.has_msg_count = true;
  start.msg_count = 2;
  start.has_account_number = start.has_chain_id = start.has_sequence = true;
  std::strcpy(start.chain_id, "chain-1");
  start.has_fee_amount = start.has_gas = true;
  expectStartRenewsButPollingDoesNot(MessageType_MessageType_MayachainSignTx,
                                     MayachainSignTx_fields, &start,
                                     mayachain_signingIsInited);
}

TEST_F(AutoLockProgress, BinanceContinuationRenewsAndMalformedAckTerminates) {
  ScopedFlash flash;
  loadAllWallet();
  BinanceSignTx start = {};
  start.has_msg_count = true;
  start.msg_count = 3;
  start.has_account_number = start.has_chain_id = start.has_sequence = true;
  start.has_source = true;
  std::strcpy(start.chain_id, "Binance-Chain-Nile");
  receiveMessage(MessageType_MessageType_BinanceSignTx, BinanceSignTx_fields,
                 &start);
  ASSERT_TRUE(binance_signingIsInited());
  HDNode signer = {};
  ASSERT_TRUE(storage_getRootNode("secp256k1", false, &signer));
  hdnode_fill_public_key(&signer);
  BinanceTransferMsg ack = {};
  ack.inputs_count = ack.outputs_count = 1;
  ack.inputs[0].has_address = ack.outputs[0].has_address = true;
  ASSERT_TRUE(tendermint_getAddress(&signer, "tbnb", ack.inputs[0].address));
  std::strcpy(ack.outputs[0].address,
              "tbnb1ss57e8sa7xnwq030k2ctr775uac9gjzglqhvpy");
  ack.inputs[0].coins_count = ack.outputs[0].coins_count = 1;
  ack.inputs[0].coins[0].has_amount = ack.outputs[0].coins[0].has_amount = true;
  ack.inputs[0].coins[0].amount = ack.outputs[0].coins[0].amount = 1;
  ack.inputs[0].coins[0].has_denom = ack.outputs[0].coins[0].has_denom = true;
  std::strcpy(ack.inputs[0].coins[0].denom, "BNB");
  std::strcpy(ack.outputs[0].coins[0].denom, "BNB");
  for (int i = 0; i < 2; ++i) {
    ASSERT_TRUE(kkconfirm_preload(1, 0));
    increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
    receiveMessage(MessageType_MessageType_BinanceTransferMsg,
                   BinanceTransferMsg_fields, &ack);
    ASSERT_EQ(0, kkconfirm_drain());
    ASSERT_TRUE(binance_signingIsInited());
    increment_idle_time(1);
    toggle_screensaver();
    ASSERT_TRUE(binance_signingIsInited());
  }
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 2);
  ack = {};
  receiveMessage(MessageType_MessageType_BinanceTransferMsg,
                 BinanceTransferMsg_fields, &ack);
  EXPECT_FALSE(binance_signingIsInited());
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, CosmosContinuationRenewsAndMalformedAckTerminates) {
  ScopedFlash flash;
  loadAllWallet();
  CosmosSignTx start = {};
  start.has_msg_count = true;
  start.msg_count = 3;
  start.has_account_number = start.has_chain_id = start.has_sequence = true;
  start.has_fee_amount = start.has_gas = true;
  std::strcpy(start.chain_id, "chain-1");
  receiveMessage(MessageType_MessageType_CosmosSignTx, CosmosSignTx_fields,
                 &start);
  ASSERT_TRUE(tendermint_signingIsInited(TENDERMINT_SIGNING_COSMOS));
  HDNode recipient = {};
  const uint8_t seed[32] = {7};
  ASSERT_TRUE(hdnode_from_seed(seed, sizeof(seed), "secp256k1", &recipient));
  hdnode_fill_public_key(&recipient);
  CosmosMsgAck ack = {};
  ack.has_send = ack.send.has_to_address = ack.send.has_amount = true;
  ack.send.amount = 1;
  ASSERT_TRUE(tendermint_getAddress(&recipient, "cosmos", ack.send.to_address));
  for (int i = 0; i < 2; ++i) {
    ASSERT_TRUE(kkconfirm_preload(1, 0));
    increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
    receiveMessage(MessageType_MessageType_CosmosMsgAck, CosmosMsgAck_fields,
                   &ack);
    ASSERT_EQ(0, kkconfirm_drain());
    ASSERT_TRUE(tendermint_signingIsInited(TENDERMINT_SIGNING_COSMOS));
    increment_idle_time(1);
    toggle_screensaver();
    ASSERT_TRUE(tendermint_signingIsInited(TENDERMINT_SIGNING_COSMOS));
  }
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 2);
  ack = {};
  receiveMessage(MessageType_MessageType_CosmosMsgAck, CosmosMsgAck_fields,
                 &ack);
  EXPECT_FALSE(tendermint_signingIsInited(TENDERMINT_SIGNING_COSMOS));
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, OsmosisContinuationRenewsAndMalformedAckTerminates) {
  ScopedFlash flash;
  loadAllWallet();
  OsmosisSignTx start = {};
  start.has_msg_count = true;
  start.msg_count = 3;
  start.has_account_number = start.has_chain_id = start.has_sequence = true;
  start.has_fee_amount = start.has_gas = true;
  std::strcpy(start.chain_id, "chain-1");
  receiveMessage(MessageType_MessageType_OsmosisSignTx, OsmosisSignTx_fields,
                 &start);
  ASSERT_TRUE(osmosis_signingIsInited());
  HDNode recipient = {};
  const uint8_t seed[32] = {7};
  ASSERT_TRUE(hdnode_from_seed(seed, sizeof(seed), "secp256k1", &recipient));
  hdnode_fill_public_key(&recipient);
  OsmosisMsgAck ack = {};
  ack.has_send = ack.send.has_to_address = ack.send.has_amount = true;
  std::strcpy(ack.send.amount, "1");
  ASSERT_TRUE(tendermint_getAddress(&recipient, "osmo", ack.send.to_address));
  ack.send.has_denom = true;
  std::strcpy(ack.send.denom, "uosmo");
  for (int i = 0; i < 2; ++i) {
    ASSERT_TRUE(kkconfirm_preload(1, 0));
    increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
    receiveMessage(MessageType_MessageType_OsmosisMsgAck, OsmosisMsgAck_fields,
                   &ack);
    ASSERT_EQ(0, kkconfirm_drain());
    ASSERT_TRUE(osmosis_signingIsInited());
    increment_idle_time(1);
    toggle_screensaver();
    ASSERT_TRUE(osmosis_signingIsInited());
  }
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 2);
  ack = {};
  receiveMessage(MessageType_MessageType_OsmosisMsgAck, OsmosisMsgAck_fields,
                 &ack);
  EXPECT_FALSE(osmosis_signingIsInited());
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

TEST_F(AutoLockProgress, EosStartRenewsButPollingDoesNot) {
  EosSignTx start = {};
  start.has_chain_id = start.has_header = start.has_num_actions = true;
  start.chain_id.size = 32;
  start.num_actions = 2;
  expectStartRenewsButPollingDoesNot(MessageType_MessageType_EosSignTx,
                                     EosSignTx_fields, &start,
                                     eos_signingIsInited);
}

#endif

// This integration-style case remaps emulator flash and drives the address
// failure UI. Keep it last in the fixture group so its process-global layout
// state cannot contaminate the setup of another AutoLockProgress case.
TEST_F(AutoLockProgress, MalformedMultisigAddressCannotRenewTheDeadline) {
  // Deriving the address caches the root seed and commits storage.
  ScopedFlash flash;

  loadAllWallet();

  SignTx start = {};
  start.inputs_count = start.outputs_count = 1;
  HDNode root = {};
  const uint8_t seed[32] = {1};
  ASSERT_TRUE(hdnode_from_seed(seed, sizeof(seed), "secp256k1", &root));
  signing_init(&start, coinByName("Bitcoin"), &root);
  ASSERT_TRUE(signing_is_active());
  leave_home();

  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  GetAddress malformed = {};
  malformed.has_multisig = true;
  fsm_test_clearLastFailure();
  receiveMessage(MessageType_MessageType_GetAddress, GetAddress_fields,
                 &malformed);
  EXPECT_EQ(FailureType_Failure_Other, fsm_test_lastFailureCode())
      << "the request must reach the multisig rejection, not an earlier gate";
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(signing_is_active());
  EXPECT_EQ(SCREENSAVER, home_get_state());
}

/* Clearing PIN authorization revokes signing, but must not discard a staged
 * setup ceremony: recovery stages before it prompts for the PIN, and every
 * routine PIN entry lands here through the wipe-code probe. */
TEST(Fsm, PinRevocationKeepsAStagedCeremony) {
  fsm_init();
  setup_abort();
  ASSERT_TRUE(setup_stage(false, "english", "dry run", 0, 0, false));

  SessionState session = {};
  Storage storage = {};
  storage.pub.has_pin = true;
  session_clear_impl(&session, &storage, /*clear_pin=*/true);

  setup_arm(SETUP_RECOVERY);
  EXPECT_TRUE(setup_isArmedAs(SETUP_RECOVERY))
      << "the PIN prompt must not disarm the ceremony it was asked for";

  setup_abort();
}

/* ... while the paths that really do end a session still discard it. */
TEST(Fsm, SessionClearDiscardsAStagedCeremony) {
  fsm_init();
  setup_abort();
  ASSERT_TRUE(setup_stage(false, "english", "reset", 0, 0, false));
  setup_arm(SETUP_RESET);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RESET));

  fsm_abort_workflows();
  EXPECT_FALSE(setup_isArmedAs(SETUP_RESET));

  setup_abort();
}

TEST(Fsm, InvalidSecondBitcoinStartTerminatesOldSigning) {
  fsm_init();

  SignTx first = {};
  first.inputs_count = 1;
  first.outputs_count = 1;
  HDNode root = {};
  const CoinType* coin = coinByName("Bitcoin");
  ASSERT_NE(nullptr, coin);

  signing_init(&first, coin, &root);
  ASSERT_TRUE(signing_is_active());

  SignTx invalid = {};
  fsm_msgSignTx(&invalid);
  EXPECT_FALSE(signing_is_active());

  TxAck stale = {};
  stale.has_tx = true;
  fsm_msgTxAck(&stale);
  EXPECT_FALSE(signing_is_active());
}

#if !BITCOIN_ONLY
TEST(Fsm, CrossWorkflowAcknowledgementsTerminateTheActiveSigner) {
  fsm_init();
  HDNode node = {};
  node.curve = &secp256k1_info;

  BinanceSignTx binance = {};
  binance.has_msg_count = true;
  binance.msg_count = 1;
  binance.has_account_number = true;
  binance.has_chain_id = true;
  std::strcpy(binance.chain_id, "Binance-Chain-Nile");
  binance.has_sequence = true;
  binance.has_source = true;
  ASSERT_TRUE(binance_signTxInit(&node, &binance));
  ASSERT_TRUE(binance_signingIsInited());

  CosmosMsgAck cosmos_ack = {};
  receiveMessage(MessageType_MessageType_CosmosMsgAck, CosmosMsgAck_fields,
                 &cosmos_ack);
  EXPECT_FALSE(binance_signingIsInited());

  TendermintSignTx cosmos = {};
  cosmos.has_msg_count = true;
  cosmos.msg_count = 1;
  cosmos.has_chain_id = true;
  std::strcpy(cosmos.chain_id, "cosmoshub-4");
  ASSERT_TRUE(tendermint_signTxInit(&node, &cosmos, sizeof(cosmos), "uatom",
                                    TENDERMINT_SIGNING_COSMOS));
  ASSERT_TRUE(tendermint_signingIsInited(TENDERMINT_SIGNING_COSMOS));

  BinanceTransferMsg binance_ack = {};
  receiveMessage(MessageType_MessageType_BinanceTransferMsg,
                 BinanceTransferMsg_fields, &binance_ack);
  EXPECT_FALSE(tendermint_signingIsInited(TENDERMINT_SIGNING_COSMOS));
}

TEST(Fsm, StaleEthereumAckCannotReplaceARecoveryCeremony) {
  kk_test_board_init();
  fsm_init();
  setup_abort();
  fsm_test_clearLastFailure();

  ASSERT_TRUE(setup_stage(false, "english", "recovery", 0, 0, false));
  setup_arm(SETUP_RECOVERY);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));

  EthereumTxAck stale = {};
  receiveMessage(MessageType_MessageType_EthereumTxAck, EthereumTxAck_fields,
                 &stale);

  EXPECT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  EXPECT_EQ(FailureType_Failure_UnexpectedMessage, fsm_test_lastFailureCode())
      << "the stale ACK was dropped without a terminal host response";

  setup_abort();
  layoutHomeForced();
}
#endif

#if !BITCOIN_ONLY
TEST(Fsm, MissingEosCommonTerminatesSigning) {
  fsm_init();

  HDNode root = {};
  uint8_t chain_id[32] = {};
  EosTxHeader header = {};
  uint32_t path[8] = {};
  eos_signingInit(chain_id, 1, &header, &root, path, 0);
  ASSERT_TRUE(eos_signingIsInited());

  EosTxActionAck missing = {};
  fsm_msgEosTxActionAck(&missing);
  EXPECT_FALSE(eos_signingIsInited());

  EosTxActionAck stale = {};
  stale.has_common = true;
  stale.has_transfer = true;
  fsm_msgEosTxActionAck(&stale);
  EXPECT_FALSE(eos_signingIsInited());
}
#endif

TEST(Fsm, LowLevelPinRevocationTerminatesSigning) {
  fsm_init();
  SignTx start = {};
  start.inputs_count = 1;
  start.outputs_count = 1;
  HDNode root = {};
  const CoinType* coin = coinByName("Bitcoin");
  ASSERT_NE(nullptr, coin);
  signing_init(&start, coin, &root);
  ASSERT_TRUE(signing_is_active());

  SessionState session = {};
  Storage storage = {};
  storage.pub.has_pin = true;
  session_clear_impl(&session, &storage, true);
  EXPECT_FALSE(signing_is_active());
  signing_abort();
}

TEST(Fsm, LowLevelSoftClearPreservesSigning) {
  fsm_init();
  SignTx start = {};
  start.inputs_count = 1;
  start.outputs_count = 1;
  HDNode root = {};
  const CoinType* coin = coinByName("Bitcoin");
  ASSERT_NE(nullptr, coin);
  signing_init(&start, coin, &root);
  ASSERT_TRUE(signing_is_active());

  SessionState session = {};
  Storage storage = {};
  storage.pub.has_pin = true;
  session_clear_impl(&session, &storage, false);
  EXPECT_TRUE(signing_is_active());
  signing_abort();
}

/* A rejected frame must not be able to resume a signing session -- but it must
 * not be able to destroy a setup ceremony either. Every unmapped message id
 * reaches the same handler, and on bitcoin-only firmware that is every
 * multi-chain message a host probes with, so a routine EthereumGetAddress
 * would otherwise memzero a recovery the user is 20 words into. */
TEST(Fsm, TransportFailureEndsSigningButKeepsRecoveryCeremony) {
  kk_test_board_init();
  fsm_init();
  setup_abort();

  ASSERT_TRUE(setup_stage(false, "english", "recovery", 0, 0, false));
  setup_arm(SETUP_RECOVERY);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));

  SignTx start = {};
  start.inputs_count = 1;
  start.outputs_count = 1;
  HDNode root = {};
  const CoinType* coin = coinByName("Bitcoin");
  ASSERT_NE(nullptr, coin);
  signing_init(&start, coin, &root);
  ASSERT_TRUE(signing_is_active());

  // Exactly what lib/board/messages.c does for a message id that is not in
  // the map, via the handler fsm_init() installed.
  call_msg_failure_handler(FailureType_Failure_UnexpectedMessage,
                           "Unknown message");

  EXPECT_FALSE(signing_is_active())
      << "a rejected frame left a signing session a later ack could resume";
  EXPECT_TRUE(setup_isArmedAs(SETUP_RECOVERY))
      << "an unmapped host probe tore down the ceremony the user was in";

  setup_abort();
  layoutHomeForced();
}

TEST(Fsm, TransportFailureDisarmsResetBeforeAStaleEntropyAck) {
  kk_test_board_init();
  fsm_init();
  setup_abort();

  ASSERT_TRUE(setup_stage(false, "english", "reset", 0, 0, false));
  setup_arm(SETUP_RESET);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RESET));

  call_msg_failure_handler(FailureType_Failure_UnexpectedMessage,
                           "Malformed frame");

  EXPECT_FALSE(setup_isArmed())
      << "a rejected frame left reset armed for a stale EntropyAck";
  layoutHomeForced();
}

TEST(Fsm, UnrelatedGetFeaturesDoesNotDeferAnActiveSigningAutoLock) {
  kk_test_board_init();
  fsm_init();
  layoutHomeForced();
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);

  SignTx start = {};
  start.inputs_count = 1;
  start.outputs_count = 1;
  HDNode root = {};
  const CoinType* coin = coinByName("Bitcoin");
  ASSERT_NE(nullptr, coin);
  signing_init(&start, coin, &root);
  ASSERT_TRUE(signing_is_active());

  leave_home();
  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  uint8_t get_features[64] = {'?', '#', '#'};
  get_features[3] =
      static_cast<uint8_t>(MessageType_MessageType_GetFeatures >> 8);
  get_features[4] = static_cast<uint8_t>(MessageType_MessageType_GetFeatures);
  handle_usb_rx(get_features, sizeof(get_features));
  ASSERT_TRUE(signing_is_active());
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_FALSE(signing_is_active());
  EXPECT_EQ(SCREENSAVER, home_get_state());

  layoutHomeForced();
}

TEST(Fsm, WorkflowResponseAtHomeDoesNotDeferTheAutoLock) {
  kk_test_board_init();
  fsm_init();
  layoutHomeForced();
  storage_setAutoLockDelayMs(STORAGE_MIN_SCREENSAVER_TIMEOUT);

  increment_idle_time(STORAGE_MIN_SCREENSAVER_TIMEOUT - 1);
  TxRequest next = {};
  ASSERT_TRUE(msg_write(MessageType_MessageType_TxRequest, &next));
  increment_idle_time(1);
  toggle_screensaver();
  EXPECT_EQ(SCREENSAVER, home_get_state());

  layoutHomeForced();
}

extern "C" {
void reset_probe_begin(int abort_phase);
void reset_probe_end(void);
unsigned reset_probe_seen(void);
unsigned reset_probe_errors(void);
const char* reset_probe_entropy_words(void);
const char* reset_probe_backup_words(void);
}
namespace {
struct ResetProbeScope {
  explicit ResetProbeScope(int abort_phase) { reset_probe_begin(abort_phase); }
  ~ResetProbeScope() { reset_probe_end(); }
};
}  // namespace

TEST(DiceCeremonyPrivacy,
     Mixed128DerivationAndDevicePagesUseIndependentFixture) {
  kk_test_board_init();
  fsm_init();
  ScopedFlash flash;
  ResetProbeScope probe(0);
  // Python hashlib oracle: draw=00..1f, rolls=(123456)*N truncated to 50.
  const uint8_t expected_seed[32] = {
      0xd7, 0x17, 0xae, 0xc4, 0x8f, 0x55, 0x58, 0x59, 0x5a, 0x60, 0x62,
      0xd1, 0xec, 0x03, 0xf9, 0x72, 0x24, 0x63, 0x62, 0x24, 0x56, 0xc6,
      0x31, 0x12, 0x37, 0xdd, 0x95, 0x82, 0x53, 0xf6, 0x24, 0x87};
  const std::string expected_mnemonic = mnemonic_from_data(expected_seed, 16);
  uint8_t draw[32];
  for (unsigned i = 0; i < 32; ++i) draw[i] = i;
  const std::string expected_entropy_words = mnemonic_from_data(draw, 32);
  reset_init(128, false, false, "english", "privacy", false, 0, 0, true, false);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RESET));
  EXPECT_TRUE(reset_debug_is_private());
  EXPECT_EQ(expected_entropy_words, reset_probe_entropy_words());
  const uint8_t host_entropy[32] = {0xa5};
  reset_entropy(host_entropy, sizeof(host_entropy));
  ASSERT_TRUE(storage_hasMnemonic());
  EXPECT_EQ(expected_mnemonic, storage_getMnemonic());
  EXPECT_EQ(expected_mnemonic, reset_probe_backup_words());
  EXPECT_EQ(126u, reset_probe_seen());
  EXPECT_EQ(0u, reset_probe_errors());
  EXPECT_FALSE(reset_debug_is_private());
  EXPECT_FALSE(setup_isArmed());
}

TEST(DiceCeremonyPrivacy,
     Mixed256DerivationAndDevicePagesUseIndependentFixture) {
  kk_test_board_init();
  fsm_init();
  ScopedFlash flash;
  ResetProbeScope probe(0);
  // Python hashlib oracle: draw=00..1f, rolls=(123456)*N truncated to 99.
  const uint8_t expected_seed[32] = {
      0x2d, 0xf1, 0x8b, 0xfa, 0x9b, 0x97, 0xb3, 0x84, 0xb8, 0xd3, 0x05,
      0xcf, 0x7b, 0xe0, 0xa9, 0x98, 0x23, 0x04, 0x51, 0xce, 0x42, 0x5b,
      0xf4, 0x8d, 0xd9, 0x25, 0xf8, 0xb8, 0x70, 0x81, 0x1f, 0x58};
  const std::string expected_mnemonic = mnemonic_from_data(expected_seed, 32);
  uint8_t draw[32];
  for (unsigned i = 0; i < 32; ++i) draw[i] = i;
  const std::string expected_entropy_words = mnemonic_from_data(draw, 32);
  reset_init(256, false, false, "english", "privacy", false, 0, 0, true, false);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RESET));
  EXPECT_TRUE(reset_debug_is_private());
  EXPECT_EQ(expected_entropy_words, reset_probe_entropy_words());
  const uint8_t host_entropy[32] = {0xa5};
  reset_entropy(host_entropy, sizeof(host_entropy));
  ASSERT_TRUE(storage_hasMnemonic());
  EXPECT_EQ(expected_mnemonic, storage_getMnemonic());
  EXPECT_EQ(expected_mnemonic, reset_probe_backup_words());
  EXPECT_EQ(126u, reset_probe_seen());
  EXPECT_EQ(0u, reset_probe_errors());
  EXPECT_FALSE(reset_debug_is_private());
  EXPECT_FALSE(setup_isArmed());
}

TEST(DiceCeremonyPrivacy,
     Only128DerivationAndDevicePagesUseIndependentFixture) {
  kk_test_board_init();
  fsm_init();
  ScopedFlash flash;
  ResetProbeScope probe(0);
  // Python hashlib oracle: draw=00..1f, rolls=(123456)*N truncated to 50.
  const uint8_t expected_seed[32] = {
      0xee, 0x72, 0xae, 0x91, 0x5a, 0x4e, 0x6e, 0xa7, 0xcc, 0xbe, 0xb8,
      0xe5, 0xe5, 0xee, 0xce, 0xf2, 0x9a, 0x1d, 0x0d, 0x90, 0xf0, 0x53,
      0x18, 0x37, 0x26, 0xa4, 0x24, 0xb6, 0xd3, 0xb0, 0x73, 0x25};
  const std::string expected_mnemonic = mnemonic_from_data(expected_seed, 16);
  uint8_t draw[32];
  for (unsigned i = 0; i < 32; ++i) draw[i] = i;
  const std::string expected_entropy_words = mnemonic_from_data(draw, 32);
  reset_init(128, false, false, "english", "privacy", false, 0, 0, true, true);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RESET));
  EXPECT_TRUE(reset_debug_is_private());
  EXPECT_EQ(std::string(), reset_probe_entropy_words());
  const uint8_t host_entropy[32] = {0xa5};
  reset_entropy(host_entropy, sizeof(host_entropy));
  ASSERT_TRUE(storage_hasMnemonic());
  EXPECT_EQ(expected_mnemonic, storage_getMnemonic());
  EXPECT_EQ(expected_mnemonic, reset_probe_backup_words());
  EXPECT_EQ(122u, reset_probe_seen());
  EXPECT_EQ(0u, reset_probe_errors());
  EXPECT_FALSE(reset_debug_is_private());
  EXPECT_FALSE(setup_isArmed());
}

TEST(DiceCeremonyPrivacy,
     Only256DerivationAndDevicePagesUseIndependentFixture) {
  kk_test_board_init();
  fsm_init();
  ScopedFlash flash;
  ResetProbeScope probe(0);
  // Python hashlib oracle: draw=00..1f, rolls=(123456)*N truncated to 99.
  const uint8_t expected_seed[32] = {
      0x55, 0x88, 0xd3, 0x63, 0x0b, 0xd1, 0x9f, 0x63, 0x75, 0xb7, 0xbd,
      0x92, 0x24, 0x57, 0xaf, 0x34, 0xea, 0x9c, 0x74, 0xf0, 0x08, 0x07,
      0x56, 0x6a, 0x1c, 0xf8, 0x08, 0xe4, 0x45, 0xdc, 0x8c, 0x20};
  const std::string expected_mnemonic = mnemonic_from_data(expected_seed, 32);
  uint8_t draw[32];
  for (unsigned i = 0; i < 32; ++i) draw[i] = i;
  const std::string expected_entropy_words = mnemonic_from_data(draw, 32);
  reset_init(256, false, false, "english", "privacy", false, 0, 0, true, true);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RESET));
  EXPECT_TRUE(reset_debug_is_private());
  EXPECT_EQ(std::string(), reset_probe_entropy_words());
  const uint8_t host_entropy[32] = {0xa5};
  reset_entropy(host_entropy, sizeof(host_entropy));
  ASSERT_TRUE(storage_hasMnemonic());
  EXPECT_EQ(expected_mnemonic, storage_getMnemonic());
  EXPECT_EQ(expected_mnemonic, reset_probe_backup_words());
  EXPECT_EQ(122u, reset_probe_seen());
  EXPECT_EQ(0u, reset_probe_errors());
  EXPECT_FALSE(reset_debug_is_private());
  EXPECT_FALSE(setup_isArmed());
}

TEST(DiceCeremonyPrivacy, AbortAtEveryPhaseWipesAndAllowsOrdinaryRestart) {
  kk_test_board_init();
  fsm_init();
  for (int phase = 1; phase <= 6; ++phase) {
    SCOPED_TRACE(phase);
    ScopedFlash flash;
    ResetProbeScope probe(phase);
    reset_init(128, false, false, "english", "abort", false, 0, 0, true, false);
    if (setup_isArmed()) {
      const uint8_t external[32] = {1};
      reset_entropy(external, sizeof(external));
    }
    EXPECT_NE(0u, reset_probe_seen() & (1u << phase));
    EXPECT_EQ(0u, reset_probe_errors());
    EXPECT_FALSE(setup_isArmed());
    EXPECT_FALSE(reset_debug_is_private());
    EXPECT_FALSE(storage_hasMnemonic());
    EXPECT_STREQ("", reset_get_word());
    uint8_t bytes[32] = {};
    EXPECT_EQ(32u, reset_get_int_entropy(bytes));
    for (uint8_t byte : bytes) EXPECT_EQ(0, byte);
    EXPECT_EQ(0u, reset_get_dice_digest(bytes));
    reset_init(128, false, false, "english", "ordinary", false, 0, 0, false,
               false);
    ASSERT_TRUE(setup_isArmedAs(SETUP_RESET));
    EXPECT_FALSE(reset_debug_is_private());
    ASSERT_EQ(32u, reset_get_int_entropy(bytes));
    for (unsigned i = 0; i < 32; ++i) EXPECT_EQ(i, bytes[i]);
  }
}

// DebugLinkGetState is also serviced inside the PIN, passphrase and confirm
// waits. The suspended outer handler may already hold its pending response in
// the shared RESP_INIT arena, so the debug reply must not be built there.
TEST(Fsm, DebugLinkGetStateLeavesPendingResponseIntact) {
  kk_test_board_init();
  fsm_init();
  ScopedFlash flash;
  size_t size = 0;
  uint8_t* arena = fsm_test_responseArena(&size);
  ASSERT_NE(nullptr, arena);
  ASSERT_GT(size, 0u);
  std::memset(arena, 0x5a, size);
  DebugLinkGetState get = {};
  fsm_msgDebugLinkGetState(&get);
  for (size_t i = 0; i < size; ++i) ASSERT_EQ(0x5a, arena[i]) << "offset " << i;
}

// FlashDump arrives on the debug endpoint, so its private-display refusal must
// be answered there, without memory; a normal-channel Failure leaves the debug
// caller waiting.
TEST(Fsm, PrivateDisplayFlashDumpRefusalAnswersOnDebugChannel) {
  ASSERT_TRUE(kkconfirm_openDebugPeer());
  DebugLinkFlashDump dump = {};
  dump.has_address = dump.has_length = true;
  dump.address = 0x20000000;
  dump.length = 32;
  bip85_set_private_display(true);
  fsm_test_clearLastFailure();
  fsm_msgDebugLinkFlashDump(&dump);
  bip85_set_private_display(false);
  EXPECT_EQ(FailureType_Failure_UnexpectedMessage, fsm_test_lastFailureCode());

  // One frame: an empty DebugLinkFlashDumpResponse, i.e. no memory bytes.
  uint8_t frame[64] = {};
  ASSERT_TRUE(kkconfirm_readDebugFrame(frame));
  EXPECT_EQ('#', frame[1]);
  EXPECT_EQ('#', frame[2]);
  EXPECT_EQ(MessageType_MessageType_DebugLinkFlashDumpResponse,
            (frame[3] << 8) | frame[4]);
  EXPECT_EQ(0, frame[5] | frame[6] | frame[7] | frame[8]);
}

TEST(DiceCeremonyPrivacy, AbortClearsCanvasBeforeDiagnosticsResume) {
  kk_test_board_init();
  fsm_init();
  ScopedFlash flash;
  ResetProbeScope probe(0);
  reset_init(128, false, false, "english", "canvas", false, 0, 0, true, false);
  ASSERT_TRUE(reset_debug_is_private());
  Canvas* canvas = display_canvas();
  ASSERT_NE(nullptr, canvas->buffer);
  const size_t size = canvas->width * canvas->height;
  std::memset(canvas->buffer, 0xa5, size);
  DebugLinkFlashDump dump = {};
  dump.has_address = dump.has_length = true;
  dump.address = 0x20000000;
  dump.length = 32;
  fsm_test_clearLastFailure();
  fsm_msgDebugLinkFlashDump(&dump);
  EXPECT_EQ(FailureType_Failure_UnexpectedMessage, fsm_test_lastFailureCode());
  setup_abort();
  EXPECT_FALSE(reset_debug_is_private());
  for (size_t i = 0; i < size; ++i) ASSERT_EQ(0, canvas->buffer[i]);
}

TEST(DiceCeremonyPrivacy, AbortClearsConfirmTextBeforeDiagnosticsResume) {
  kk_test_board_init();
  fsm_init();
  ScopedFlash flash;
  ResetProbeScope probe(0);
  reset_init(128, false, false, "english", "text", false, 0, 0, true, false);
  ASSERT_TRUE(reset_debug_is_private());
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  ASSERT_TRUE(confirm(ButtonRequestType_ButtonRequest_DiceRoll, "Dice Rolls",
                      "%s", "private page"));
  EXPECT_EQ(0, kkconfirm_drain());
  ASSERT_STREQ("private page", confirm_debug_body());
  setup_abort();
  EXPECT_FALSE(reset_debug_is_private());
  EXPECT_STREQ("", confirm_debug_title());
  EXPECT_STREQ("", confirm_debug_body());
}

TEST(Fsm, Bip85CompletionAndCancelClearConfirmText) {
  kk_test_board_init();
  fsm_init();
  ScopedFlash flash;
  struct WipeOnExit {
    ~WipeOnExit() { storage_wipe(); }
  } cleanup;
  LoadDevice load = allLoad();
  storage_loadDevice(&load);
  GetBip85Mnemonic request = {};
  request.word_count = 12;
  for (bool cancel : {false, true}) {
    SCOPED_TRACE(cancel);
    // Approve the derivation prompt, then every page or only the first.
    ASSERT_TRUE(kkconfirm_preload(cancel ? 2 : 20, cancel ? 1 : 0));
    fsm_test_clearLastFailure();
    fsm_msgGetBip85Mnemonic(&request);
    EXPECT_EQ(cancel ? FailureType_Failure_ActionCancelled : 0,
              static_cast<int>(fsm_test_lastFailureCode()));
    kkconfirm_drain();
    EXPECT_FALSE(bip85_debug_is_private());
    EXPECT_STREQ("", confirm_debug_title());
    EXPECT_STREQ("", confirm_debug_body());
  }
}

TEST(Fsm, LockedStorageRefusesResetAndSetupCommitWithoutChangingFlash) {
  kk_test_board_init();
  fsm_init();
  const uint32_t versions[] = {
#if BITCOIN_ONLY
      STORAGE_VERSION_BTC_ONLY_BASE + STORAGE_VERSION + 1,
#else
      STORAGE_VERSION + 1,
      STORAGE_VERSION_BTC_ONLY_BASE + STORAGE_VERSION,
#endif
  };
  for (uint32_t version : versions) {
    SCOPED_TRACE(version);
    ScopedFlash flash;
    struct WipeOnExit {
      ~WipeOnExit() { storage_wipe(); }
    } cleanup;
    auto* active =
        reinterpret_cast<uint8_t*>(flash_write_helper(storage_getLocation()));
    std::memcpy(active + 44, &version, sizeof(version));
    storage_init();
    ASSERT_TRUE(storage_isFirmwareTooOld() || storage_isBitcoinOnlyLocked());
    const auto before = flash.bytes;
    ResetDevice reset = {};
    reset.has_strength = true;
    reset.strength = 128;
    fsm_test_clearLastFailure();
    receiveMessage(MessageType_MessageType_ResetDevice, ResetDevice_fields,
                   &reset);
    // Same split as IncompatibleStorage.CreationRefusesBeforeStagingOrConfirmation:
    // bitcoin-only locks keep Failure_Other (CHECK_NOT_BTC_ONLY_LOCKED); a
    // normal-band wallet newer than this build is UnexpectedMessage
    // (CHECK_STORAGE_WRITABLE).
    EXPECT_EQ(storage_isBitcoinOnlyLocked()
                  ? FailureType_Failure_Other
                  : FailureType_Failure_UnexpectedMessage,
              fsm_test_lastFailureCode());
    EXPECT_FALSE(setup_isArmed());
    ASSERT_TRUE(setup_stage(false, "english", "blocked", 0, 0, false));
    setup_arm(SETUP_RESET);
    fsm_test_clearLastFailure();
    EXPECT_FALSE(setup_commit(
        SETUP_RESET, "all all all all all all all all all all all all", false));
    EXPECT_EQ(FailureType_Failure_UnexpectedMessage,
              fsm_test_lastFailureCode());
    EXPECT_FALSE(setup_isArmed());
    EXPECT_FALSE(storage_hasMnemonic());
    EXPECT_EQ(before, flash.bytes);
  }
}

// 7.14.3: every settings handler refuses a locked wallet before asking for a
// button press. firmware-unit maps no flash (see ScopedFlash), so the locked
// image is a scratch one instead of setup()'s global mapping.
TEST(Fsm, BitcoinOnlyLockRefusesSettingsHandlersBeforeAnyConfirm) {
  kk_test_board_init();
  fsm_init();
  ScopedFlash flash;

  flash_erase_word(FLASH_STORAGE1);
  flash_erase_word(FLASH_STORAGE2);
  flash_erase_word(FLASH_STORAGE3);
#if BITCOIN_ONLY
  // In-band but NEWER than this build understands -- the only way a
  // bitcoin-only image reaches the same lock.
  const uint32_t version = STORAGE_VERSION_BTC_ONLY + 1;
#else
  const uint32_t version = STORAGE_VERSION_BTC_ONLY;
#endif
  ASSERT_TRUE(flash_write(FLASH_STORAGE1, 0, STORAGE_MAGIC_LEN,
                          (const uint8_t*)STORAGE_MAGIC_STR));
  // Offset 44: the version word, immediately after the 44-byte Metadata.
  ASSERT_TRUE(flash_write(FLASH_STORAGE1, 44, sizeof(version),
                          (const uint8_t*)&version));
  storage_init();
  ASSERT_TRUE(storage_isBitcoinOnlyLocked());
  ASSERT_FALSE(storage_isInitialized());

  ApplyPolicies policies = {};
  policies.policy_count = 1;
  policies.policy[0].has_policy_name = true;
  std::strcpy(policies.policy[0].policy_name, "AdvancedMode");
  policies.policy[0].has_enabled = true;
  policies.policy[0].enabled = true;
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  fsm_msgApplyPolicies(&policies);
  EXPECT_EQ(0, kkconfirm_drain())
      << "ApplyPolicies asked for a button press it could never persist";
  EXPECT_FALSE(storage_isPolicyEnabled("AdvancedMode"))
      << "the policy changed in RAM only, so this boot disagrees with flash";

  ApplySettings settings = {};
  settings.has_label = true;
  std::strcpy(settings.label, "locked");
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  fsm_msgApplySettings(&settings);
  EXPECT_EQ(0, kkconfirm_drain())
      << "ApplySettings asked for a button press it could never persist";

  ChangePin pin = {};
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  fsm_msgChangePin(&pin);
  EXPECT_EQ(0, kkconfirm_drain())
      << "ChangePin ran the Create PIN ceremony on a device it cannot write";

  // Authenticator account changes persist too; storage_commit() would drop
  // them silently, so the command must be refused rather than succeed.
  Ping auth = {};
  auth.has_message = true;
  std::strcpy(auth.message, "\x15initializeAuth:JBSWY3DPEHPK3PXP");
  fsm_test_clearLastFailure();
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  fsm_msgPing(&auth);
  EXPECT_EQ(0, kkconfirm_drain());
  EXPECT_EQ(FailureType_Failure_UnexpectedMessage, fsm_test_lastFailureCode())
      << "an authenticator write on a locked wallet must be refused";

  storage_wipe();
  EXPECT_FALSE(storage_isBitcoinOnlyLocked());
  layoutHomeForced();
}

#if !BITCOIN_ONLY
// 7.14.3: a recipient-mismatch compile error must still scrub the derived
// node. Uses ScopedFlash for the same reason as the test above.
TEST(Fsm, EthereumTransferRecipientMismatchWipesDerivedNode) {
  kk_test_board_init();
  fsm_init();
  ScopedFlash flash;
  storage_wipe();
  LoadDevice load = allLoad();
  storage_loadDevice(&load);
  ASSERT_TRUE(storage_isInitialized());

  const uint8_t usdc[20] = {0xa0, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b,
                            0x36, 0xc1, 0xd1, 0x9d, 0x4a, 0x2e, 0x9e,
                            0xb0, 0xce, 0x36, 0x06, 0xeb, 0x48};
  const TokenType* token = tokenByChainAddress(1, usdc);
  ASSERT_NE(UnknownToken, token);
  EthereumSignTx msg = {};
  msg.has_chain_id = true;
  msg.chain_id = 1;
  msg.has_address_type = true;
  msg.address_type = OutputAddressType_TRANSFER;
  msg.to_address_n_count = 5;
  const uint32_t path[5] = {0x8000002c, 0x8000003c, 0x80000000, 0, 0};
  memcpy(msg.to_address_n, path, sizeof(path));
  msg.has_to = true;
  msg.to.size = 20;
  memcpy(msg.to.bytes, token->address, 20);
  msg.has_data_length = true;
  msg.data_length = 68;
  msg.has_data_initial_chunk = true;
  msg.data_initial_chunk.size = 68;
  memcpy(msg.data_initial_chunk.bytes, "\xa9\x05\x9c\xbb", 4);
  msg.data_initial_chunk.bytes[67] = 1;
  ASSERT_TRUE(ethereum_isStandardERC20Transfer(&msg));

  // The ABI recipient is zero; prove it differs from the derived account.
  HDNode node = {};
  ASSERT_TRUE(storage_getRootNode(SECP256K1_NAME, true, &node));
  ASSERT_TRUE(hdnode_private_ckd_cached(&node, path, 5, nullptr));
  uint8_t recipient[20] = {};
  ASSERT_TRUE(hdnode_get_ethereum_pubkeyhash(&node, recipient));
  const uint8_t zeros[20] = {};
  ASSERT_NE(0, memcmp(recipient, zeros, sizeof(recipient)));

  ASSERT_TRUE(kkconfirm_preload(1, 0));
  fsm_test_seedDerivedNode();
  fsm_msgEthereumSignTx(&msg);
  EXPECT_EQ(0, kkconfirm_drain()) << "must reach the transfer approval";
  EXPECT_TRUE(fsm_test_derivedNodeIsZero());
  storage_wipe();
  layoutHomeForced();
}
#endif
