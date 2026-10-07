extern "C" {
#include "keepkey/board/memory.h"
#include "keepkey/board/layout.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/app_confirm.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/firmware/reset.h"
#include "keepkey/firmware/ripple.h"
#include "keepkey/firmware/tron.h"
#include "keepkey/firmware/mayachain.h"
#include "keepkey/firmware/thorchain.h"
#include "keepkey/firmware/bip85.h"
#include "keepkey/firmware/signed_metadata.h"
#include "storage.h"
}
#include "gtest/gtest.h"
#include <cstring>
#include <algorithm>
#include <string>
#include <vector>

// After the C++ headers: confirm_sm.h defines isprint() as a macro.
extern "C" {
#include "keepkey/board/confirm_sm.h"
}

bool kkconfirm_preload(int, int);
void kkconfirm_capture_start(void);
std::vector<std::string> kkconfirm_capture_finish(void);
int kkconfirm_drain(void);

class ReviewHandlers : public ::testing::Test {
 protected:
  std::vector<uint8_t> flash = std::vector<uint8_t>(FLASH_TOTAL_SIZE, 0xff);
  uint8_t* previous;
  void SetUp() override {
    ASSERT_TRUE(kkconfirm_preload(0, 0));
    ASSERT_EQ(0, kkconfirm_drain());
    previous = emulator_flash_base;
    emulator_flash_base = flash.data();
    storage_init();
    LoadDevice load = {};
    load.has_mnemonic = true;
    strcpy(load.mnemonic, "all all all all all all all all all all all all");
    storage_loadDevice(&load);
    fsm_test_clearLastFailure();
  }
  void TearDown() override {
    fsm_abort_workflows();
    kkconfirm_drain();
#if !BITCOIN_ONLY
    signed_metadata_clear_signers();
#endif
    storage_wipe();
    storage_reset();
    emulator_flash_base = previous;
  }
};

TEST_F(ReviewHandlers, StorageReinitializationRecomputesFirmwareLock) {
  storage_commit();
  const auto normal_flash = flash;
  char record[STORAGE_SECTOR_LEN] = {};
  memcpy(record, "stor", 4);
  record[44] = STORAGE_VERSION + 1;
  std::fill(flash.begin(), flash.end(), 0xff);
  memcpy(flash.data() + 0x4000, record, sizeof(record));
  storage_init();
  ASSERT_TRUE(storage_isFirmwareTooOld());
  flash = normal_flash;
  storage_init();
  EXPECT_FALSE(storage_isFirmwareTooOld());
  EXPECT_FALSE(storage_isBitcoinOnlyLocked());
  LoadDevice load = {};
  load.has_mnemonic = true;
  strcpy(load.mnemonic, "all all all all all all all all all all all all");
  storage_loadDevice(&load);
  EXPECT_TRUE(storage_isInitialized());
}

static void expect_mnemonic_scratch_cleared() {
  for (char c : mnemonic_scratch_tokened) EXPECT_EQ(0, c);
  for (const auto& page : mnemonic_scratch_formatted)
    for (char c : page) EXPECT_EQ(0, c);
  for (char c : mnemonic_scratch_display) EXPECT_EQ(0, c);
  for (char c : mnemonic_scratch_word) EXPECT_EQ(0, c);
}

TEST_F(ReviewHandlers, ResetCancellationClearsScratchBeforeAndAfterFormatting) {
  const auto unchanged = flash;
  const uint8_t entropy[32] = {};
  for (int accepted : {0, 1}) {
    SCOPED_TRACE(accepted);
    reset_init(256, false, false, "english", "reset", false, 0, 0, false,
               false);
    ASSERT_TRUE(setup_isArmedAs(SETUP_RESET));
    // Exercise early cancellation with dirty shared scratch as well as the
    // cancellation reached after actual seed formatting.
    memset(mnemonic_scratch_formatted, 's', sizeof(mnemonic_scratch_formatted));
    memset(mnemonic_scratch_display, 's', sizeof(mnemonic_scratch_display));
    memset(mnemonic_scratch_word, 's', sizeof(mnemonic_scratch_word));
    ASSERT_TRUE(kkconfirm_preload(accepted, 1));
    reset_entropy(entropy, sizeof(entropy));
    EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
    EXPECT_FALSE(setup_isArmed());
    EXPECT_EQ(unchanged, flash);
    EXPECT_EQ(0, kkconfirm_drain());
    expect_mnemonic_scratch_cleared();
  }
}

TEST_F(ReviewHandlers, ResetWithoutBackupCommitsAndClearsScratch) {
  const uint8_t entropy[32] = {};
  ASSERT_TRUE(kkconfirm_preload(2, 0));
  reset_init(128, false, false, "english", "reset", true, 0, 0, false, false);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RESET));
  reset_entropy(entropy, sizeof(entropy));
  EXPECT_FALSE(setup_isArmed());
  EXPECT_EQ(0, fsm_test_lastFailureCode());
  EXPECT_EQ(0, kkconfirm_drain());
  EXPECT_TRUE(storage_isInitialized());
  EXPECT_STREQ("reset", storage_getLabel());
  expect_mnemonic_scratch_cleared();
}

TEST_F(ReviewHandlers, ResetBackupCommitsAllStrengthsAndClearsScratch) {
  const uint8_t entropy[32] = {};
  for (uint32_t strength : {128u, 192u, 256u}) {
    SCOPED_TRACE(strength);
    fsm_test_clearLastFailure();
    reset_init(strength, false, false, "english", "backed up", false, 0, 0,
               false, false);
    ASSERT_TRUE(setup_isArmedAs(SETUP_RESET));
    ASSERT_TRUE(kkconfirm_preload(20, 0));
    reset_entropy(entropy, sizeof(entropy));
    EXPECT_FALSE(setup_isArmed());
    EXPECT_EQ(0, fsm_test_lastFailureCode());
    EXPECT_GE(kkconfirm_drain(), 0);
    EXPECT_STREQ("backed up", storage_getLabel());
    const char* words = storage_getMnemonic();
    ASSERT_NE(nullptr, words);
    EXPECT_EQ(strength * 3 / 32,
              1u + std::count(words, words + strlen(words), ' '));
    expect_mnemonic_scratch_cleared();
  }
}

#if !BITCOIN_ONLY
TEST_F(ReviewHandlers, RippleMemoReachesReviewBeforeSigning) {
  RippleSignTx msg = {};
  msg.has_payment = true;
  msg.payment.has_amount = true;
  msg.payment.amount = 1000000;
  msg.payment.has_destination = true;
  strcpy(msg.payment.destination, "rNaqKtKrMSwpwZSzRckPf7S96DkimjkF4H");
  msg.has_fee = true;
  msg.fee = RIPPLE_MIN_FEE;
  msg.has_memo = true;
  strcpy(msg.memo, "Memo review must be reached");
  ASSERT_TRUE(kkconfirm_preload(1, 1));
  fsm_test_clearLastFailure();
  fsm_msgRippleSignTx(&msg);
  EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
  EXPECT_EQ(0, kkconfirm_drain());
}

static const uint8_t review_pubkey[33] = {
    0x02, 0xe3, 0xb3, 0x01, 0x5c, 0x47, 0xdd, 0xca, 0xab, 0xe4, 0xf8,
    0xe8, 0x72, 0xf1, 0xed, 0x8f, 0x09, 0xca, 0x14, 0x5a, 0x8d, 0x81,
    0x77, 0x0d, 0x92, 0x21, 0x3d, 0x56, 0xda, 0x31, 0xab, 0x51, 0x07};

TEST_F(ReviewHandlers, SessionEndClearsRuntimeSignerAndAlias) {
  ASSERT_TRUE(signed_metadata_store_signer(3, review_pubkey, "Session signer",
                                           nullptr, 0, 0, 0, false));
  ASSERT_TRUE(signed_metadata_signer_is_runtime(3));
  ASSERT_NE(nullptr, signed_metadata_signer_alias(3));
  ClearSession clear = {};
  fsm_msgClearSession(&clear);
  EXPECT_FALSE(signed_metadata_signer_is_runtime(3));
  EXPECT_EQ(nullptr, signed_metadata_signer_alias(3));

  ASSERT_TRUE(signed_metadata_store_signer(3, review_pubkey, "Next session",
                                           nullptr, 0, 0, 0, false));
  Initialize initialize = {};
  fsm_msgInitialize(&initialize);
  EXPECT_FALSE(signed_metadata_signer_is_runtime(3));
  EXPECT_EQ(nullptr, signed_metadata_signer_alias(3));
}

TEST_F(ReviewHandlers, ReopeningFlashClearsRuntimeSigner) {
  ASSERT_TRUE(signed_metadata_store_signer(3, review_pubkey, "Old wallet",
                                           nullptr, 0, 0, 0, false));
  ASSERT_TRUE(signed_metadata_signer_is_runtime(3));
  storage_init();
  EXPECT_FALSE(signed_metadata_signer_is_runtime(3));
  EXPECT_EQ(nullptr, signed_metadata_signer_alias(3));
}

TEST_F(ReviewHandlers, MetadataKeyIdRefusesNarrowingBeforeAck) {
  // The handler's AdvancedMode gate (added after 00b's version of this test)
  // answers ActionCancelled first; enable it so the key_id check is reached.
  ASSERT_TRUE(storage_setPolicy("AdvancedMode", true));
  for (uint32_t key_id :
       {static_cast<uint32_t>(METADATA_MAX_KEYS), 256u, 0xffffffffu}) {
    EthereumTxMetadata msg = {};
    msg.has_key_id = true;
    msg.key_id = key_id;
    fsm_test_clearLastFailure();
    fsm_msgEthereumTxMetadata(&msg);
    EXPECT_EQ(FailureType_Failure_Other, fsm_test_lastFailureCode());
  }
}

TEST_F(ReviewHandlers, Bip85DerivationMatchesIndependentBip32Oracle) {
  char child[241] = {};
  ASSERT_TRUE(bip85_derive_mnemonic(12, 0, child, sizeof(child)));
  EXPECT_STREQ(
      "eternal siege creek hand combine grass name balance identify "
      "rude ozone truly",
      child);
  EXPECT_FALSE(bip85_derive_mnemonic(15, 0, child, sizeof(child)));
  EXPECT_FALSE(bip85_derive_mnemonic(12, 0x80000000u, child, sizeof(child)));
  GetBip85Mnemonic request = {};
  request.word_count = 12;
  request.index = 0;
  ASSERT_TRUE(kkconfirm_preload(0, 1));
  fsm_test_clearLastFailure();
  fsm_msgGetBip85Mnemonic(&request);
  EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
  EXPECT_EQ(0, kkconfirm_drain());

  ASSERT_TRUE(kkconfirm_preload(20, 0));
  fsm_test_clearLastFailure();
  fsm_msgGetBip85Mnemonic(&request);
  EXPECT_EQ(0, fsm_test_lastFailureCode());
  EXPECT_EQ(32, kkconfirm_drain());  // 20 pairs queued, 4 screens approved
  for (char byte : mnemonic_scratch_tokened) EXPECT_EQ(0, byte);
  for (const auto& page : mnemonic_scratch_formatted)
    for (char byte : page) EXPECT_EQ(0, byte);
  for (char byte : mnemonic_scratch_display) EXPECT_EQ(0, byte);
  for (char byte : mnemonic_scratch_word) EXPECT_EQ(0, byte);
}

// The consent screen for a runtime clear-sign signer must render the identity
// the way every later per-transaction identity screen will. A ZCASH_PRIVACY
// build stores no session icons, so it must not draw the host icon at
// consent either. Observable through the body width: an alias that fits one
// screen at BODY_WIDTH but not beside an icon pages only when the icon is
// drawn.
TEST_F(ReviewHandlers, ClearsignSignerConsentDrawsTheIconOnlyWhereItIsKept) {
  static const uint8_t kIcon[] = {0x04, 0xFF};  // 2x2, one run of four
  const char fingerprint[] = "0123456789abcdef";
  std::string alias;
  for (size_t n = 1; n <= METADATA_ALIAS_MAX_LEN; ++n) {
    const std::string candidate(n, 'W');
    char body[160];
    snprintf(body, sizeof(body),
             "Trust '%s' (%s) for this session to describe transactions? NOT "
             "verified by KeepKey.",
             candidate.c_str(), fingerprint);
    if (confirm_body_fits(body, BODY_WIDTH) &&
        !confirm_body_fits(body, BODY_WIDTH_WITH_ICON)) {
      alias = candidate;
      break;
    }
  }
  ASSERT_FALSE(alias.empty()) << "no alias separates the two body widths";

  ASSERT_TRUE(kkconfirm_preload(4, 0));
  kkconfirm_capture_start();
  EXPECT_TRUE(signed_metadata_confirm_load(alias.c_str(), fingerprint, kIcon, 2,
                                           2, sizeof(kIcon)));
  const auto screens = kkconfirm_capture_finish();
  (void)kkconfirm_drain();
#if ZCASH_PRIVACY
  EXPECT_EQ(1u, screens.size()) << "icon drawn at consent but never again";
#else
  EXPECT_GT(screens.size(), 1u) << "icon kept for the session but not shown";
#endif
}

// Handler-level regression for the BIP-85 pager. Index 84 of this seed is a
// 24-word child whose last page, packed at BODY_WIDTH, needs more rows than
// the constant-power canvas has (measured; 35 of the first 2000 24-word
// children overflow like this). Unpaged, that page reaches the renderer as
// one screen and its tail is never drawn; paged, every screen must fit.
TEST_F(ReviewHandlers, Bip85SeedScreensAllFitTheConstantPowerCanvas) {
  GetBip85Mnemonic request = {};
  request.word_count = 24;
  request.index = 84;
  ASSERT_TRUE(kkconfirm_preload(40, 0));
  kkconfirm_capture_start();
  fsm_test_clearLastFailure();
  fsm_msgGetBip85Mnemonic(&request);
  const auto screens = kkconfirm_capture_finish();
  EXPECT_EQ(0, fsm_test_lastFailureCode());
  (void)kkconfirm_drain();

  size_t seed_screens = 0;
  for (const auto& body : screens) {
    const size_t first = body.find_first_not_of(' ');
    if (first == std::string::npos || (body[first] < '0' || body[first] > '9'))
      continue;  // the "BIP-85 Derive Seed" confirmation, not a seed page
    ++seed_screens;
    EXPECT_TRUE(confirm_body_fits_constant_power(body.c_str(),
                                                 CONSTANT_POWER_BODY_WIDTH))
        << "seed screen does not fit: " << body;
  }
  EXPECT_GE(seed_screens, 6u) << "every packed page must reach the screen";
}

static TronSignMessage message(size_t size, bool binary) {
  TronSignMessage msg = {};
  msg.address_n_count = 3;
  msg.address_n[0] = 0x80000000 | 44;
  msg.address_n[1] = 0x80000000 | 195;
  msg.address_n[2] = 0x80000000;
  msg.has_message = true;
  msg.message.size = size;
  memset(msg.message.bytes, binary ? 0 : 'W', size);
  if (size) msg.message.bytes[size - 1] = 'Z';
  return msg;
}

TEST_F(ReviewHandlers, MissingAndEmptyTronMessageNeverRequestsConsent) {
  for (bool present : {false, true}) {
    auto msg = message(0, false);
    msg.has_message = present;
    ASSERT_TRUE(kkconfirm_preload(0, 1));
    fsm_test_clearLastFailure();
    fsm_msgTronSignMessage(&msg);
    EXPECT_EQ(FailureType_Failure_Other, fsm_test_lastFailureCode());
    EXPECT_EQ(2, kkconfirm_drain());
  }
}

static int page_count(const uint8_t* bytes, size_t size) {
  int pages = 0;
  for (size_t offset = 0; offset < size; ++pages) {
    char page[BODY_CHAR_MAX];
    size_t n = confirm_bytes_format_page(bytes + offset, size - offset, page,
                                         sizeof(page));
    if (!n) return 0;
    offset += n;
  }
  return pages;
}

TEST_F(ReviewHandlers, RejectTronSignedAndVerifiedMessageTail) {
  for (bool binary : {false, true}) {
    auto msg = message(200, binary);
    const int pages = page_count(msg.message.bytes, msg.message.size);
    ASSERT_GT(pages, 1);
    ASSERT_TRUE(kkconfirm_preload(pages - 1, 1));
    fsm_test_clearLastFailure();
    fsm_msgTronSignMessage(&msg);
    EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
    EXPECT_EQ(0, kkconfirm_drain());

    HDNode node = {};
    ASSERT_TRUE(storage_getRootNode("secp256k1", true, &node));
    for (uint32_t step : {msg.address_n[0], msg.address_n[1], msg.address_n[2]})
      ASSERT_TRUE(hdnode_private_ckd(&node, step));
    hdnode_fill_public_key(&node);
    TronMessageSignature signature = {};
    ASSERT_TRUE(tron_message_sign(&node, &msg, &signature));
    TronVerifyMessage verify = {};
    verify.has_message = verify.has_signature = verify.has_address = true;
    verify.message.size = msg.message.size;
    memcpy(verify.message.bytes, msg.message.bytes, msg.message.size);
    verify.signature.size = signature.signature.size;
    memcpy(verify.signature.bytes, signature.signature.bytes,
           signature.signature.size);
    strcpy(verify.address, signature.address);
    ASSERT_EQ(0, tron_message_verify(&verify));
    ASSERT_TRUE(kkconfirm_preload(pages, 1));  // signer + all but final page
    fsm_test_clearLastFailure();
    fsm_msgTronVerifyMessage(&verify);
    EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
    EXPECT_EQ(0, kkconfirm_drain());
  }
}

TEST_F(ReviewHandlers, MayaDefaultDenomReachesConsentForMissingAndEmptyField) {
  for (bool present : {false, true}) {
    HDNode node = {};
    ASSERT_TRUE(storage_getRootNode("secp256k1", true, &node));
    hdnode_fill_public_key(&node);
    MayachainSignTx tx = {};
    tx.has_chain_id = tx.has_msg_count = true;
    strcpy(tx.chain_id, "mayachain");
    tx.msg_count = 1;
    ASSERT_TRUE(mayachain_signTxInit(&node, &tx));
    MayachainMsgAck ack = {};
    ack.has_send = true;
    ack.send.has_to_address = ack.send.has_amount = true;
    ack.send.amount = 1;
    ack.send.has_denom = present;
    strcpy(ack.send.to_address, "maya1g9el7lzjwh9yun2c4jjzhy09j98vkhfxfqkl5k");
    // Accept output and asset, reject the final "Sign ... on ...?" screen.
    ASSERT_TRUE(kkconfirm_preload(2, 1));
    fsm_test_clearLastFailure();
    kkconfirm_capture_start();
    fsm_msgMayachainMsgAck(&ack);
    const auto screens = kkconfirm_capture_finish();
    EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
    EXPECT_FALSE(mayachain_signingIsInited());
    EXPECT_EQ(0, kkconfirm_drain());
    EXPECT_NE(
        screens.end(),
        std::find_if(screens.begin(), screens.end(), [](const std::string& s) {
          return s.rfind("Sign cacao on mayachain?", 0) == 0;
        }));
  }
}

// The THORChain signing screen names the denom actually sent, never "RUNE"
// for a non-rune MsgSend.
TEST_F(ReviewHandlers, ThorchainSignScreenNamesTheSentDenom) {
  // The default denom keeps the screen it always had.
  const std::pair<const char*, const char*> cases[] = {{"tcy", "tcy"},
                                                       {"rune", "RUNE"}};
  for (const auto& c : cases) {
    const char* denom = c.first;
    HDNode node = {};
    ASSERT_TRUE(storage_getRootNode("secp256k1", true, &node));
    hdnode_fill_public_key(&node);
    ThorchainSignTx tx = {};
    tx.has_chain_id = tx.has_msg_count = true;
    strcpy(tx.chain_id, "thorchain-1");
    tx.msg_count = 1;
    ASSERT_TRUE(thorchain_signTxInit(&node, &tx));
    ThorchainMsgAck ack = {};
    ack.has_send = true;
    ack.send.has_to_address = ack.send.has_amount = ack.send.has_denom = true;
    ack.send.amount = 1;
    strcpy(ack.send.denom, denom);
    strcpy(ack.send.to_address, "thor1am058pdux3hyulcmfgj4m3hhrlfn8nzmpq9u6l");
    // Accept output and asset, reject the final "Sign ... on ...?" screen.
    ASSERT_TRUE(kkconfirm_preload(2, 1));
    fsm_test_clearLastFailure();
    kkconfirm_capture_start();
    fsm_msgThorchainMsgAck(&ack);
    const auto screens = kkconfirm_capture_finish();
    EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
    EXPECT_FALSE(thorchain_signingIsInited());
    EXPECT_EQ(0, kkconfirm_drain());
    const std::string expected =
        std::string("Sign ") + c.second + " on thorchain-1?";
    EXPECT_NE(screens.end(), std::find_if(screens.begin(), screens.end(),
                                          [&](const std::string& s) {
                                            return s.rfind(expected, 0) == 0;
                                          }))
        << denom;
  }
}

TEST_F(ReviewHandlers, MayaDepositGrammarRejectedBeforeConsent) {
  HDNode node = {};
  ASSERT_TRUE(storage_getRootNode("secp256k1", true, &node));
  MayachainSignTx tx = {};
  tx.has_chain_id = tx.has_msg_count = true;
  strcpy(tx.chain_id, "mayachain");
  tx.msg_count = 1;
  ASSERT_TRUE(mayachain_signTxInit(&node, &tx));
  MayachainMsgAck ack = {};
  ack.has_deposit = true;
  ack.deposit.has_asset = ack.deposit.has_amount = ack.deposit.has_memo =
      ack.deposit.has_signer = true;
  strcpy(ack.deposit.asset, "MAYA:CACAO");
  strcpy(ack.deposit.signer, "maya1g9el7lzjwh9yun2c4jjzhy09j98vkhfxfqkl5k");
  ASSERT_TRUE(kkconfirm_preload(0, 1));
  fsm_test_clearLastFailure();
  fsm_msgMayachainMsgAck(&ack);
  EXPECT_EQ(FailureType_Failure_SyntaxError, fsm_test_lastFailureCode());
  EXPECT_FALSE(mayachain_signingIsInited());
  EXPECT_EQ(2, kkconfirm_drain());
}
#endif
