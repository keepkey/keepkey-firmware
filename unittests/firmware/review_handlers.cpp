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
#if ZCASH_PRIVACY
#include "keepkey/firmware/zcash.h"
#include "trezor/crypto/blake2b.h"
#include "keepkey/rand/rng_health.h"
#include "trezor/crypto/bip32.h"
#include "trezor/crypto/bip39.h"
#include "trezor/crypto/curves.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/redpallas.h"
#include "trezor/crypto/secp256k1.h"
#include "zcash_fabricated_vectors.h"
#include "zcash_migration_vectors.h"
#include "zcash_note_vectors.h"
#include "zcash_tex_vectors.h"
#include "trezor/crypto/base58.h"
#endif
#include "keepkey/board/canvas.h"
#include "storage.h"
}
#include "gtest/gtest.h"
#include <cstring>
#include <algorithm>
#include <functional>
#include <string>
#include <vector>

// After the C++ headers: confirm_sm.h defines isprint() as a macro.
extern "C" {
#include "keepkey/board/confirm_sm.h"
}

extern "C" bool keepkey_before_message_dispatch(MessageType msg_id);
bool kkconfirm_preload(int, int);
bool kkconfirm_readResponse(uint16_t expected, const pb_field_t* fields,
                            void* result);
std::vector<uint16_t> kkconfirm_readResponseIds(void);
void kkconfirm_capture_start(void);
std::vector<std::string> kkconfirm_capture_finish(void);
std::vector<std::string> kkconfirm_captured_titles(void);
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

#if ZCASH_PRIVACY
// The PCZT summary is shown before anything the device verifies, so it must
// not present the host's total_amount as a fact: nothing signed commits to it.
TEST_F(ReviewHandlers, ZcashSummaryNeverShowsTheHostTotalAmount) {
  ZcashSignPCZT msg = {};
  msg.has_n_actions = true;
  msg.n_actions = 1;
  msg.has_account = true;
  msg.account = 0;
  msg.has_tx_version = msg.has_version_group_id = msg.has_branch_id =
      msg.has_lock_time = msg.has_expiry_height = true;
  msg.tx_version = 5;
  msg.version_group_id = 0x26a7270a;
  msg.branch_id = 0xc2d6d0b4;
  msg.lock_time = 123456;
  msg.expiry_height = 987654;
  msg.has_header_digest = true;
  msg.header_digest.size = 32;
  ASSERT_TRUE(zcash_compute_header_digest(
      msg.tx_version, msg.version_group_id, msg.branch_id, msg.lock_time,
      msg.expiry_height, msg.header_digest.bytes));
  msg.has_orchard_digest = true;
  msg.orchard_digest.size = 32;
  msg.has_orchard_flags = msg.has_orchard_value_balance = true;
  msg.has_orchard_anchor = true;
  msg.orchard_anchor.size = 32;
  msg.has_total_amount = true;
  msg.total_amount = 12345678;  // would render as 0.12345678
  msg.has_fee = true;
  msg.fee = 1000;

  ASSERT_TRUE(kkconfirm_preload(0, 1));  // reject the summary
  fsm_test_clearLastFailure();
  kkconfirm_capture_start();
  fsm_msgZcashSignPCZT(&msg);
  const auto screens = kkconfirm_capture_finish();
  EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
  EXPECT_EQ(0, kkconfirm_drain());
  ASSERT_EQ(1u, screens.size());
  EXPECT_NE(std::string::npos, screens[0].find("Sign shielded transaction?"));
  EXPECT_EQ(std::string::npos, screens[0].find("Amount"));
  EXPECT_EQ(std::string::npos, screens[0].find("12345678"));
}

// A shielded-only request signs over the empty transparent digest, so a
// different supplied digest is refused before the summary, never replaced.
TEST_F(ReviewHandlers, ZcashShieldedOnlyRefusesANonEmptyTransparentDigest) {
  ZcashSignPCZT msg = {};
  msg.has_n_actions = true;
  msg.n_actions = 1;
  msg.has_account = true;
  msg.has_tx_version = msg.has_version_group_id = msg.has_branch_id =
      msg.has_lock_time = msg.has_expiry_height = true;
  msg.tx_version = 5;
  msg.version_group_id = 0x26a7270a;
  msg.branch_id = 0xc2d6d0b4;
  msg.has_header_digest = true;
  msg.header_digest.size = 32;
  ASSERT_TRUE(zcash_compute_header_digest(
      msg.tx_version, msg.version_group_id, msg.branch_id, msg.lock_time,
      msg.expiry_height, msg.header_digest.bytes));
  msg.has_orchard_digest = true;
  msg.orchard_digest.size = 32;
  msg.has_orchard_flags = msg.has_orchard_value_balance = true;
  msg.has_orchard_anchor = true;
  msg.orchard_anchor.size = 32;
  msg.has_transparent_digest = true;
  msg.transparent_digest.size = 32;

  std::memset(msg.transparent_digest.bytes, 0x11, 32);
  ASSERT_TRUE(kkconfirm_preload(0, 1));
  fsm_test_clearLastFailure();
  kkconfirm_capture_start();
  fsm_msgZcashSignPCZT(&msg);
  EXPECT_TRUE(kkconfirm_capture_finish().empty());
  EXPECT_EQ(FailureType_Failure_SyntaxError, fsm_test_lastFailureCode());
  EXPECT_EQ(2, kkconfirm_drain());  // the summary's ack + decision, unused

  // The canonical empty digest is accepted and reaches the summary.
  ASSERT_TRUE(zcash_compute_transparent_digest(NULL, 0, NULL, 0,
                                               msg.transparent_digest.bytes));
  ASSERT_TRUE(kkconfirm_preload(0, 1));  // reject the summary
  fsm_test_clearLastFailure();
  kkconfirm_capture_start();
  fsm_msgZcashSignPCZT(&msg);
  EXPECT_EQ(1u, kkconfirm_capture_finish().size());
  EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
  EXPECT_EQ(0, kkconfirm_drain());
}

// A v5 sighash has no Ironwood component, so a supplied ironwood_digest of any
// size is refused before the summary instead of being dropped.
TEST_F(ReviewHandlers, ZcashV5RefusesAnIronwoodDigest) {
  ZcashSignPCZT msg = {};
  msg.has_n_actions = true;
  msg.n_actions = 1;
  msg.has_account = true;
  msg.has_tx_version = msg.has_version_group_id = msg.has_branch_id =
      msg.has_lock_time = msg.has_expiry_height = true;
  msg.tx_version = 5;
  msg.version_group_id = 0x26a7270a;
  msg.branch_id = 0xc2d6d0b4;
  msg.has_header_digest = true;
  msg.header_digest.size = 32;
  ASSERT_TRUE(zcash_compute_header_digest(
      msg.tx_version, msg.version_group_id, msg.branch_id, msg.lock_time,
      msg.expiry_height, msg.header_digest.bytes));
  msg.has_orchard_digest = true;
  msg.orchard_digest.size = 32;
  msg.has_orchard_flags = msg.has_orchard_value_balance = true;
  msg.has_orchard_anchor = true;
  msg.orchard_anchor.size = 32;
  for (pb_size_t size : {32, 7}) {
    SCOPED_TRACE(size);
    msg.has_ironwood_digest = true;
    msg.ironwood_digest.size = size;
    ASSERT_TRUE(kkconfirm_preload(0, 1));
    fsm_test_clearLastFailure();
    kkconfirm_capture_start();
    fsm_msgZcashSignPCZT(&msg);
    EXPECT_TRUE(kkconfirm_capture_finish().empty());
    EXPECT_EQ(FailureType_Failure_SyntaxError, fsm_test_lastFailureCode());
    EXPECT_EQ(2, kkconfirm_drain());  // the summary's ack + decision, unused
  }
  // Without it the same request reaches the summary.
  msg.has_ironwood_digest = false;
  msg.ironwood_digest.size = 0;
  ASSERT_TRUE(kkconfirm_preload(0, 1));  // reject the summary
  fsm_test_clearLastFailure();
  fsm_msgZcashSignPCZT(&msg);
  EXPECT_EQ(FailureType_Failure_ActionCancelled, fsm_test_lastFailureCode());
  EXPECT_EQ(0, kkconfirm_drain());
}

// Fixtures for streamed Orchard sessions. Every output is a zcash-test-vectors
// note (zcash_note_vectors.h), so the device's cmx and note-ciphertext checks
// pass on real data; cv_net and out_ciphertext are opaque to the device.
namespace {
std::vector<uint8_t> zcashHex(const char* hex) {
  std::vector<uint8_t> out;
  for (size_t i = 0; hex[i] && hex[i + 1]; i += 2) {
    out.push_back(static_cast<uint8_t>(std::stoul(std::string(hex + i, 2),
                                                  nullptr, 16)));
  }
  return out;
}

void zcashPersonal(const char* person, const std::vector<uint8_t>& data,
                   uint8_t out[32]) {
  blake2b_state ctx;
  blake2b_InitPersonal(&ctx, 32, person, 16);
  blake2b_Update(&ctx, data.data(), data.size());
  blake2b_Final(&ctx, out, 32);
}

template <typename Bytes>
void zcashSet(Bytes& field, const std::vector<uint8_t>& value) {
  field.size = value.size();
  std::memcpy(field.bytes, value.data(), value.size());
}

template <typename Bytes>
std::vector<uint8_t> zcashGet(const Bytes& field) {
  return std::vector<uint8_t>(field.bytes, field.bytes + field.size);
}

const std::vector<uint8_t> kZcashAnchor(32, 0x13);
const uint8_t kZcashFlags = 3;

ZcashPCZTAction zcashNoteAction(uint32_t index, const ZcashNoteVector& note) {
  ZcashPCZTAction action = {};
  action.has_index = action.has_is_spend = true;
  action.index = index;
  action.has_alpha = true;
  zcashSet(action.alpha, std::vector<uint8_t>(32, 1));
  action.has_value = true;
  action.value = note.value;
  action.has_recipient = action.has_rseed = true;
  auto recipient = zcashHex(note.d);
  const auto pk_d = zcashHex(note.pk_d);
  recipient.insert(recipient.end(), pk_d.begin(), pk_d.end());
  zcashSet(action.recipient, recipient);
  zcashSet(action.rseed, zcashHex(note.rseed));
  action.has_nullifier = action.has_cmx = action.has_epk = true;
  zcashSet(action.nullifier, zcashHex(note.rho));  // rho of the output note
  zcashSet(action.cmx, zcashHex(note.cmx));
  zcashSet(action.epk, zcashHex(note.epk));
  const auto c_enc = zcashHex(note.c_enc);
  action.has_enc_compact = action.has_enc_memo = true;
  action.has_enc_noncompact = true;
  zcashSet(action.enc_compact,
           std::vector<uint8_t>(c_enc.begin(), c_enc.begin() + 52));
  zcashSet(action.enc_memo,
           std::vector<uint8_t>(c_enc.begin() + 52, c_enc.begin() + 564));
  zcashSet(action.enc_noncompact,
           std::vector<uint8_t>(c_enc.begin() + 564, c_enc.end()));
  action.has_cv_net = action.has_rk = action.has_out_ciphertext = true;
  zcashSet(action.cv_net, std::vector<uint8_t>(32, 6));
  zcashSet(action.rk, std::vector<uint8_t>(32, 7));
  zcashSet(action.out_ciphertext, std::vector<uint8_t>(80, 8));
  return action;
}

// The ZIP-244 v5 Orchard bundle digest the device recomputes.
void zcashBundleDigest(const std::vector<ZcashPCZTAction>& actions,
                       int64_t value_balance, uint8_t digest[32]) {
  std::vector<uint8_t> compact_data, memo_data, noncompact_data;
  for (const auto& a : actions) {
    for (const auto& part : {zcashGet(a.nullifier), zcashGet(a.cmx),
                             zcashGet(a.epk), zcashGet(a.enc_compact)})
      compact_data.insert(compact_data.end(), part.begin(), part.end());
    const auto memo = zcashGet(a.enc_memo);
    memo_data.insert(memo_data.end(), memo.begin(), memo.end());
    for (const auto& part :
         {zcashGet(a.cv_net), zcashGet(a.rk), zcashGet(a.enc_noncompact),
          zcashGet(a.out_ciphertext)})
      noncompact_data.insert(noncompact_data.end(), part.begin(), part.end());
  }
  uint8_t compact[32], memos[32], noncompact[32];
  zcashPersonal("ZTxIdOrcActCHash", compact_data, compact);
  zcashPersonal("ZTxIdOrcActMHash", memo_data, memos);
  zcashPersonal("ZTxIdOrcActNHash", noncompact_data, noncompact);
  std::vector<uint8_t> data(compact, compact + 32);
  data.insert(data.end(), memos, memos + 32);
  data.insert(data.end(), noncompact, noncompact + 32);
  data.push_back(kZcashFlags);
  for (int i = 0; i < 8; i++)
    data.push_back(
        static_cast<uint8_t>(static_cast<uint64_t>(value_balance) >> (8 * i)));
  data.insert(data.end(), kZcashAnchor.begin(), kZcashAnchor.end());
  zcashPersonal("ZTxIdOrchardHash", data, digest);
}

// A v5 (NU6.2) request for account 0 over a precomputed bundle digest.
ZcashSignPCZT zcashSignRequest(uint32_t n_actions, const uint8_t digest[32],
                               int64_t value_balance, uint64_t fee) {
  ZcashSignPCZT msg = {};
  msg.has_n_actions = true;
  msg.n_actions = n_actions;
  msg.has_account = true;
  msg.has_tx_version = msg.has_version_group_id = msg.has_branch_id =
      msg.has_lock_time = msg.has_expiry_height = true;
  msg.tx_version = 5;
  msg.version_group_id = 0x26a7270a;
  msg.branch_id = 0x5437f330;
  msg.has_header_digest = true;
  msg.header_digest.size = 32;
  zcash_compute_header_digest(msg.tx_version, msg.version_group_id,
                              msg.branch_id, msg.lock_time, msg.expiry_height,
                              msg.header_digest.bytes);
  msg.has_orchard_digest = true;
  msg.orchard_digest.size = 32;
  std::memcpy(msg.orchard_digest.bytes, digest, 32);
  msg.has_orchard_flags = msg.has_orchard_value_balance = true;
  msg.orchard_flags = kZcashFlags;
  msg.orchard_value_balance = value_balance;
  msg.has_orchard_anchor = true;
  zcashSet(msg.orchard_anchor, kZcashAnchor);
  msg.has_fee = true;
  msg.fee = fee;
  return msg;
}
}  // namespace

// Handler-level walk of a whole shielded-only session: summary, one streamed
// output action, the recomputed bundle digest, then the final fee gate. A
// legacy host action sighash and a note ciphertext that does not decrypt to
// the committed note are refused before the output screens. A bundle digest
// the device does not recompute, or a host fee other than the verified one
// (here orchard_value_balance, 0), aborts before the fee screen and releases
// nothing; the matching request reaches the fee screen and completes.
TEST_F(ReviewHandlers, ZcashSessionCompletesOnlyPastTheDigestAndFeeGates) {
  enum Case {
    kHostSighash,
    kTamperedCiphertext,
    kTamperedDigest,
    kFeeMismatch,
    kAccepted
  };
  for (Case c : {kHostSighash, kTamperedCiphertext, kTamperedDigest,
                 kFeeMismatch, kAccepted}) {
    SCOPED_TRACE(c);
    ZcashPCZTAction action = zcashNoteAction(0, kZcashOrchardNoteVectors[0]);
    // A host corrupting the ciphertext also recomputes the bundle digest.
    if (c == kTamperedCiphertext) action.enc_memo.bytes[100] ^= 1;
    uint8_t digest[32];
    zcashBundleDigest({action}, 0, digest);
    ZcashSignPCZT msg =
        zcashSignRequest(1, digest, 0, c == kFeeMismatch ? 1000 : 0);
    if (c == kTamperedDigest) msg.orchard_digest.bytes[0] ^= 1;

    // Summary, the two output screens, then the fee screen if it is reached.
    ASSERT_TRUE(kkconfirm_preload(4, 0));
    fsm_test_clearLastFailure();
    kkconfirm_capture_start();
    fsm_msgZcashSignPCZT(&msg);
    ASSERT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()));

    if (c == kHostSighash) {
      action.has_sighash = true;
      zcashSet(action.sighash, std::vector<uint8_t>(32, 9));
    }
    fsm_msgZcashPCZTAction(&action);
    const auto screens = kkconfirm_capture_finish();
    const bool fee_screen =
        std::any_of(screens.begin(), screens.end(), [](const std::string& s) {
          return s.find("Confirm transaction fee?") != std::string::npos;
        });
    if (c == kHostSighash || c == kTamperedCiphertext) {
      // Refused before the output screens: only the summary was shown.
      EXPECT_EQ(c == kHostSighash ? FailureType_Failure_SyntaxError
                                  : FailureType_Failure_Other,
                fsm_test_lastFailureCode());
      EXPECT_STREQ(c == kHostSighash ? "Host action sighash rejected"
                                     : "Shielded note ciphertext mismatch",
                   fsm_test_lastFailureMessage());
      EXPECT_EQ(1u, screens.size());
      EXPECT_EQ(6, kkconfirm_drain());  // three unused screens' pairs
    } else if (c != kAccepted) {
      EXPECT_EQ(FailureType_Failure_Other, fsm_test_lastFailureCode());
      EXPECT_EQ(c == kFeeMismatch,
                std::string("Fee mismatch") == fsm_test_lastFailureMessage());
      EXPECT_EQ(c == kTamperedDigest,
                std::string(fsm_test_lastFailureMessage())
                        .find("Shielded digest mismatch") == 0);
      EXPECT_FALSE(fee_screen);
      EXPECT_EQ(3u, screens.size());
      EXPECT_EQ(2, kkconfirm_drain());  // the fee screen's pair, unused
    } else {
      EXPECT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()));
      EXPECT_TRUE(fee_screen);
      EXPECT_EQ(4u, screens.size());
      EXPECT_EQ(0, kkconfirm_drain());
    }
  }
}

// An unprotected Ping between streamed actions is dispatched without ending
// the session. It must not draw home over the signing screen while the
// approved session and its keys stay live; the stream then completes.
TEST_F(ReviewHandlers, ZcashPingBetweenActionsKeepsTheSigningScreen) {
  const std::vector<ZcashPCZTAction> actions = {
      zcashNoteAction(0, kZcashOrchardNoteVectors[0]),
      zcashNoteAction(1, kZcashOrchardNoteVectors[1])};
  uint8_t digest[32];
  zcashBundleDigest(actions, 0, digest);
  ZcashSignPCZT msg = zcashSignRequest(2, digest, 0, 0);

  // Summary, two screens per output, then the fee.
  ASSERT_TRUE(kkconfirm_preload(6, 0));
  fsm_test_clearLastFailure();
  fsm_msgZcashSignPCZT(&msg);
  ZcashPCZTAction first = actions[0];
  fsm_msgZcashPCZTAction(&first);
  ASSERT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()));
  ASSERT_TRUE(zcash_signing_is_active());

  const Canvas* canvas = layout_get_canvas();
  ASSERT_NE(nullptr, canvas);
  const size_t bytes = canvas->width * canvas->height;
  const std::vector<uint8_t> signing(canvas->buffer, canvas->buffer + bytes);

  ASSERT_TRUE(keepkey_before_message_dispatch(MessageType_MessageType_Ping));
  Ping ping = {};
  fsm_msgPing(&ping);
  EXPECT_TRUE(zcash_signing_is_active());
  EXPECT_EQ(signing,
            std::vector<uint8_t>(canvas->buffer, canvas->buffer + bytes))
      << "Ping drew home over the Zcash signing screen";

  ZcashPCZTAction second = actions[1];
  fsm_msgZcashPCZTAction(&second);
  EXPECT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()));
  EXPECT_FALSE(zcash_signing_is_active());
  EXPECT_EQ(0, kkconfirm_drain());
}

namespace {
// The sighash a v5 shielded request commits to, from its own fields.
void zcashRequestSighash(const ZcashSignPCZT& msg,
                         const uint8_t transparent_digest[32],
                         uint8_t sighash[32]) {
  uint8_t sapling[32];
  zcashPersonal("ZTxIdSaplingHash", {}, sapling);
  ASSERT_TRUE(zcash_compute_shielded_sighash(
      msg.header_digest.bytes, transparent_digest, sapling,
      msg.orchard_digest.bytes, msg.branch_id, sighash));
}

bool zcashSignatureEmitted(const std::vector<uint16_t>& ids) {
  return std::any_of(ids.begin(), ids.end(), [](uint16_t id) {
    return id == MessageType_MessageType_ZcashSignedPCZT ||
           id == MessageType_MessageType_ZcashTransparentSigned;
  });
}
}  // namespace

// ZIP 374 user_address on a real spend whose output is note vector 0. A
// matching multi-receiver address (built by zcash_address 0.13.0) is shown
// verbatim and the spend is signed, and so is its all-uppercase QR form,
// shown in lowercase; a valid address holding another Orchard
// receiver is refused before the output screens with no signature; without
// one the device shows the Orchard-only address under an honest title.
TEST_F(ReviewHandlers, ZcashUserAddressIsCheckedThenShown) {
  static const char kMatching[] =
      "u16065qzvddm89jcmzufxjs5pe6dr006tezvd7pap2nc58cctca8tt373s2he7xx76cn"
      "lyfatutph9kfl5g35cnuw6szxlf0qhpqajh0xrujjny6rxh6wej6mx6x5zuz4auaffd5"
      "hd56t8kwxnnquasruhg8qv3344cn6dauw00waq8ak2lmlyn8r84jumahr2nrd246gdxw"
      "932t8uvgs";
  // zcash_keys 0.16.1, "all" seed, account 0: P2PKH+Sapling+Orchard.
  static const char kOtherOrchard[] =
      "u1elnjt36zcqfelwj62v8lujthlqefztqcy02jfm2p5vs9phrzr8fj68j3mpzmvlktay"
      "k9fdz4zd4k3x6f7z3n62dw09w8sr9a8a0ka5m6xktd8hl6x5ekd0qky8h8t0an6p8eqk"
      "3ggwnl30dkv7txlw5r2qef330j94r0lftqktn0ev70kc78h8ev43ja5x7de27rvvhf0h"
      "4ku663uw6";
  ZcashOrchardKeys keys;
  ASSERT_TRUE(storage_zcashOrchardKeys(0, true, &keys));

  enum Case { kMatch, kUpper, kMismatch, kAbsent };
  for (Case c : {kMatch, kUpper, kMismatch, kAbsent}) {
    SCOPED_TRACE(c);
    ZcashPCZTAction action = zcashNoteAction(0, kZcashOrchardNoteVectors[0]);
    action.is_spend = true;
    std::vector<uint8_t> rk(32);
    ASSERT_EQ(0, redpallas_derive_rk_from_ak(keys.ak, action.alpha.bytes,
                                             rk.data()));
    zcashSet(action.rk, rk);
    if (c != kAbsent) {
      action.has_user_address = true;
      strlcpy(action.user_address, c == kMismatch ? kOtherOrchard : kMatching,
              sizeof(action.user_address));
      if (c == kUpper)
        for (char* p = action.user_address; *p; p++)
          *p = (char)toupper((unsigned char)*p);
    }
    uint8_t digest[32];
    zcashBundleDigest({action}, 0, digest);
    ZcashSignPCZT msg = zcashSignRequest(1, digest, 0, 0);

    ASSERT_TRUE(kkconfirm_preload(8, 0));
    fsm_test_clearLastFailure();
    fsm_msgZcashSignPCZT(&msg);
    ASSERT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()));
    kkconfirm_capture_start();
    fsm_msgZcashPCZTAction(&action);
    const auto titles = kkconfirm_captured_titles();
    const auto bodies = kkconfirm_capture_finish();
    EXPECT_FALSE(zcash_signing_is_active());

    if (c == kMismatch) {
      EXPECT_EQ(FailureType_Failure_Other, fsm_test_lastFailureCode());
      EXPECT_STREQ("Recipient address does not match output",
                   fsm_test_lastFailureMessage());
      EXPECT_TRUE(bodies.empty()) << "refused after an output screen";
      EXPECT_FALSE(zcashSignatureEmitted(kkconfirm_readResponseIds()));
      (void)kkconfirm_drain();
      continue;
    }

    EXPECT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()))
        << fsm_test_lastFailureMessage();
    const std::string title =
        c == kAbsent ? "Orchard address" : "Shielded recipient";
    const std::string expected =
        c != kAbsent ? kMatching
                    : "u17j4lvw84jd238ev9ukr0lvqhv4z32v98pxcglctaj3aqfqj7rr2w"
                      "wvh73247ekczw4smyrvm2wf2v5nfxvn3sl0ycc6w4455yg49yf2m";
    std::string shown;
    for (size_t i = 0; i < titles.size(); i++) {
      if (titles[i].find(title) != 0) continue;
      for (char ch : bodies[i])
        if (ch != '\n' && ch != ' ') shown += ch;
    }
    EXPECT_EQ(expected, shown);
    EXPECT_TRUE(zcashSignatureEmitted(kkconfirm_readResponseIds()));
    (void)kkconfirm_drain();
  }
  memzero(&keys, sizeof(keys));
}

// Real spends are signed in action order into a compact list; the dummy
// between them is verified but never signed. Each signature verifies under
// the rk the device derives for its own ak and that action's alpha, and the
// order matters. A host rk that is not the device's aborts while streaming; a
// failed RNG verdict aborts at the final gate. Neither releases a signature.
TEST_F(ReviewHandlers, ZcashRealSpendsReleaseOnlyCompactVerifiedSignatures) {
  ZcashOrchardKeys keys;
  ASSERT_TRUE(storage_zcashOrchardKeys(0, true, &keys));

  enum Case { kAccepted, kForeignRk, kRngFailed };
  for (Case c : {kAccepted, kForeignRk, kRngFailed}) {
    SCOPED_TRACE(c);
    std::vector<ZcashPCZTAction> actions = {
        zcashNoteAction(0, kZcashOrchardNoteVectors[0]),
        zcashNoteAction(1, kZcashOrchardNoteVectors[1]),
        zcashNoteAction(2, kZcashOrchardNoteVectors[0])};
    std::vector<std::vector<uint8_t>> rks;
    for (uint32_t i : {0u, 2u}) {
      ZcashPCZTAction& spend = actions[i];
      spend.is_spend = true;
      zcashSet(spend.alpha, std::vector<uint8_t>(32, uint8_t(0x11 + i)));
      std::vector<uint8_t> rk(32);
      ASSERT_EQ(0, redpallas_derive_rk_from_ak(keys.ak, spend.alpha.bytes,
                                               rk.data()));
      zcashSet(spend.rk, rk);
      rks.push_back(rk);
    }
    if (c == kForeignRk) actions[2].rk.bytes[0] ^= 1;
    uint8_t digest[32];
    zcashBundleDigest(actions, 0, digest);
    ZcashSignPCZT msg = zcashSignRequest(3, digest, 0, 0);

    // Summary, two screens per output, then the fee.
    ASSERT_TRUE(kkconfirm_preload(8, 0));
    fsm_test_clearLastFailure();
    fsm_msgZcashSignPCZT(&msg);
    ASSERT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()));
    if (c == kRngFailed) rng_health_force_verdict(false);
    for (auto& action : actions) {
      fsm_msgZcashPCZTAction(&action);
      if (fsm_test_lastFailureCode() != 0) break;
    }
    rng_health_reset_for_test();

    if (c != kAccepted) {
      EXPECT_STREQ(c == kForeignRk
                       ? "Orchard spend authorization failed"
                       : "RNG health check failed; refusing to sign",
                   fsm_test_lastFailureMessage());
      EXPECT_FALSE(zcash_signing_is_active());
      EXPECT_FALSE(zcashSignatureEmitted(kkconfirm_readResponseIds()));
      (void)kkconfirm_drain();
      continue;
    }

    EXPECT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()));
    EXPECT_EQ(0, kkconfirm_drain());
    ZcashSignedPCZT signed_pczt = {};
    ASSERT_TRUE(kkconfirm_readResponse(MessageType_MessageType_ZcashSignedPCZT,
                                       ZcashSignedPCZT_fields, &signed_pczt));
    ASSERT_EQ(2u, signed_pczt.signatures_count);
    uint8_t empty_transparent[32], sighash[32];
    ASSERT_TRUE(
        zcash_compute_transparent_digest(NULL, 0, NULL, 0, empty_transparent));
    zcashRequestSighash(msg, empty_transparent, sighash);
    for (size_t i = 0; i < 2; i++) {
      ASSERT_EQ(64u, signed_pczt.signatures[i].size);
      EXPECT_EQ(0, redpallas_verify_digest(rks[i].data(), sighash,
                                           signed_pczt.signatures[i].bytes));
    }
    EXPECT_NE(0, redpallas_verify_digest(rks[0].data(), sighash,
                                         signed_pczt.signatures[1].bytes));
  }
  memzero(&keys, sizeof(keys));
}

namespace {
ZcashPCZTAction zcashFabricatedAction(uint32_t index,
                                      const ZcashFabricatedAction& v) {
  ZcashPCZTAction action = {};
  action.has_index = action.has_is_spend = true;
  action.index = index;
  action.is_spend = true;  // both spends are wallet-controlled
  action.has_alpha = action.has_value = true;
  zcashSet(action.alpha, zcashHex(v.alpha));
  action.value = v.value;
  action.has_recipient = action.has_rseed = true;
  zcashSet(action.recipient, zcashHex(v.recipient));
  zcashSet(action.rseed, zcashHex(v.rseed));
  action.has_nullifier = action.has_cmx = action.has_epk = true;
  zcashSet(action.nullifier, zcashHex(v.nullifier));
  zcashSet(action.cmx, zcashHex(v.cmx));
  zcashSet(action.epk, zcashHex(v.epk));
  const auto c_enc = zcashHex(v.enc);
  action.has_enc_compact = action.has_enc_memo = true;
  action.has_enc_noncompact = true;
  zcashSet(action.enc_compact,
           std::vector<uint8_t>(c_enc.begin(), c_enc.begin() + 52));
  zcashSet(action.enc_memo,
           std::vector<uint8_t>(c_enc.begin() + 52, c_enc.begin() + 564));
  zcashSet(action.enc_noncompact,
           std::vector<uint8_t>(c_enc.begin() + 564, c_enc.end()));
  action.has_cv_net = action.has_rk = action.has_out_ciphertext = true;
  zcashSet(action.cv_net, zcashHex(v.cv_net));
  zcashSet(action.rk, zcashHex(v.rk));
  zcashSet(action.out_ciphertext, zcashHex(v.out));
  return action;
}
}  // namespace

// A real NU6.3 bundle from the orchard crate (zcash_fabricated_vectors.h):
// the spend's fabricated zero-valued output carries a random ciphertext
// (ZIP 326) and is accepted without a screen; the change output, proven to
// pay the account's internal address, is shown as the change total, and both
// spends are signed. A value-bearing output whose ciphertext does not
// decrypt, or a zero-valued output whose cmx does not match its note, is
// still refused before any output screen and releases nothing.
TEST_F(ReviewHandlers, ZcashFabricatedSameAddressOutputSigns) {
  ZcashOrchardKeys keys;
  ASSERT_TRUE(storage_zcashOrchardKeys(0, true, &keys));

  enum Case { kAccepted, kTamperedChangeCiphertext, kTamperedFabricatedCmx };
  for (Case c :
       {kAccepted, kTamperedChangeCiphertext, kTamperedFabricatedCmx}) {
    SCOPED_TRACE(c);
    std::vector<ZcashPCZTAction> actions = {
        zcashFabricatedAction(0, kZcashFabricatedBundle[0]),
        zcashFabricatedAction(1, kZcashFabricatedBundle[1])};
    // The crate's rk is the device's own ak re-randomized by alpha.
    for (const auto& action : actions) {
      std::vector<uint8_t> rk(32);
      ASSERT_EQ(0, redpallas_derive_rk_from_ak(keys.ak, action.alpha.bytes,
                                               rk.data()));
      ASSERT_EQ(zcashGet(action.rk), rk);
    }
    // A host tampering with an action also recomputes the bundle digest.
    if (c == kTamperedChangeCiphertext) actions[1].enc_memo.bytes[7] ^= 1;
    if (c == kTamperedFabricatedCmx) actions[0].cmx.bytes[0] ^= 1;
    uint8_t digest[32];
    zcashBundleDigest(actions, 10000, digest);
    ZcashSignPCZT msg = zcashSignRequest(2, digest, 10000, 10000);

    // Summary, the change total, then the fee.
    ASSERT_TRUE(kkconfirm_preload(3, 0));
    fsm_test_clearLastFailure();
    kkconfirm_capture_start();
    fsm_msgZcashSignPCZT(&msg);
    ASSERT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()));
    for (auto& action : actions) {
      fsm_msgZcashPCZTAction(&action);
      if (fsm_test_lastFailureCode() != 0) break;
    }
    const auto screens = kkconfirm_capture_finish();
    EXPECT_FALSE(zcash_signing_is_active());

    if (c != kAccepted) {
      EXPECT_EQ(FailureType_Failure_Other, fsm_test_lastFailureCode());
      EXPECT_STREQ(c == kTamperedChangeCiphertext
                       ? "Shielded note ciphertext mismatch"
                       : "Shielded note commitment mismatch",
                   fsm_test_lastFailureMessage());
      EXPECT_EQ(1u, screens.size());  // the summary only
      EXPECT_FALSE(zcashSignatureEmitted(kkconfirm_readResponseIds()));
      (void)kkconfirm_drain();
      continue;
    }

    EXPECT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()))
        << fsm_test_lastFailureMessage();
    ASSERT_EQ(3u, screens.size());
    EXPECT_NE(std::string::npos,
              screens[1].find("Change back to your wallet:\n0.00090000 ZEC"))
        << screens[1];
    for (const auto& s : screens)
      EXPECT_EQ(std::string::npos, s.find("0.00000000 ZEC")) << s;
    EXPECT_NE(std::string::npos, screens[2].find("0.00010000 ZEC"));
    EXPECT_EQ(0, kkconfirm_drain());

    ZcashSignedPCZT signed_pczt = {};
    ASSERT_TRUE(kkconfirm_readResponse(MessageType_MessageType_ZcashSignedPCZT,
                                       ZcashSignedPCZT_fields, &signed_pczt));
    ASSERT_EQ(2u, signed_pczt.signatures_count);
    uint8_t empty_transparent[32], sighash[32];
    ASSERT_TRUE(
        zcash_compute_transparent_digest(NULL, 0, NULL, 0, empty_transparent));
    zcashRequestSighash(msg, empty_transparent, sighash);
    for (size_t i = 0; i < 2; i++) {
      ASSERT_EQ(64u, signed_pczt.signatures[i].size);
      EXPECT_EQ(0, redpallas_verify_digest(actions[i].rk.bytes, sighash,
                                           signed_pczt.signatures[i].bytes));
    }
  }
  memzero(&keys, sizeof(keys));
}

// A real NU6.2 bundle (zcash_fabricated_vectors.h) padded with a dummy
// zero-valued output to a random address whose ciphertext does decrypt. It
// moves no funds, so like Keystone and Ledger the device does not show it;
// the change output is shown as the change total. The host-signed dummy spend
// is not signed. A dummy output
// whose cmx does not match its note is still refused before any output screen.
TEST_F(ReviewHandlers, ZcashZeroValuePaddingOutputIsNotShown) {
  ZcashOrchardKeys keys;
  ASSERT_TRUE(storage_zcashOrchardKeys(0, true, &keys));

  for (bool tampered : {false, true}) {
    SCOPED_TRACE(tampered);
    std::vector<ZcashPCZTAction> actions = {
        zcashFabricatedAction(0, kZcashPaddingBundle[0]),
        zcashFabricatedAction(1, kZcashPaddingBundle[1])};
    actions[1].is_spend = false;  // the dummy spend carries dummy_sk
    if (tampered) actions[1].cmx.bytes[0] ^= 1;
    uint8_t digest[32];
    zcashBundleDigest(actions, 10000, digest);
    ZcashSignPCZT msg = zcashSignRequest(2, digest, 10000, 10000);

    // Summary, the change total, then the fee.
    ASSERT_TRUE(kkconfirm_preload(3, 0));
    fsm_test_clearLastFailure();
    kkconfirm_capture_start();
    fsm_msgZcashSignPCZT(&msg);
    ASSERT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()));
    for (auto& action : actions) {
      fsm_msgZcashPCZTAction(&action);
      if (fsm_test_lastFailureCode() != 0) break;
    }
    const auto screens = kkconfirm_capture_finish();
    EXPECT_FALSE(zcash_signing_is_active());
    for (const auto& s : screens)
      EXPECT_EQ(std::string::npos, s.find("0.00000000 ZEC")) << s;

    if (tampered) {
      EXPECT_STREQ("Shielded note commitment mismatch",
                   fsm_test_lastFailureMessage());
      EXPECT_FALSE(zcashSignatureEmitted(kkconfirm_readResponseIds()));
      (void)kkconfirm_drain();
      continue;
    }

    EXPECT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()))
        << fsm_test_lastFailureMessage();
    ASSERT_EQ(3u, screens.size());
    EXPECT_NE(std::string::npos,
              screens[1].find("Change back to your wallet:\n0.00090000 ZEC"))
        << screens[1];
    EXPECT_NE(std::string::npos, screens[2].find("0.00010000 ZEC"));
    EXPECT_EQ(0, kkconfirm_drain());

    ZcashSignedPCZT signed_pczt = {};
    ASSERT_TRUE(kkconfirm_readResponse(MessageType_MessageType_ZcashSignedPCZT,
                                       ZcashSignedPCZT_fields, &signed_pczt));
    ASSERT_EQ(1u, signed_pczt.signatures_count);
    uint8_t empty_transparent[32], sighash[32];
    ASSERT_TRUE(
        zcash_compute_transparent_digest(NULL, 0, NULL, 0, empty_transparent));
    zcashRequestSighash(msg, empty_transparent, sighash);
    EXPECT_EQ(0, redpallas_verify_digest(actions[0].rk.bytes, sighash,
                                         signed_pczt.signatures[0].bytes));
  }
  memzero(&keys, sizeof(keys));
}

// A real NU6.2 bundle (zcash_fabricated_vectors.h, kZcashMemoBundle) with
// four outputs. Only the one proven to pay this account's internal address is
// folded into the change total; a self-send to the account's external address
// and a payment to another account's internal (change) address are shown like
// any other output. The zero-valued memo-only send carries the address the
// user entered and is shown with it at 0 ZEC; without a user_address the same
// output is taken for padding and not shown. A change output whose cmx does
// not match its note is refused before any output screen, and declining the
// change total releases nothing.
TEST_F(ReviewHandlers, ZcashOnlyProvenChangeIsFoldedAndMemoSendIsShown) {
  ZcashOrchardKeys keys;
  ASSERT_TRUE(storage_zcashOrchardKeys(0, true, &keys));

  enum Case { kAccepted, kNoUserAddress, kTamperedChangeCmx, kChangeDeclined };
  for (Case c :
       {kAccepted, kNoUserAddress, kTamperedChangeCmx, kChangeDeclined}) {
    SCOPED_TRACE(c);
    std::vector<ZcashPCZTAction> actions;
    for (const auto& v : kZcashMemoBundle)
      actions.push_back(zcashFabricatedAction(actions.size(), v));
    ASSERT_EQ(4u, actions.size());
    for (size_t i = 1; i < actions.size(); i++)
      actions[i].is_spend = false;  // dummy spends carry dummy_sk
    std::vector<uint8_t> rk(32);
    ASSERT_EQ(0, redpallas_derive_rk_from_ak(keys.ak, actions[0].alpha.bytes,
                                             rk.data()));
    ASSERT_EQ(zcashGet(actions[0].rk), rk);
    if (c != kNoUserAddress) {
      actions[3].has_user_address = true;
      strlcpy(actions[3].user_address, kZcashMemoUserAddress,
              sizeof(actions[3].user_address));
    }
    if (c == kTamperedChangeCmx) actions[2].cmx.bytes[0] ^= 1;
    uint8_t digest[32];
    zcashBundleDigest(actions, 10000, digest);
    ZcashSignPCZT msg = zcashSignRequest(4, digest, 10000, 10000);

    // Summary; self-send; another account's change; the memo send (only with
    // its user_address); the change total; the fee.
    const size_t expected = c == kNoUserAddress ? 7u : 9u;
    if (c == kChangeDeclined) {
      ASSERT_TRUE(kkconfirm_preload(static_cast<int>(expected) - 2, 1));
    } else {
      ASSERT_TRUE(kkconfirm_preload(static_cast<int>(expected), 0));
    }
    fsm_test_clearLastFailure();
    kkconfirm_capture_start();
    fsm_msgZcashSignPCZT(&msg);
    ASSERT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()));
    for (auto& action : actions) {
      fsm_msgZcashPCZTAction(&action);
      if (fsm_test_lastFailureCode() != 0) break;
    }
    const auto screens = kkconfirm_capture_finish();
    EXPECT_FALSE(zcash_signing_is_active());

    if (c == kChangeDeclined) {
      EXPECT_STREQ("Signing cancelled", fsm_test_lastFailureMessage());
      ASSERT_EQ(expected - 1, screens.size());  // up to the change total
      EXPECT_NE(std::string::npos,
                screens.back().find("Change back to your wallet:"));
      EXPECT_FALSE(zcashSignatureEmitted(kkconfirm_readResponseIds()));
      (void)kkconfirm_drain();
      continue;
    }
    if (c == kTamperedChangeCmx) {
      EXPECT_STREQ("Shielded note commitment mismatch",
                   fsm_test_lastFailureMessage());
      // The summary and the two outputs streamed before the change.
      EXPECT_EQ(5u, screens.size());
      EXPECT_FALSE(zcashSignatureEmitted(kkconfirm_readResponseIds()));
      (void)kkconfirm_drain();
      continue;
    }

    EXPECT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()))
        << fsm_test_lastFailureMessage();
    char self_ua[ZCASH_ORCHARD_UNIFIED_ADDRESS_SIZE];
    char other_change_ua[ZCASH_ORCHARD_UNIFIED_ADDRESS_SIZE];
    ASSERT_TRUE(zcash_orchard_receiver_to_unified_address(
        actions[0].recipient.bytes, "u", self_ua, sizeof(self_ua)));
    ASSERT_TRUE(zcash_orchard_receiver_to_unified_address(
        actions[1].recipient.bytes, "u", other_change_ua,
        sizeof(other_change_ua)));
    auto shows = [&](size_t i, const char* text) {
      ASSERT_LT(i, screens.size());
      EXPECT_NE(std::string::npos, screens[i].find(text)) << screens[i];
    };
    ASSERT_EQ(expected, screens.size());
    shows(1, "0.00020000 ZEC");
    shows(2, self_ua);
    shows(3, "0.00030000 ZEC");
    shows(4, other_change_ua);
    if (c == kAccepted) {
      shows(5, "0.00000000 ZEC");
      shows(6, kZcashMemoUserAddress);
    }
    shows(expected - 2, "Change back to your wallet:\n0.00040000 ZEC");
    shows(expected - 1, "0.00010000 ZEC");
    size_t change_screens = 0;  // the change has no screen of its own
    for (const auto& screen : screens)
      change_screens += screen.find("0.00040000 ZEC") != std::string::npos;
    EXPECT_EQ(1u, change_screens);
    EXPECT_EQ(0, kkconfirm_drain());

    ZcashSignedPCZT signed_pczt = {};
    ASSERT_TRUE(kkconfirm_readResponse(MessageType_MessageType_ZcashSignedPCZT,
                                       ZcashSignedPCZT_fields, &signed_pczt));
    ASSERT_EQ(1u, signed_pczt.signatures_count);
    uint8_t empty_transparent[32], sighash[32];
    ASSERT_TRUE(
        zcash_compute_transparent_digest(NULL, 0, NULL, 0, empty_transparent));
    zcashRequestSighash(msg, empty_transparent, sighash);
    EXPECT_EQ(0, redpallas_verify_digest(actions[0].rk.bytes, sighash,
                                         signed_pczt.signatures[0].bytes));
  }
  memzero(&keys, sizeof(keys));
}

namespace {
// m/44'/133'/account'/change/index public key for this fixture's seed.
std::vector<uint8_t> zcashTransparentPubkey(uint32_t index, uint32_t change = 0,
                                            uint32_t account = 0) {
  uint8_t seed[64];
  mnemonic_to_seed("all all all all all all all all all all all all", "", seed,
                   NULL);
  HDNode node;
  hdnode_from_seed(seed, sizeof(seed), SECP256K1_NAME, &node);
  for (uint32_t child :
       {0x80000000u | 44, 0x80000000u | 133, 0x80000000u | account, change,
        index})
    hdnode_private_ckd(&node, child);
  hdnode_fill_public_key(&node);
  std::vector<uint8_t> pubkey(node.public_key, node.public_key + 33);
  memzero(&node, sizeof(node));
  memzero(seed, sizeof(seed));
  return pubkey;
}

std::vector<uint8_t> zcashP2pkh(const std::vector<uint8_t>& pubkey) {
  std::vector<uint8_t> script = {0x76, 0xa9, 0x14};
  uint8_t hash[20];
  ecdsa_get_pubkeyhash(pubkey.data(), HASHER_SHA2_RIPEMD, hash);
  script.insert(script.end(), hash, hash + 20);
  script.push_back(0x88);
  script.push_back(0xac);
  return script;
}
}  // namespace

// A hybrid (shielding) session: the P2PKH input's path, account and script
// are checked against the session while streaming; its ECDSA signature is made
// only after the Orchard digest and the verified fee pass and the fee screen is
// approved, then released. Every refusal releases neither signature response.
TEST_F(ReviewHandlers, ZcashHybridReleasesTransparentSignaturesLast) {
  const auto pubkey = zcashTransparentPubkey(0);
  const auto script = zcashP2pkh(pubkey);
  const std::vector<uint8_t> txid(32, 0xab);
  const uint64_t amount = 100000;
  const int64_t value_balance = -90000;  // into the Orchard pool
  const uint64_t fee = amount + value_balance;

  ZcashTransparentInputDigestInfo info = {};
  info.prevout_txid = txid.data();
  info.prevout_index = 1;
  info.sequence = 0xffffffff;
  info.value = amount;
  info.script_pubkey = script.data();
  info.script_pubkey_size = script.size();
  uint8_t transparent_digest[32];
  ASSERT_TRUE(zcash_compute_orchard_transparent_sig_digest(&info, 1, NULL, 0,
                                                           transparent_digest));

  const ZcashPCZTAction output =
      zcashNoteAction(0, kZcashOrchardNoteVectors[0]);
  uint8_t digest[32];
  zcashBundleDigest({output}, value_balance, digest);

  enum Case {
    kAccepted,
    kForeignAccount,
    kScriptForAnotherKey,
    kP2sh,
    kTamperedDigest,
    kFeeMismatch,
    kFeeCancelled
  };
  for (Case c : {kAccepted, kForeignAccount, kScriptForAnotherKey, kP2sh,
                 kTamperedDigest, kFeeMismatch, kFeeCancelled}) {
    SCOPED_TRACE(c);
    ZcashSignPCZT msg = zcashSignRequest(1, digest, value_balance,
                                         c == kFeeMismatch ? fee + 1 : fee);
    if (c == kTamperedDigest) msg.orchard_digest.bytes[0] ^= 1;
    msg.has_n_transparent_inputs = true;
    msg.n_transparent_inputs = 1;
    msg.has_transparent_digest = true;
    msg.transparent_digest.size = 32;
    std::memcpy(msg.transparent_digest.bytes, transparent_digest, 32);

    ZcashTransparentInput input = {};
    input.address_n_count = 5;
    const uint32_t path[] = {0x80000000u | 44, 0x80000000u | 133,
                             0x80000000u | (c == kForeignAccount ? 1u : 0u), 0,
                             c == kScriptForAnotherKey ? 1u : 0u};
    std::memcpy(input.address_n, path, sizeof(path));
    input.has_amount = input.has_prevout_txid = input.has_prevout_index =
        input.has_sequence = input.has_script_pubkey = true;
    input.amount = amount;
    zcashSet(input.prevout_txid, txid);
    input.prevout_index = info.prevout_index;
    input.sequence = info.sequence;
    if (c == kP2sh) {
      std::vector<uint8_t> p2sh = {0xa9, 0x14};
      p2sh.insert(p2sh.end(), script.begin() + 3, script.begin() + 23);
      p2sh.push_back(0x87);
      zcashSet(input.script_pubkey, p2sh);
    } else {
      zcashSet(input.script_pubkey, script);
    }

    // The two-page summary, the two output screens, the fee, then the input.
    ASSERT_TRUE(kkconfirm_preload(c == kFeeCancelled ? 4 : 6,
                                  c == kFeeCancelled ? 1 : 0));
    fsm_test_clearLastFailure();
    fsm_msgZcashSignPCZT(&msg);
    ASSERT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()));
    fsm_msgZcashTransparentInput(&input);
    const bool input_refused =
        c == kForeignAccount || c == kScriptForAnotherKey || c == kP2sh;
    if (!input_refused) {
      ASSERT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()));
      ZcashPCZTAction action = output;
      fsm_msgZcashPCZTAction(&action);
    }

    if (c != kAccepted) {
      const char* expected =
          c == kForeignAccount ? "Account does not match approved session"
          : c == kScriptForAnotherKey
              ? "Transparent input script does not match path"
          : c == kP2sh         ? "Transparent inputs must be P2PKH"
          : c == kFeeMismatch  ? "Fee mismatch"
          : c == kFeeCancelled ? "Signing cancelled"
                               : nullptr;
      if (expected) {
        EXPECT_STREQ(expected, fsm_test_lastFailureMessage());
      } else {
        EXPECT_EQ(0u, std::string(fsm_test_lastFailureMessage())
                          .find("Shielded digest mismatch"));
      }
      EXPECT_FALSE(zcash_signing_is_active());
      EXPECT_FALSE(zcashSignatureEmitted(kkconfirm_readResponseIds()));
      (void)kkconfirm_drain();
      continue;
    }

    EXPECT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()))
        << fsm_test_lastFailureMessage();
    EXPECT_EQ(0, kkconfirm_drain());
    // The transparent signature comes first, then the (empty) Orchard list.
    ZcashTransparentSigned transparent = {};
    ASSERT_TRUE(
        kkconfirm_readResponse(MessageType_MessageType_ZcashTransparentSigned,
                               ZcashTransparentSigned_fields, &transparent));
    ZcashSignedPCZT signed_pczt = {};
    ASSERT_TRUE(kkconfirm_readResponse(MessageType_MessageType_ZcashSignedPCZT,
                                       ZcashSignedPCZT_fields, &signed_pczt));
    EXPECT_EQ(0u, signed_pczt.signatures_count);

    ASSERT_EQ(1u, transparent.signatures_count);
    uint8_t input_digest[32], sighash[32], sig[64];
    ASSERT_TRUE(zcash_compute_transparent_sighash_digest(&info, 1, NULL, 0, 0,
                                                         0x01, input_digest));
    zcashRequestSighash(msg, input_digest, sighash);
    ASSERT_EQ(0, ecdsa_sig_from_der(transparent.signatures[0].bytes,
                                    transparent.signatures[0].size, sig));
    EXPECT_EQ(0, ecdsa_verify_digest(&secp256k1, pubkey.data(), sig, sighash));
  }
}

// Verify before sign: no RedPallas or transparent ECDSA operation runs until
// the final gate has recomputed the bundle digest, so a host whose claimed
// orchard_digest differs from the streamed actions gets no signature and no
// signing operation at all. The accepted control signs only at the gate.
TEST_F(ReviewHandlers, ZcashSignsNothingBeforeTheFinalGate) {
  ZcashOrchardKeys keys;
  ASSERT_TRUE(storage_zcashOrchardKeys(0, true, &keys));
  const auto pubkey = zcashTransparentPubkey(0);
  const auto script = zcashP2pkh(pubkey);
  const std::vector<uint8_t> txid(32, 0xab);
  const uint64_t amount = 100000;
  const int64_t value_balance = -90000;

  ZcashTransparentInputDigestInfo info = {};
  info.prevout_txid = txid.data();
  info.prevout_index = 1;
  info.sequence = 0xffffffff;
  info.value = amount;
  info.script_pubkey = script.data();
  info.script_pubkey_size = script.size();
  uint8_t transparent_digest[32];
  ASSERT_TRUE(zcash_compute_orchard_transparent_sig_digest(&info, 1, NULL, 0,
                                                           transparent_digest));

  std::vector<ZcashPCZTAction> actions = {
      zcashNoteAction(0, kZcashOrchardNoteVectors[0]),
      zcashNoteAction(1, kZcashOrchardNoteVectors[1])};
  for (uint32_t i = 0; i < actions.size(); i++) {
    actions[i].is_spend = true;
    zcashSet(actions[i].alpha, std::vector<uint8_t>(32, uint8_t(0x21 + i)));
    std::vector<uint8_t> rk(32);
    ASSERT_EQ(0, redpallas_derive_rk_from_ak(keys.ak, actions[i].alpha.bytes,
                                             rk.data()));
    zcashSet(actions[i].rk, rk);
  }
  uint8_t digest[32];
  zcashBundleDigest(actions, value_balance, digest);

  for (bool tampered : {true, false}) {
    SCOPED_TRACE(tampered);
    ZcashSignPCZT msg =
        zcashSignRequest(2, digest, value_balance, amount + value_balance);
    if (tampered) msg.orchard_digest.bytes[0] ^= 1;
    msg.has_n_transparent_inputs = true;
    msg.n_transparent_inputs = 1;
    msg.has_transparent_digest = true;
    msg.transparent_digest.size = 32;
    std::memcpy(msg.transparent_digest.bytes, transparent_digest, 32);

    ZcashTransparentInput input = {};
    input.address_n_count = 5;
    const uint32_t path[] = {0x80000000u | 44, 0x80000000u | 133, 0x80000000u,
                             0, 0};
    std::memcpy(input.address_n, path, sizeof(path));
    input.has_amount = input.has_prevout_txid = input.has_prevout_index =
        input.has_sequence = input.has_script_pubkey = true;
    input.amount = amount;
    zcashSet(input.prevout_txid, txid);
    input.prevout_index = info.prevout_index;
    input.sequence = info.sequence;
    zcashSet(input.script_pubkey, script);

    // Two-page summary, two screens per output, the fee, then the input.
    ASSERT_TRUE(kkconfirm_preload(8, 0));
    fsm_test_clearLastFailure();
    zcash_test_clearSignOperations();
    fsm_msgZcashSignPCZT(&msg);
    fsm_msgZcashTransparentInput(&input);
    ZcashPCZTAction first = actions[0];
    fsm_msgZcashPCZTAction(&first);
    ASSERT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()))
        << fsm_test_lastFailureMessage();
    EXPECT_EQ(0u, zcash_test_signOperations())
        << "signed before the final gate";

    ZcashPCZTAction last = actions[1];
    fsm_msgZcashPCZTAction(&last);
    EXPECT_FALSE(zcash_signing_is_active());
    if (tampered) {
      EXPECT_EQ(0u, std::string(fsm_test_lastFailureMessage())
                        .find("Shielded digest mismatch"));
      EXPECT_EQ(0u, zcash_test_signOperations());
      EXPECT_FALSE(zcashSignatureEmitted(kkconfirm_readResponseIds()));
      (void)kkconfirm_drain();
    } else {
      EXPECT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()))
          << fsm_test_lastFailureMessage();
      EXPECT_EQ(3u, zcash_test_signOperations());
      EXPECT_EQ(0, kkconfirm_drain());
    }
  }
  memzero(&keys, sizeof(keys));
}

namespace {
ZcashPCZTAction zcashMigrationAction(uint32_t index,
                                     const ZcashMigrationAction& v) {
  ZcashPCZTAction action = {};
  action.has_index = action.has_is_spend = true;
  action.index = index;
  action.is_spend = v.is_spend;
  action.has_alpha = action.has_value = true;
  zcashSet(action.alpha, zcashHex(v.alpha));
  action.value = v.value;
  action.has_recipient = action.has_rseed = true;
  zcashSet(action.recipient, zcashHex(v.recipient));
  zcashSet(action.rseed, zcashHex(v.rseed));
  action.has_nullifier = action.has_cmx = action.has_epk = true;
  zcashSet(action.nullifier, zcashHex(v.nullifier));
  zcashSet(action.cmx, zcashHex(v.cmx));
  zcashSet(action.epk, zcashHex(v.epk));
  const auto c_enc = zcashHex(v.enc);
  action.has_enc_compact = action.has_enc_memo = true;
  action.has_enc_noncompact = true;
  zcashSet(action.enc_compact,
           std::vector<uint8_t>(c_enc.begin(), c_enc.begin() + 52));
  zcashSet(action.enc_memo,
           std::vector<uint8_t>(c_enc.begin() + 52, c_enc.begin() + 564));
  zcashSet(action.enc_noncompact,
           std::vector<uint8_t>(c_enc.begin() + 564, c_enc.end()));
  action.has_cv_net = action.has_rk = action.has_out_ciphertext = true;
  zcashSet(action.cv_net, zcashHex(v.cv_net));
  zcashSet(action.rk, zcashHex(v.rk));
  zcashSet(action.out_ciphertext, zcashHex(v.out));
  return action;
}

// ZIP-229 v6 bundle digest (no anchor) of one pool's actions.
void zcashV6BundleDigest(const std::vector<ZcashPCZTAction>& actions,
                         bool ironwood, uint8_t flags, int64_t value_balance,
                         uint8_t digest[32]) {
  std::vector<uint8_t> compact_data, memo_data, noncompact_data;
  for (const auto& a : actions) {
    for (const auto& part : {zcashGet(a.nullifier), zcashGet(a.cmx),
                             zcashGet(a.epk), zcashGet(a.enc_compact)})
      compact_data.insert(compact_data.end(), part.begin(), part.end());
    const auto memo = zcashGet(a.enc_memo);
    memo_data.insert(memo_data.end(), memo.begin(), memo.end());
    for (const auto& part :
         {zcashGet(a.cv_net), zcashGet(a.rk), zcashGet(a.enc_noncompact),
          zcashGet(a.out_ciphertext)})
      noncompact_data.insert(noncompact_data.end(), part.begin(), part.end());
  }
  uint8_t compact[32], memos[32], noncompact[32];
  zcashPersonal(ironwood ? "ZTxIdIrnActCH_v6" : "ZTxIdOrcActCHash",
                compact_data, compact);
  zcashPersonal(ironwood ? "ZTxIdIrnActMH_v6" : "ZTxIdOrcActMHash", memo_data,
                memos);
  zcashPersonal(ironwood ? "ZTxIdIrnActNH_v6" : "ZTxIdOrcActNHash",
                noncompact_data, noncompact);
  std::vector<uint8_t> data(compact, compact + 32);
  data.insert(data.end(), memos, memos + 32);
  data.insert(data.end(), noncompact, noncompact + 32);
  data.push_back(flags);
  for (int i = 0; i < 8; i++)
    data.push_back(
        static_cast<uint8_t>(static_cast<uint64_t>(value_balance) >> (8 * i)));
  zcashPersonal(ironwood ? "ZTxIdIronwd_H_v6" : "ZTxIdOrchardH_v6", data,
                digest);
}

// A v6 NU6.3 request, as zcash_pool_migration builds it (expiry 69120).
ZcashSignPCZT zcashV6Request(uint32_t n_orchard, const uint8_t orchard[32],
                             uint8_t orchard_flags,
                             int64_t orchard_value_balance, uint64_t fee) {
  ZcashSignPCZT msg = {};
  msg.has_n_actions = true;
  msg.n_actions = n_orchard;
  msg.has_account = true;
  msg.has_tx_version = msg.has_version_group_id = msg.has_branch_id =
      msg.has_lock_time = msg.has_expiry_height = true;
  msg.tx_version = 6;
  msg.version_group_id = 0xD884B698;
  msg.branch_id = 0x37A5165B;
  msg.expiry_height = 69120;
  msg.has_header_digest = true;
  msg.header_digest.size = 32;
  zcash_compute_header_digest(msg.tx_version, msg.version_group_id,
                              msg.branch_id, msg.lock_time, msg.expiry_height,
                              msg.header_digest.bytes);
  msg.has_orchard_digest = true;
  msg.orchard_digest.size = 32;
  std::memcpy(msg.orchard_digest.bytes, orchard, 32);
  msg.has_orchard_flags = msg.has_orchard_value_balance = true;
  msg.orchard_flags = orchard_flags;
  msg.orchard_value_balance = orchard_value_balance;
  msg.has_orchard_anchor = true;
  zcashSet(msg.orchard_anchor, kZcashAnchor);
  msg.has_fee = true;
  msg.fee = fee;
  return msg;
}

void zcashAddIronwood(ZcashSignPCZT& msg, uint32_t n_ironwood,
                      const uint8_t ironwood[32], uint8_t flags,
                      int64_t value_balance) {
  msg.has_n_ironwood_actions = msg.has_ironwood_flags =
      msg.has_ironwood_value_balance = msg.has_ironwood_digest = true;
  msg.n_ironwood_actions = n_ironwood;
  msg.ironwood_flags = flags;
  msg.ironwood_value_balance = value_balance;
  msg.ironwood_digest.size = 32;
  std::memcpy(msg.ironwood_digest.bytes, ironwood, 32);
}

struct ZcashMigrationRun {
  std::vector<std::string> screens;
  std::vector<std::vector<uint8_t>> signatures;
};

// Streams a request and its actions, approving up to `screens` confirms.
ZcashMigrationRun zcashRunSession(const ZcashSignPCZT& msg,
                                  std::vector<ZcashPCZTAction>& actions,
                                  int screens) {
  ZcashMigrationRun run;
  EXPECT_TRUE(kkconfirm_preload(screens, 0));
  fsm_test_clearLastFailure();
  kkconfirm_capture_start();
  fsm_msgZcashSignPCZT(&msg);
  if (fsm_test_lastFailureCode() == 0) {
    for (auto& action : actions) {
      fsm_msgZcashPCZTAction(&action);
      if (fsm_test_lastFailureCode() != 0) break;
    }
  }
  run.screens = kkconfirm_capture_finish();
  EXPECT_FALSE(zcash_signing_is_active());
  ZcashSignedPCZT signed_pczt = {};
  if (fsm_test_lastFailureCode() == 0 &&
      kkconfirm_readResponse(MessageType_MessageType_ZcashSignedPCZT,
                             ZcashSignedPCZT_fields, &signed_pczt)) {
    for (pb_size_t i = 0; i < signed_pczt.signatures_count; i++)
      run.signatures.emplace_back(
          signed_pczt.signatures[i].bytes,
          signed_pczt.signatures[i].bytes + signed_pczt.signatures[i].size);
  } else {
    EXPECT_FALSE(zcashSignatureEmitted(kkconfirm_readResponseIds()));
  }
  (void)kkconfirm_drain();
  return run;
}
}  // namespace

// ZIP 318 migration transfer built by librustzcash's zcash_pool_migration:
// one v6 transaction spending an Orchard note into the Ironwood pool. Both
// bundles are streamed and recomputed. The Ironwood output pays the
// account's own internal address (ZIP 318), so the device shows it as change
// back to the wallet, then the fee; its one signature verifies under
// librustzcash's sighash.
// A claim for either bundle that does not match its actions, a tampered
// Ironwood note, or a wrong fee is refused with no signature; a host that
// does not declare the Ironwood actions is refused as before.
TEST_F(ReviewHandlers, ZcashMigrationTransferSignsBothPools) {
  enum Case {
    kAccepted,
    kOrchardClaimMismatch,
    kIronwoodClaimMismatch,
    kTamperedIronwoodNote,
    kWrongFee,
    kUndeclaredIronwood,
  };
  for (Case c : {kAccepted, kOrchardClaimMismatch, kIronwoodClaimMismatch,
                 kTamperedIronwoodNote, kWrongFee, kUndeclaredIronwood}) {
    SCOPED_TRACE(c);
    std::vector<ZcashPCZTAction> orchard, ironwood, actions;
    for (const auto& v : kZcashMigrationTransferOrchard)
      orchard.push_back(zcashMigrationAction(orchard.size(), v));
    for (const auto& v : kZcashMigrationTransferIronwood)
      ironwood.push_back(
          zcashMigrationAction(orchard.size() + ironwood.size(), v));
    uint8_t orchard_digest[32], ironwood_digest[32];
    zcashV6BundleDigest(orchard, false, 0x03, 1015000, orchard_digest);
    zcashV6BundleDigest(ironwood, true, 0x07, -1000000, ironwood_digest);
    if (c == kTamperedIronwoodNote) ironwood[0].cmx.bytes[0] ^= 1;
    if (c == kOrchardClaimMismatch) orchard_digest[0] ^= 1;
    if (c == kIronwoodClaimMismatch) ironwood_digest[0] ^= 1;
    ZcashSignPCZT msg = zcashV6Request(2, orchard_digest, 0x03, 1015000,
                                       c == kWrongFee ? 10000 : 15000);
    zcashAddIronwood(msg, 1, ironwood_digest, 0x07, -1000000);
    if (c == kUndeclaredIronwood) msg.has_n_ironwood_actions = false;
    actions = orchard;
    actions.insert(actions.end(), ironwood.begin(), ironwood.end());

    // Summary, the change total (the Ironwood output), then the fee.
    const auto run = zcashRunSession(msg, actions, 3);
    switch (c) {
      case kAccepted:
        break;
      case kOrchardClaimMismatch:
      case kIronwoodClaimMismatch:
        EXPECT_STREQ(
            "Shielded digest mismatch: transaction data does not match sighash",
            fsm_test_lastFailureMessage());
        EXPECT_TRUE(run.signatures.empty());
        continue;
      case kTamperedIronwoodNote:
        EXPECT_STREQ("Shielded note commitment mismatch",
                     fsm_test_lastFailureMessage());
        EXPECT_TRUE(run.signatures.empty());
        continue;
      case kWrongFee:
        EXPECT_STREQ("Fee mismatch", fsm_test_lastFailureMessage());
        EXPECT_TRUE(run.signatures.empty());
        continue;
      case kUndeclaredIronwood:
        EXPECT_STREQ("Orchard transaction must have an empty Ironwood bundle",
                     fsm_test_lastFailureMessage());
        EXPECT_TRUE(run.signatures.empty());
        continue;
    }

    EXPECT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()))
        << fsm_test_lastFailureMessage();
    ASSERT_EQ(3u, run.screens.size());
    EXPECT_NE(std::string::npos,
              run.screens[1].find("Change back to your wallet:\n0.01000000 ZEC"))
        << run.screens[1];
    EXPECT_NE(std::string::npos, run.screens[2].find("0.00015000 ZEC"));
    const auto sighash = zcashHex(kZcashMigrationTransferSighash);
    ASSERT_EQ(1u, run.signatures.size());  // the one real Orchard spend
    ASSERT_EQ(64u, run.signatures[0].size());
    EXPECT_EQ(0, redpallas_verify_digest(actions[1].rk.bytes, sighash.data(),
                                         run.signatures[0].data()));
  }
}

// ZIP 318 note preparation built by librustzcash: an Orchard-only v6
// transaction of exactly 16 actions, every spend the wallet's. Its fifteen
// outputs all pay the account's internal address, so instead of thirty output
// screens the device shows one change total. All 16 signatures verify under
// librustzcash's sighash.
TEST_F(ReviewHandlers, ZcashMigrationPreparationSignsSixteenActions) {
  std::vector<ZcashPCZTAction> actions;
  for (const auto& v : kZcashMigrationPrepOrchard)
    actions.push_back(zcashMigrationAction(actions.size(), v));
  ASSERT_EQ(16u, actions.size());
  uint8_t digest[32];
  zcashV6BundleDigest(actions, false, 0x03, 80000, digest);
  const ZcashSignPCZT msg = zcashV6Request(16, digest, 0x03, 80000, 80000);

  // Summary, the change total of the fifteen outputs, then the fee.
  const auto run = zcashRunSession(msg, actions, 3);
  EXPECT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()))
      << fsm_test_lastFailureMessage();
  ASSERT_EQ(3u, run.screens.size());
  EXPECT_NE(std::string::npos,
            run.screens[1].find("Change back to your wallet:\n0.15225000 ZEC"))
      << run.screens[1];
  EXPECT_NE(std::string::npos, run.screens[2].find("0.00080000 ZEC"));
  const auto sighash = zcashHex(kZcashMigrationPrepSighash);
  ASSERT_EQ(16u, run.signatures.size());
  for (size_t i = 0; i < 16; i++) {
    EXPECT_EQ(0, redpallas_verify_digest(actions[i].rk.bytes, sighash.data(),
                                         run.signatures[i].data()))
        << i;
  }
}

namespace {
// The t1 address of a P2PKH script.
std::string zcashT1(const std::vector<uint8_t>& script) {
  uint8_t raw[22] = {0x1c, 0xb8};
  std::memcpy(raw + 2, script.data() + 3, 20);
  char out[64];
  EXPECT_NE(0, base58_encode_check(raw, sizeof(raw), HASHER_SHA2D, out,
                                   sizeof(out)));
  return out;
}

ZcashTransparentOutput zcashOutput(const std::vector<uint8_t>& script,
                                   uint64_t amount) {
  ZcashTransparentOutput out = {};
  out.has_amount = out.has_script_pubkey = true;
  out.amount = amount;
  zcashSet(out.script_pubkey, script);
  return out;
}

void zcashSetPath(uint32_t* address_n, pb_size_t* count, uint32_t account,
                  uint32_t change, uint32_t index) {
  const uint32_t path[] = {0x80000000u | 44, 0x80000000u | 133,
                           0x80000000u | account, change, index};
  std::memcpy(address_n, path, sizeof(path));
  *count = 5;
}

struct ZcashTexRun {
  std::vector<std::string> screens;
  std::vector<std::vector<uint8_t>> orchard;
  std::vector<std::vector<uint8_t>> transparent;
  bool signed_pczt = false;
};

// Streams outputs, inputs, then actions, approving every screen; stops at the
// first failure.
ZcashTexRun zcashRunTex(const ZcashSignPCZT& msg,
                        std::vector<ZcashTransparentOutput> outputs,
                        std::vector<ZcashTransparentInput> inputs,
                        std::vector<ZcashPCZTAction> actions) {
  ZcashTexRun run;
  EXPECT_TRUE(kkconfirm_preload(16, 0));
  fsm_test_clearLastFailure();
  kkconfirm_capture_start();
  fsm_msgZcashSignPCZT(&msg);
  for (size_t i = 0; i < outputs.size() && !fsm_test_lastFailureCode(); i++) {
    outputs[i].index = i;
    fsm_msgZcashTransparentOutput(&outputs[i]);
  }
  for (size_t i = 0; i < inputs.size() && !fsm_test_lastFailureCode(); i++) {
    inputs[i].index = i;
    fsm_msgZcashTransparentInput(&inputs[i]);
  }
  for (size_t i = 0; i < actions.size() && !fsm_test_lastFailureCode(); i++)
    fsm_msgZcashPCZTAction(&actions[i]);
  run.screens = kkconfirm_capture_finish();
  EXPECT_FALSE(zcash_signing_is_active());
  if (fsm_test_lastFailureCode() == 0) {
    if (!inputs.empty()) {
      ZcashTransparentSigned t = {};
      EXPECT_TRUE(
          kkconfirm_readResponse(MessageType_MessageType_ZcashTransparentSigned,
                                 ZcashTransparentSigned_fields, &t));
      for (pb_size_t i = 0; i < t.signatures_count; i++)
        run.transparent.emplace_back(
            t.signatures[i].bytes,
            t.signatures[i].bytes + t.signatures[i].size);
    }
    ZcashSignedPCZT signed_pczt = {};
    run.signed_pczt =
        kkconfirm_readResponse(MessageType_MessageType_ZcashSignedPCZT,
                               ZcashSignedPCZT_fields, &signed_pczt);
    for (pb_size_t i = 0; i < signed_pczt.signatures_count; i++)
      run.orchard.emplace_back(signed_pczt.signatures[i].bytes,
                               signed_pczt.signatures[i].bytes +
                                   signed_pczt.signatures[i].size);
  } else {
    EXPECT_FALSE(zcashSignatureEmitted(kkconfirm_readResponseIds()));
  }
  (void)kkconfirm_drain();
  return run;
}

bool zcashShown(const ZcashTexRun& run, const std::string& text) {
  return std::any_of(run.screens.begin(), run.screens.end(),
                     [&](const std::string& s) {
                       return s.find(text) != std::string::npos;
                     });
}
}  // namespace

// ZIP 320 TEX step 1, built by librustzcash: a v6 NU6.3 transaction spending
// an Orchard note to the account's own one-time address m/44'/133'/0'/2/0.
// With that path the device proves the script pays its own key and shows a
// transfer to yourself, not a payment; without it, a normal send to the same
// t1 address. A path that does not pay the script, is not the one-time
// scope, belongs to another account, or claims to be a TEX is refused before
// any signature. The Orchard signature verifies under librustzcash's sighash.
TEST_F(ReviewHandlers, ZcashTexStep1PaysTheOwnOneTimeAddress) {
  const auto pubkey = zcashTransparentPubkey(0, 2);
  ASSERT_EQ(zcashHex(kZcashTexEphemeralPubkey), pubkey);
  const auto script = zcashHex(kZcashTexStep1OutputScript);
  ASSERT_EQ(zcashP2pkh(pubkey), script);
  const std::string t1 = zcashT1(script);

  std::vector<ZcashPCZTAction> actions;
  for (const auto& v : kZcashTexStep1Orchard)
    actions.push_back(zcashMigrationAction(actions.size(), v));
  uint8_t digest[32];
  zcashV6BundleDigest(actions, false, 0x03, kZcashTexStep1ValueBalance,
                      digest);
  ZcashTransparentOutputDigestInfo info = {};
  info.value = kZcashTexStep1OutputValue;
  info.script_pubkey = script.data();
  info.script_pubkey_size = script.size();

  enum Case { kOwn, kNoPath, kOtherIndex, kExternal, kOtherAccount, kTex };
  for (Case c : {kOwn, kNoPath, kOtherIndex, kExternal, kOtherAccount, kTex}) {
    SCOPED_TRACE(c);
    ZcashSignPCZT msg = zcashV6Request(2, digest, 0x03,
                                       kZcashTexStep1ValueBalance,
                                       kZcashTexStep1Fee);
    msg.has_n_transparent_outputs = msg.has_transparent_digest = true;
    msg.n_transparent_outputs = 1;
    msg.transparent_digest.size = 32;
    ASSERT_TRUE(zcash_compute_orchard_transparent_sig_digest(
        NULL, 0, &info, 1, msg.transparent_digest.bytes));
    ZcashTransparentOutput out = zcashOutput(script, kZcashTexStep1OutputValue);
    if (c != kNoPath)
      zcashSetPath(out.address_n, &out.address_n_count,
                   c == kOtherAccount ? 1 : 0, c == kExternal ? 0 : 2,
                   c == kOtherIndex ? 1 : 0);
    if (c == kTex) out.has_is_tex = out.is_tex = true;

    const auto run = zcashRunTex(msg, {out}, {}, actions);
    if (c == kOwn || c == kNoPath) {
      EXPECT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()))
          << fsm_test_lastFailureMessage();
      EXPECT_TRUE(zcashShown(run, c == kOwn ? "To your one-time address:\n" + t1
                                            : "Send transparent ZEC?\n" + t1));
      EXPECT_EQ(c == kOwn, zcashShown(run, "one-time"));
      EXPECT_TRUE(zcashShown(run, "Amount: 0.01010000 ZEC"));
      EXPECT_TRUE(zcashShown(run, "0.00015000 ZEC"));
      ASSERT_EQ(1u, run.orchard.size());  // the one real Orchard spend
      const auto sighash = zcashHex(kZcashTexStep1Sighash);
      EXPECT_EQ(0, redpallas_verify_digest(actions[1].rk.bytes, sighash.data(),
                                           run.orchard[0].data()));
      continue;
    }
    EXPECT_STREQ(c == kOtherIndex
                     ? "Transparent output script does not match path"
                 : c == kExternal ? "Output path must be a one-time address"
                 : c == kOtherAccount
                     ? "Account does not match approved session"
                     : "A one-time address is not a TEX",
                 fsm_test_lastFailureMessage());
    EXPECT_FALSE(zcashShown(run, t1));
    EXPECT_TRUE(run.orchard.empty());
  }
}

namespace {
// TEX step 2 as librustzcash builds it: the one-time output of step 1 to the
// ZIP 320 example TEX address, transparent-only, v6 (NU6.3) or v5 (NU6.2).
struct ZcashTexStep2 {
  ZcashSignPCZT msg;
  ZcashTransparentOutput output;
  ZcashTransparentInput input;
  std::vector<uint8_t> txid;
  std::vector<uint8_t> input_script;
  std::vector<uint8_t> output_script;
};

ZcashTexStep2 zcashTexStep2(bool v6) {
  ZcashTexStep2 t = {};
  t.txid = zcashHex(v6 ? kZcashTexStep2V6PrevoutTxid
                       : kZcashTexStep2V5PrevoutTxid);
  t.input_script = zcashHex(kZcashTexStep1OutputScript);
  t.output_script = zcashHex(kZcashTexStep2OutputScript);
  uint8_t empty_orchard[32];
  zcashPersonal(v6 ? "ZTxIdOrchardH_v6" : "ZTxIdOrchardHash", {},
                empty_orchard);
  t.msg = v6 ? zcashV6Request(0, empty_orchard, 0, 0, kZcashTexStep2Fee)
             : zcashSignRequest(0, empty_orchard, 0, kZcashTexStep2Fee);
  t.msg.orchard_flags = 0;
  t.msg.expiry_height = 69121;
  t.msg.branch_id = v6 ? 0x37A5165B : 0x5437F330;
  zcash_compute_header_digest(t.msg.tx_version, t.msg.version_group_id,
                              t.msg.branch_id, t.msg.lock_time,
                              t.msg.expiry_height, t.msg.header_digest.bytes);
  t.msg.has_n_transparent_inputs = t.msg.has_n_transparent_outputs = true;
  t.msg.n_transparent_inputs = t.msg.n_transparent_outputs = 1;

  t.output = zcashOutput(t.output_script, kZcashTexStep2OutputValue);
  t.output.has_is_tex = t.output.is_tex = true;

  ZcashTransparentInput& in = t.input;
  zcashSetPath(in.address_n, &in.address_n_count, 0, 2, 0);
  in.has_amount = in.has_prevout_txid = in.has_prevout_index =
      in.has_sequence = in.has_script_pubkey = true;
  in.amount = kZcashTexStep2InputValue;
  zcashSet(in.prevout_txid, t.txid);
  in.prevout_index = 0;
  in.sequence = 0xffffffff;
  zcashSet(in.script_pubkey, t.input_script);
  return t;
}

// The host's transparent digest claim for the current input and output.
void zcashTexClaimDigest(ZcashTexStep2& t) {
  ZcashTransparentInputDigestInfo in = {};
  in.prevout_txid = t.input.prevout_txid.bytes;
  in.prevout_index = t.input.prevout_index;
  in.sequence = t.input.sequence;
  in.value = t.input.amount;
  in.script_pubkey = t.input.script_pubkey.bytes;
  in.script_pubkey_size = t.input.script_pubkey.size;
  ZcashTransparentOutputDigestInfo out = {};
  out.value = t.output.amount;
  out.script_pubkey = t.output.script_pubkey.bytes;
  out.script_pubkey_size = t.output.script_pubkey.size;
  t.msg.has_transparent_digest = true;
  t.msg.transparent_digest.size = 32;
  ASSERT_TRUE(zcash_compute_orchard_transparent_sig_digest(
      &in, 1, &out, 1, t.msg.transparent_digest.bytes));
}
}  // namespace

// ZIP 320 TEX step 2, built by librustzcash in v6 and v5: no shielded action,
// one input from the account's one-time address, one P2PKH output to the TEX
// recipient. The device shows the tex1 address (the ZIP 320 example) when the
// host marks the output is_tex and the plain t1 form of the same key hash
// otherwise, then the fee and the input; the one ECDSA signature verifies under
// librustzcash's transparent sighash and no Orchard signature is returned. The
// canonical empty Sapling digest is accepted.
TEST_F(ReviewHandlers, ZcashTexStep2SignsATransparentOnlyTransaction) {
  const auto pubkey = zcashTransparentPubkey(0, 2);
  for (bool v6 : {true, false}) {
    for (bool tex : {true, false}) {
      SCOPED_TRACE(std::string(v6 ? "v6" : "v5") + (tex ? " tex" : " t1"));
      ZcashTexStep2 t = zcashTexStep2(v6);
      t.output.is_tex = tex;
      zcashTexClaimDigest(t);
      t.msg.has_sapling_digest = true;
      zcashSet(t.msg.sapling_digest, std::vector<uint8_t>(32));
      zcashPersonal("ZTxIdSaplingHash", {}, t.msg.sapling_digest.bytes);

      const auto run = zcashRunTex(t.msg, {t.output}, {t.input}, {});
      ASSERT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()))
          << fsm_test_lastFailureMessage();
      EXPECT_TRUE(zcashShown(run, "Send transparent ZEC?\nFee: 0.00010000 ZEC"));
      EXPECT_TRUE(zcashShown(
          run, tex ? std::string("Send to TEX address?\n") + kZcashTexAddress
                   : "Send transparent ZEC?\nt1VmmGiyjVNeCjxDZzg7vZmd99WyzVby9yC"));
      EXPECT_EQ(tex, zcashShown(run, "tex1"));
      EXPECT_TRUE(zcashShown(run, "Amount: 0.01000000 ZEC"));
      EXPECT_TRUE(zcashShown(run, "Confirm transaction fee?\n0.00010000 ZEC"));
      EXPECT_TRUE(zcashShown(run, "Input 1: 0.01010000 ZEC"));
      EXPECT_FALSE(zcashShown(run, "Shield"));
      EXPECT_FALSE(zcashShown(run, "Actions"));

      EXPECT_TRUE(run.signed_pczt);
      EXPECT_TRUE(run.orchard.empty());
      ASSERT_EQ(1u, run.transparent.size());
      uint8_t sig[64];
      ASSERT_EQ(0, ecdsa_sig_from_der(run.transparent[0].data(),
                                      run.transparent[0].size(), sig));
      const auto sighash =
          zcashHex(v6 ? kZcashTexStep2V6Sighash : kZcashTexStep2V5Sighash);
      EXPECT_EQ(0, ecdsa_verify_digest(&secp256k1, pubkey.data(), sig,
                                       sighash.data()));
    }
  }
}

// A transparent-only request is refused, with no signature, when it has no
// transparent input to sign, claims a shielded bundle the device would not
// see, or a non-empty Sapling component; an input path in the one-time scope
// of another account, or a change index past the one-time scope (2), is
// refused while streaming.
TEST_F(ReviewHandlers, ZcashTransparentOnlyRefusals) {
  const auto other_account = zcashP2pkh(zcashTransparentPubkey(0, 2, 1));
  const auto change3 = zcashP2pkh(zcashTransparentPubkey(0, 3));
  struct {
    const char* name;
    std::function<void(ZcashTexStep2&)> mutate;
    const char* failure;
  } cases[] = {
      {"no transparent input",
       [](ZcashTexStep2& t) { t.msg.n_transparent_inputs = 0; },
       "No actions specified"},
      {"ironwood actions",
       [](ZcashTexStep2& t) {
         t.msg.has_n_ironwood_actions = true;
         t.msg.n_ironwood_actions = 1;
       },
       "No actions specified"},
      {"orchard digest",
       [](ZcashTexStep2& t) { t.msg.orchard_digest.bytes[0] ^= 1; },
       "Transparent transaction must have empty shielded bundles"},
      {"orchard value balance",
       [](ZcashTexStep2& t) { t.msg.orchard_value_balance = 5000; },
       "Transparent transaction must have empty shielded bundles"},
      {"ironwood digest",
       [](ZcashTexStep2& t) {
         t.msg.has_ironwood_digest = true;
         t.msg.ironwood_digest.size = 32;
         t.msg.ironwood_digest.bytes[0] = 1;
       },
       "Orchard transaction must have an empty Ironwood bundle"},
      {"ironwood value balance",
       [](ZcashTexStep2& t) {
         t.msg.has_ironwood_value_balance = true;
         t.msg.ironwood_value_balance = -1;
       },
       "Transparent transaction must have empty shielded bundles"},
      {"sapling digest",
       [](ZcashTexStep2& t) {
         t.msg.has_sapling_digest = true;
         zcashSet(t.msg.sapling_digest, std::vector<uint8_t>(32, 0x11));
       },
       "Sapling not supported"},
      {"other account one-time input",
       [&](ZcashTexStep2& t) {
         zcashSetPath(t.input.address_n, &t.input.address_n_count, 1, 2, 0);
         zcashSet(t.input.script_pubkey, other_account);
       },
       "Account does not match approved session"},
      {"change 3",
       [&](ZcashTexStep2& t) {
         zcashSetPath(t.input.address_n, &t.input.address_n_count, 0, 3, 0);
         zcashSet(t.input.script_pubkey, change3);
       },
       "Change must be 0, 1 or 2"},
  };
  for (const auto& tc : cases) {
    SCOPED_TRACE(tc.name);
    ZcashTexStep2 t = zcashTexStep2(true);
    tc.mutate(t);
    zcashTexClaimDigest(t);
    const auto run = zcashRunTex(t.msg, {t.output}, {t.input}, {});
    EXPECT_STREQ(tc.failure, fsm_test_lastFailureMessage());
    EXPECT_TRUE(run.transparent.empty());
    EXPECT_FALSE(run.signed_pczt);
    EXPECT_FALSE(zcashShown(run, "Sign transparent input?"));
  }
}

// Transactions consensus can never accept are refused before any screen:
// reserved flag bits (Orchard bits 2..7, Ironwood bits 3..7), value entering
// the Orchard pool from NU6.3, a crossing outside a v6 NU6.3 transaction, and
// more than 16 actions in all.
TEST_F(ReviewHandlers, ZcashRefusesBundlesConsensusRejects) {
  std::vector<ZcashPCZTAction> orchard, ironwood;
  for (const auto& v : kZcashMigrationTransferOrchard)
    orchard.push_back(zcashMigrationAction(orchard.size(), v));
  for (const auto& v : kZcashMigrationTransferIronwood)
    ironwood.push_back(zcashMigrationAction(2, v));
  uint8_t orchard_digest[32], ironwood_digest[32];
  zcashV6BundleDigest(orchard, false, 0x03, 1015000, orchard_digest);
  zcashV6BundleDigest(ironwood, true, 0x07, -1000000, ironwood_digest);

  struct {
    const char* name;
    void (*mutate)(ZcashSignPCZT&);
    const char* failure;
  } cases[] = {
      {"orchard bit 2", [](ZcashSignPCZT& m) { m.orchard_flags = 0x07; },
       "Invalid shielded bundle flags"},
      {"orchard bit 7", [](ZcashSignPCZT& m) { m.orchard_flags = 0x83; },
       "Invalid shielded bundle flags"},
      {"ironwood bit 3", [](ZcashSignPCZT& m) { m.ironwood_flags = 0x0F; },
       "Invalid shielded bundle flags"},
      {"value into orchard",
       [](ZcashSignPCZT& m) { m.orchard_value_balance = -1; },
       "Value cannot enter the Orchard pool"},
      {"crossing in v5",
       [](ZcashSignPCZT& m) {
         m.tx_version = 5;
         m.version_group_id = 0x26A7270A;
       },
       "Invalid pool-crossing transaction"},
      {"crossing before NU6.3",
       [](ZcashSignPCZT& m) { m.branch_id = 0x5437F330; },
       "Invalid pool-crossing transaction"},
      {"ironwood session crossing",
       [](ZcashSignPCZT& m) {
         m.has_shielded_pool = true;
         m.shielded_pool = ZcashShieldedPool_ZCASH_SHIELDED_POOL_IRONWOOD;
       },
       "Invalid pool-crossing transaction"},
      {"17 actions", [](ZcashSignPCZT& m) { m.n_ironwood_actions = 15; },
       "Too many Orchard actions"},
  };
  for (const auto& tc : cases) {
    SCOPED_TRACE(tc.name);
    ZcashSignPCZT msg = zcashV6Request(2, orchard_digest, 0x03, 1015000, 15000);
    zcashAddIronwood(msg, 1, ironwood_digest, 0x07, -1000000);
    tc.mutate(msg);
    ASSERT_TRUE(kkconfirm_preload(1, 0));
    fsm_test_clearLastFailure();
    kkconfirm_capture_start();
    fsm_msgZcashSignPCZT(&msg);
    EXPECT_TRUE(kkconfirm_capture_finish().empty());
    EXPECT_STREQ(tc.failure, fsm_test_lastFailureMessage());
    EXPECT_FALSE(zcash_signing_is_active());
    (void)kkconfirm_drain();
  }
}
#endif

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
