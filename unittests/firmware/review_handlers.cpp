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
#endif
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

// Handler-level walk of a whole shielded-only session: summary, one streamed
// output action (the cmx is the device's own known-answer vector, see
// OrchardNoteCommitment_KnownVectorAndProgress), the recomputed bundle digest,
// then the final fee gate. A legacy host action sighash is refused outright. A bundle digest the device does not recompute, or a
// host fee other than the verified one (here orchard_value_balance, 0), aborts
// before the fee screen and releases nothing; the matching request reaches the
// fee screen and completes.
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
}  // namespace

TEST_F(ReviewHandlers, ZcashSessionCompletesOnlyPastTheDigestAndFeeGates) {
  const auto rho = zcashHex(
      "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00");
  const auto cmx = zcashHex(
      "02defb39c8f2e1ecc945189373cf2a8e21d4e154398efa1621d5fb989e1deb36");
  const auto recipient = zcashHex(
      "3c150e6098b861716cc7f62835f69feb302193c92660444f26624fd13e00ea7a"
      "c774cd55074d6367efef37");
  const auto rseed = zcashHex(
      "cafebabedeadbeef0102030405060708090a0b0c0d0e0f101112131415161718");
  const std::vector<uint8_t> epk(32, 2), enc_compact(52, 3), enc_memo(512, 4),
      enc_noncompact(16, 5), cv_net(32, 6), rk(32, 7), out_ciphertext(80, 8),
      anchor(32, 0x13);
  const uint8_t flags = 3;

  // The ZIP-244 Orchard bundle digest the device recomputes.
  uint8_t compact[32], memos[32], noncompact[32], digest[32];
  std::vector<uint8_t> data = rho;
  data.insert(data.end(), cmx.begin(), cmx.end());
  data.insert(data.end(), epk.begin(), epk.end());
  data.insert(data.end(), enc_compact.begin(), enc_compact.end());
  zcashPersonal("ZTxIdOrcActCHash", data, compact);
  zcashPersonal("ZTxIdOrcActMHash", enc_memo, memos);
  data = cv_net;
  data.insert(data.end(), rk.begin(), rk.end());
  data.insert(data.end(), enc_noncompact.begin(), enc_noncompact.end());
  data.insert(data.end(), out_ciphertext.begin(), out_ciphertext.end());
  zcashPersonal("ZTxIdOrcActNHash", data, noncompact);
  data.assign(compact, compact + 32);
  data.insert(data.end(), memos, memos + 32);
  data.insert(data.end(), noncompact, noncompact + 32);
  data.push_back(flags);
  data.insert(data.end(), 8, 0);  // orchard_value_balance = 0, LE i64
  data.insert(data.end(), anchor.begin(), anchor.end());
  zcashPersonal("ZTxIdOrchardHash", data, digest);

  enum Case { kHostSighash, kTamperedDigest, kFeeMismatch, kAccepted };
  for (Case c : {kHostSighash, kTamperedDigest, kFeeMismatch, kAccepted}) {
    SCOPED_TRACE(c);
    ZcashSignPCZT msg = {};
    msg.has_n_actions = true;
    msg.n_actions = 1;
    msg.has_account = true;
    msg.has_tx_version = msg.has_version_group_id = msg.has_branch_id =
        msg.has_lock_time = msg.has_expiry_height = true;
    msg.tx_version = 5;
    msg.version_group_id = 0x26a7270a;
    msg.branch_id = 0x5437f330;
    msg.has_header_digest = true;
    msg.header_digest.size = 32;
    ASSERT_TRUE(zcash_compute_header_digest(
        msg.tx_version, msg.version_group_id, msg.branch_id, msg.lock_time,
        msg.expiry_height, msg.header_digest.bytes));
    msg.has_orchard_digest = true;
    msg.orchard_digest.size = 32;
    std::memcpy(msg.orchard_digest.bytes, digest, 32);
    if (c == kTamperedDigest) msg.orchard_digest.bytes[0] ^= 1;
    msg.has_orchard_flags = msg.has_orchard_value_balance = true;
    msg.orchard_flags = flags;
    msg.has_orchard_anchor = true;
    zcashSet(msg.orchard_anchor, anchor);
    msg.has_fee = true;
    msg.fee = c == kFeeMismatch ? 1000 : 0;

    // Summary, the two output screens, then the fee screen if it is reached.
    ASSERT_TRUE(kkconfirm_preload(4, 0));
    fsm_test_clearLastFailure();
    kkconfirm_capture_start();
    fsm_msgZcashSignPCZT(&msg);
    ASSERT_EQ(0, static_cast<int>(fsm_test_lastFailureCode()));

    ZcashPCZTAction action = {};
    action.has_index = action.has_is_spend = true;
    action.has_alpha = true;
    zcashSet(action.alpha, std::vector<uint8_t>(32, 1));
    action.has_value = true;
    action.value = 12345678;
    action.has_nullifier = action.has_cmx = action.has_epk = true;
    zcashSet(action.nullifier, rho);
    zcashSet(action.cmx, cmx);
    zcashSet(action.epk, epk);
    action.has_enc_compact = action.has_enc_memo = true;
    action.has_enc_noncompact = true;
    zcashSet(action.enc_compact, enc_compact);
    zcashSet(action.enc_memo, enc_memo);
    zcashSet(action.enc_noncompact, enc_noncompact);
    action.has_cv_net = action.has_rk = action.has_out_ciphertext = true;
    zcashSet(action.cv_net, cv_net);
    zcashSet(action.rk, rk);
    zcashSet(action.out_ciphertext, out_ciphertext);
    action.has_recipient = action.has_rseed = true;
    zcashSet(action.recipient, recipient);
    zcashSet(action.rseed, rseed);
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
    if (c == kHostSighash) {
      // Refused before the output screens: only the summary was shown.
      EXPECT_EQ(FailureType_Failure_SyntaxError, fsm_test_lastFailureCode());
      EXPECT_STREQ("Host action sighash rejected",
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
