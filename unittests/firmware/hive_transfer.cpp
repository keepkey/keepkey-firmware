extern "C" {
#include "keepkey/board/keepkey_display.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/memory.h"
#include "keepkey/firmware/app_confirm.h"
#include "keepkey/firmware/app_layout.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/hive.h"
#include "keepkey/firmware/storage.h"
#include "qrenc/qrcodegen.h"
#include "trezor/crypto/curves.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/secp256k1.h"
#include "trezor/crypto/sha2.h"
}

#include "gtest/gtest.h"
#include <cstring>
#include <string>
#include <vector>

bool kkconfirm_preload(int, int);
int kkconfirm_drain(void);
void kkconfirm_capture_start(void);
std::vector<std::string> kkconfirm_capture_finish(void);

static HiveSignTx transfer_request() {
  HiveSignTx msg = {};
  msg.has_from = msg.has_to = msg.has_amount = true;
  strcpy(msg.from, "alice");
  strcpy(msg.to, "bob");
  msg.amount = 1000;
  msg.has_ref_block_num = msg.has_ref_block_prefix = msg.has_expiration = true;
  msg.ref_block_num = 1;
  msg.ref_block_prefix = 2;
  msg.expiration = 3;
  return msg;
}

TEST(Hive, TransferAssetShownIsAssetSigned) {
  HDNode node = {};
  const uint8_t seed[32] = {1};
  ASSERT_EQ(1, hdnode_from_seed(seed, sizeof(seed), SECP256K1_NAME, &node));
  hdnode_fill_public_key(&node);
  for (const char* symbol : {"HIVE", "STEEM", "HBD", "SBD"}) {
    SCOPED_TRACE(symbol);
    HiveSignTx msg = transfer_request();
    msg.has_asset_symbol = true;
    strcpy(msg.asset_symbol, symbol);
    const bool hive =
        strcmp(symbol, "HIVE") == 0 || strcmp(symbol, "STEEM") == 0;
    const char *wire, *display;
    uint8_t precision = 0;
    ASSERT_TRUE(hive_transferAsset(&msg, &wire, &display, &precision));
    EXPECT_STREQ(hive ? "HIVE" : "HBD", display);
    EXPECT_STREQ(hive ? "STEEM" : "SBD", wire);
    EXPECT_EQ(3, precision);

    // Independent bytes, including empty memo/extensions; do not use the
    // firmware serializer or response as the signature oracle.
    std::vector<uint8_t> expected = {
        1,   0,   2, 0,   0,   0,   3,    0, 0, 0, 1, 2, 5, 'a', 'l', 'i',
        'c', 'e', 3, 'b', 'o', 'b', 0xe8, 3, 0, 0, 0, 0, 0, 0,   3};
    const char* signed_symbol = hive ? "STEEM" : "SBD";
    for (size_t i = 0; i < 7; i++)
      expected.push_back(i < strlen(signed_symbol) ? signed_symbol[i] : 0);
    expected.push_back(0);
    expected.push_back(0);
    HiveSignedTx response = {};
    hive_signTx(&node, &msg, &response);
    ASSERT_TRUE(response.has_signature);
    ASSERT_TRUE(response.has_serialized_tx);
    ASSERT_EQ(expected.size(), response.serialized_tx.size);
    EXPECT_EQ(0, memcmp(expected.data(), response.serialized_tx.bytes,
                        expected.size()));
    std::vector<uint8_t> preimage = {0xbe, 0xea, 0xb0, 0xde};
    preimage.resize(32, 0);
    preimage.insert(preimage.end(), expected.begin(), expected.end());
    uint8_t digest[32];
    sha256_Raw(preimage.data(), preimage.size(), digest);
    EXPECT_EQ(0, ecdsa_verify_digest(&secp256k1, node.public_key,
                                     response.signature.bytes + 1, digest));
  }
}

TEST(Hive, TransferRejectsUnsupportedAssetsAndUntruncatedPrecision) {
  HDNode node = {};
  const uint8_t seed[32] = {1};
  ASSERT_EQ(1, hdnode_from_seed(seed, sizeof(seed), SECP256K1_NAME, &node));
  for (const char* symbol : {"", "HIVEX", "VESTS", "hive"}) {
    HiveSignTx msg = transfer_request();
    msg.has_asset_symbol = true;
    strcpy(msg.asset_symbol, symbol);
    HiveSignedTx response = {};
    hive_signTx(&node, &msg, &response);
    EXPECT_FALSE(response.has_signature);
    EXPECT_FALSE(response.has_serialized_tx);
  }
  for (uint32_t decimals : {0u, 2u, 4u, 18u, 259u, UINT32_MAX}) {
    HiveSignTx msg = transfer_request();
    msg.has_decimals = true;
    msg.decimals = decimals;
    HiveSignedTx response = {};
    hive_signTx(&node, &msg, &response);
    EXPECT_FALSE(response.has_signature);
    EXPECT_FALSE(response.has_serialized_tx);
  }
}

template <typename Request, typename Response, typename Sign>
static void check_chain_id_contract(Request request, Sign sign) {
  // Omission is the documented mainnet default. Explicit malformed bytes
  // must never silently select that default, including an empty bytes field.
  Response baseline = {};
  sign(request, baseline);
  ASSERT_TRUE(baseline.has_signature);
  ASSERT_TRUE(baseline.has_serialized_tx);
  request.has_chain_id = true;
  memset(request.chain_id.bytes, 0xa5, sizeof(request.chain_id.bytes));
  for (size_t size = 0; size < HIVE_CHAIN_ID_LEN; ++size) {
    SCOPED_TRACE(size);
    request.chain_id.size = size;
    Response response = {};
    sign(request, response);
    EXPECT_FALSE(response.has_signature);
    EXPECT_FALSE(response.has_serialized_tx);
  }

  request.chain_id.size = HIVE_CHAIN_ID_LEN;
  const uint8_t mainnet[32] = {0xbe, 0xea, 0xb0, 0xde};
  memcpy(request.chain_id.bytes, mainnet, sizeof(mainnet));
  Response explicit_mainnet = {};
  sign(request, explicit_mainnet);
  ASSERT_TRUE(explicit_mainnet.has_signature);
  EXPECT_EQ(baseline.signature.size, explicit_mainnet.signature.size);
  EXPECT_EQ(0,
            memcmp(baseline.signature.bytes, explicit_mainnet.signature.bytes,
                   baseline.signature.size));

  // Preserve support for exact-length custom domains; their signatures must
  // differ even though the serialized transaction remains identical.
  request.chain_id.bytes[0] ^= 1;
  Response custom = {};
  sign(request, custom);
  ASSERT_TRUE(custom.has_signature);
  ASSERT_EQ(baseline.serialized_tx.size, custom.serialized_tx.size);
  EXPECT_EQ(0, memcmp(baseline.serialized_tx.bytes, custom.serialized_tx.bytes,
                      baseline.serialized_tx.size));
  EXPECT_NE(0, memcmp(baseline.signature.bytes, custom.signature.bytes,
                      baseline.signature.size));
}

TEST(Hive, AllSigningOperationsRejectMalformedExplicitChainIds) {
  HDNode node = {};
  const uint8_t seed[32] = {1};
  ASSERT_EQ(1, hdnode_from_seed(seed, sizeof(seed), SECP256K1_NAME, &node));
  hdnode_fill_public_key(&node);
  check_chain_id_contract<HiveSignTx, HiveSignedTx>(
      transfer_request(), [&](const HiveSignTx& msg, HiveSignedTx& response) {
        hive_signTx(&node, &msg, &response);
      });

  HiveSignAccountCreate create = {};
  create.has_creator = create.has_new_account_name = true;
  strcpy(create.creator, "alice");
  strcpy(create.new_account_name, "bob");
  create.has_ref_block_num = create.has_ref_block_prefix =
      create.has_expiration = true;
  create.ref_block_num = 1;
  create.ref_block_prefix = 2;
  create.expiration = 3;
  check_chain_id_contract<HiveSignAccountCreate, HiveSignedAccountCreate>(
      create,
      [&](const HiveSignAccountCreate& msg, HiveSignedAccountCreate& response) {
        hive_signAccountCreate(&node, &msg, node.public_key, node.public_key,
                               node.public_key, node.public_key, &response);
      });

  HiveSignAccountUpdate update = {};
  update.has_account = true;
  strcpy(update.account, "alice");
  update.has_ref_block_num = update.has_ref_block_prefix =
      update.has_expiration = true;
  update.ref_block_num = 1;
  update.ref_block_prefix = 2;
  update.expiration = 3;
  check_chain_id_contract<HiveSignAccountUpdate, HiveSignedAccountUpdate>(
      update,
      [&](const HiveSignAccountUpdate& msg, HiveSignedAccountUpdate& response) {
        hive_signAccountUpdate(&node, &msg, node.public_key, node.public_key,
                               node.public_key, node.public_key, &response);
      });
}

// TaPoS takes a 16-bit block number; a wider value is refused, not masked.
TEST(Hive, AllSigningOperationsRefuseAnOutOfRangeRefBlockNum) {
  HiveSignTx transfer = transfer_request();
  HiveSignAccountCreate create = {};
  create.has_creator = create.has_new_account_name = true;
  strcpy(create.creator, "alice");
  strcpy(create.new_account_name, "bob");
  create.has_ref_block_num = create.has_ref_block_prefix =
      create.has_expiration = true;
  create.ref_block_prefix = 2;
  create.expiration = 3;
  HiveSignAccountUpdate update = {};
  update.has_account = true;
  strcpy(update.account, "alice");
  update.has_ref_block_num = update.has_ref_block_prefix =
      update.has_expiration = true;
  update.ref_block_prefix = 2;
  update.expiration = 3;
  for (uint32_t ref : {0u, 0xFFFFu, 0x10000u, 0x10001u, 0xFFFFFFFFu}) {
    SCOPED_TRACE(ref);
    const bool in_range = ref <= 0xFFFF;
    transfer.ref_block_num = create.ref_block_num = update.ref_block_num = ref;
    EXPECT_EQ(in_range, hive_validateTransfer(&transfer));
    EXPECT_EQ(in_range, hive_validateAccountCreate(&create));
    EXPECT_EQ(in_range, hive_validateAccountUpdate(&update));
  }
}

TEST(Hive, TransferRejectsInvalidAmountAndAccountLabels) {
  HDNode node = {};
  const uint8_t seed[32] = {1};
  ASSERT_EQ(1, hdnode_from_seed(seed, sizeof(seed), SECP256K1_NAME, &node));
  for (uint64_t amount : {uint64_t(0), uint64_t(INT64_MAX) + 1, UINT64_MAX}) {
    HiveSignTx msg = transfer_request();
    msg.amount = amount;
    HiveSignedTx response = {};
    hive_signTx(&node, &msg, &response);
    EXPECT_FALSE(response.has_signature) << amount;
    EXPECT_FALSE(response.has_serialized_tx);
  }
  for (const char* name : {"", "ab", "Alice", "alice\nbob", "alice bob",
                           "@alice", "-alice", "alice-", "ali_ce", ".alice",
                           "alice.", "alice..bob", "a.bob", "alice.1bob"}) {
    for (bool sender : {false, true}) {
      HiveSignTx msg = transfer_request();
      strcpy(sender ? msg.from : msg.to, name);
      HiveSignedTx response = {};
      hive_signTx(&node, &msg, &response);
      EXPECT_FALSE(response.has_signature) << name;
      EXPECT_FALSE(response.has_serialized_tx);
    }
  }
  for (const char* name :
       {"abc", "alice-bob", "alice.bob", "abcdefghijklmnop"}) {
    HiveSignTx msg = transfer_request();
    strcpy(msg.from, name);
    strcpy(msg.to, name);
    msg.amount = INT64_MAX;
    msg.has_memo = true;
    memset(msg.memo, 'm', HIVE_MAX_MEMO_LEN);
    msg.memo[HIVE_MAX_MEMO_LEN] = 0;
    HiveSignedTx response = {};
    hive_signTx(&node, &msg, &response);
    ASSERT_TRUE(response.has_signature) << name;
    // Header12 + two length-prefixed accounts + asset16 + memo varint2 +
    // memo440 + extensions1. Proves the maximum payload is not truncated.
    EXPECT_EQ(473u + 2u * strlen(name), response.serialized_tx.size);
    EXPECT_EQ(0, response.serialized_tx.bytes[response.serialized_tx.size - 1]);
  }
}

// Independent Graphene/Hive layout for the two authority-bearing operations.
// Expected bytes are assembled here from the protocol's field order, not from
// the firmware serializer, with four DISTINCT keys so a swapped or repeated
// role cannot pass.
namespace {
using Bytes = std::vector<uint8_t>;

void put(Bytes& out, std::initializer_list<uint8_t> bytes) {
  out.insert(out.end(), bytes);
}
void put_string(Bytes& out, const char* text) {  // varint length < 128
  out.push_back((uint8_t)strlen(text));
  out.insert(out.end(), text, text + strlen(text));
}
void put_key(Bytes& out, const uint8_t key[33]) {
  out.insert(out.end(), key, key + 33);
}
// weight_threshold=1, no account_auths, one key_auth, weight=1
void put_authority(Bytes& out, const uint8_t key[33]) {
  put(out, {1, 0, 0, 0, 0, 1});
  put_key(out, key);
  put(out, {1, 0});
}
void put_header(Bytes& out, uint8_t operation) {
  put(out, {1, 0, 2, 0, 0, 0, 3, 0, 0, 0, 1, operation});
}

struct DistinctKeys {
  uint8_t owner[33], active[33], posting[33], memo[33];
  DistinctKeys() {
    owner[0] = active[0] = posting[0] = memo[0] = 2;
    memset(owner + 1, 0x11, 32);
    active[0] = 3;
    memset(active + 1, 0x22, 32);
    memset(posting + 1, 0x33, 32);
    memo[0] = 3;
    memset(memo + 1, 0x44, 32);
  }
};

void expect_signed_over(const HDNode& node, const Bytes& expected,
                        const uint8_t* serialized, size_t size,
                        const uint8_t* signature) {
  ASSERT_EQ(expected.size(), size);
  EXPECT_EQ(0, memcmp(expected.data(), serialized, size));
  Bytes preimage = {0xbe, 0xea, 0xb0, 0xde};
  preimage.resize(32, 0);
  preimage.insert(preimage.end(), expected.begin(), expected.end());
  uint8_t digest[32];
  sha256_Raw(preimage.data(), preimage.size(), digest);
  EXPECT_EQ(0, ecdsa_verify_digest(&secp256k1, node.public_key, signature + 1,
                                   digest));
}
}  // namespace

TEST(Hive, AccountCreateBytesMatchIndependentGrapheneLayout) {
  HDNode node = {};
  const uint8_t seed[32] = {1};
  ASSERT_EQ(1, hdnode_from_seed(seed, sizeof(seed), SECP256K1_NAME, &node));
  hdnode_fill_public_key(&node);
  const DistinctKeys keys;
  struct Case {
    const char *creator, *created;
    bool has_fee;
    uint64_t fee;  // amount signed: default 3000 when the field is omitted
  };
  const Case cases[] = {
      {"alice", "bob", false, 3000},
      {"alice", "bob", true, 0},
      {"abcdefghijklmnop", "qrstuvwxyzabcdef", true, INT64_MAX},
      {"abc.def", "ghi-jkl.mno", true, 1},
  };
  for (const Case& c : cases) {
    SCOPED_TRACE(std::string(c.creator) + "/" + c.created);
    HiveSignAccountCreate msg = {};
    msg.has_creator = msg.has_new_account_name = true;
    strcpy(msg.creator, c.creator);
    strcpy(msg.new_account_name, c.created);
    msg.has_fee_amount = c.has_fee;
    msg.fee_amount = c.fee;
    msg.has_ref_block_num = msg.has_ref_block_prefix = msg.has_expiration =
        true;
    msg.ref_block_num = 1;
    msg.ref_block_prefix = 2;
    msg.expiration = 3;

    Bytes expected;
    put_header(expected, 9);
    for (int i = 0; i < 8; i++) expected.push_back((uint8_t)(c.fee >> (8 * i)));
    put(expected, {3, 'S', 'T', 'E', 'E', 'M', 0, 0});
    put_string(expected, c.creator);
    put_string(expected, c.created);
    put_authority(expected, keys.owner);
    put_authority(expected, keys.active);
    put_authority(expected, keys.posting);
    put_key(expected, keys.memo);
    put(expected, {0, 0});  // empty json_metadata, empty extensions

    HiveSignedAccountCreate response = {};
    hive_signAccountCreate(&node, &msg, keys.owner, keys.active, keys.posting,
                           keys.memo, &response);
    ASSERT_TRUE(response.has_signature);
    ASSERT_TRUE(response.has_serialized_tx);
    expect_signed_over(node, expected, response.serialized_tx.bytes,
                       response.serialized_tx.size, response.signature.bytes);
  }
}

TEST(Hive, AccountUpdateBytesMatchIndependentGrapheneLayout) {
  HDNode node = {};
  const uint8_t seed[32] = {1};
  ASSERT_EQ(1, hdnode_from_seed(seed, sizeof(seed), SECP256K1_NAME, &node));
  hdnode_fill_public_key(&node);
  const DistinctKeys keys;
  for (const char* account : {"alice", "abcdefghijklmnop", "abc.def-ghi"}) {
    SCOPED_TRACE(account);
    HiveSignAccountUpdate msg = {};
    msg.has_account = true;
    strcpy(msg.account, account);
    msg.has_ref_block_num = msg.has_ref_block_prefix = msg.has_expiration =
        true;
    msg.ref_block_num = 1;
    msg.ref_block_prefix = 2;
    msg.expiration = 3;

    Bytes expected;
    put_header(expected, 10);
    put_string(expected, account);
    for (const uint8_t* key : {keys.owner, keys.active, keys.posting}) {
      expected.push_back(1);  // optional authority present
      put_authority(expected, key);
    }
    put_key(expected, keys.memo);
    put(expected, {0, 0});  // empty json_metadata, empty extensions

    HiveSignedAccountUpdate response = {};
    hive_signAccountUpdate(&node, &msg, keys.owner, keys.active, keys.posting,
                           keys.memo, &response);
    ASSERT_TRUE(response.has_signature);
    ASSERT_TRUE(response.has_serialized_tx);
    expect_signed_over(node, expected, response.serialized_tx.bytes,
                       response.serialized_tx.size, response.signature.bytes);
  }
}

TEST(Hive, PublicKeysRejectAccountIndexWithHardeningBit) {
  HDNode root = {};
  const uint8_t seed[32] = {1};
  ASSERT_EQ(1, hdnode_from_seed(seed, sizeof(seed), SECP256K1_NAME, &root));
  char keys[4][64];
  EXPECT_TRUE(hive_getPublicKeys(&root, 0x7FFFFFFFu, keys[0], 64, keys[1], 64,
                                 keys[2], 64, keys[3], 64));
  EXPECT_FALSE(hive_getPublicKeys(&root, 0x80000000u, keys[0], 64, keys[1], 64,
                                  keys[2], 64, keys[3], 64));
}

// The native binary has no mapped flash unless a test supplies one. Cleanup
// runs on every exit, including a failed ASSERT, so later tests never see a
// dangling emulator_flash_base.
struct HiveScopedFlash {
  std::vector<uint8_t> bytes = std::vector<uint8_t>(FLASH_TOTAL_SIZE, 0xff);
  uint8_t* previous = emulator_flash_base;
  HiveScopedFlash() {
    emulator_flash_base = bytes.data();
    storage_init();
  }
  ~HiveScopedFlash() {
    storage_wipe();
    storage_reset();
    emulator_flash_base = previous;
  }
};

TEST(Hive, PublicKeyHandlersRejectNonHivePathsAndAliasedAccounts) {
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  ASSERT_EQ(0, kkconfirm_drain());
  HiveScopedFlash flash;
  LoadDevice load = {};
  load.has_mnemonic = true;
  strcpy(load.mnemonic, "all all all all all all all all all all all all");
  storage_loadDevice(&load);
  // Nothing below may show a screen: only the sentinel is queued.
  ASSERT_TRUE(kkconfirm_preload(0, 0));

  HiveGetPublicKey key = {};
  const uint32_t hive_path[5] = {HIVE_SLIP48_PURPOSE, HIVE_SLIP48_NETWORK,
                                 HIVE_ROLE_OWNER, 0x80000000u, 0x80000000u};
  key.address_n_count = 5;
  memcpy(key.address_n, hive_path, sizeof(hive_path));
  fsm_test_clearLastFailure();
  fsm_msgHiveGetPublicKey(&key);
  EXPECT_EQ(0, fsm_test_lastFailureCode());  // control: real Hive path
  // Every component outside the SLIP-0048 Hive shape is refused before
  // derivation, including the role slot the display label is taken from.
  for (int i = 0; i < 5; ++i) {
    SCOPED_TRACE(i);
    memcpy(key.address_n, hive_path, sizeof(hive_path));
    key.address_n[i] = i == 2   ? 0x80000002u
                       : i == 3 ? 0u
                                : key.address_n[i] ^ 1u;
    fsm_test_clearLastFailure();
    fsm_msgHiveGetPublicKey(&key);
    EXPECT_EQ(FailureType_Failure_SyntaxError, fsm_test_lastFailureCode());
  }
  key.address_n_count = 4;
  memcpy(key.address_n, hive_path, sizeof(hive_path));
  fsm_test_clearLastFailure();
  fsm_msgHiveGetPublicKey(&key);
  EXPECT_EQ(FailureType_Failure_SyntaxError, fsm_test_lastFailureCode());

  HiveGetPublicKeys keys = {};
  keys.has_account_index = true;
  keys.account_index = 0x7FFFFFFFu;
  fsm_test_clearLastFailure();
  fsm_msgHiveGetPublicKeys(&keys);
  EXPECT_EQ(0, fsm_test_lastFailureCode());
  keys.account_index = 0x80000001u;
  fsm_test_clearLastFailure();
  fsm_msgHiveGetPublicKeys(&keys);
  EXPECT_EQ(FailureType_Failure_SyntaxError, fsm_test_lastFailureCode());
  EXPECT_EQ(0, kkconfirm_drain());
}

namespace {
std::vector<std::vector<uint8_t>> frames;
void record_frame(const uint8_t* buffer) {
  const Canvas* canvas = layout_get_canvas();
  frames.emplace_back(buffer, buffer + canvas->width * canvas->height);
}
std::vector<uint8_t> standard_screen(const char* title, const char* body) {
  layout_standard_notification(title, body, NOTIFICATION_REQUEST);
  const Canvas* canvas = layout_get_canvas();
  return std::vector<uint8_t>(canvas->buffer,
                              canvas->buffer + canvas->width * canvas->height);
}
}  // namespace

// A 53-character STM key overflows the address layout's text area, which
// clips it. Every page must instead be the standard body screen, which the
// pager has measured, and the pages together must be the whole key. A QR of
// the same key follows on its own screen.
TEST(Hive, ShowDisplayRendersTheCompleteKey) {
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  ASSERT_EQ(0, kkconfirm_drain());
  HiveScopedFlash flash;
  LoadDevice load = {};
  load.has_mnemonic = true;
  strcpy(load.mnemonic, "all all all all all all all all all all all all");
  storage_loadDevice(&load);

  HDNode root = {};
  ASSERT_TRUE(storage_getRootNode(SECP256K1_NAME, true, &root));
  char expected[4][64];
  ASSERT_TRUE(hive_getPublicKeys(&root, 0, expected[0], 64, expected[1], 64,
                                 expected[2], 64, expected[3], 64));
  memzero(&root, sizeof(root));
  const std::string key = expected[0];
  ASSERT_EQ(53u, key.size());

  std::vector<std::string> pages;
  for (size_t offset = 0; offset < key.size();) {
    char page[BODY_CHAR_MAX];
    const size_t take =
        confirm_bytes_format_page((const uint8_t*)key.data() + offset,
                                  key.size() - offset, page, sizeof(page));
    ASSERT_GT(take, 0u);
    pages.emplace_back(page);
    offset += take;
  }

  HiveGetPublicKey msg = {};
  const uint32_t path[5] = {HIVE_SLIP48_PURPOSE, HIVE_SLIP48_NETWORK,
                            HIVE_ROLE_OWNER, 0x80000000u, 0x80000000u};
  msg.address_n_count = 5;
  memcpy(msg.address_n, path, sizeof(path));
  msg.has_show_display = msg.show_display = true;

  ASSERT_TRUE(kkconfirm_preload((int)pages.size() + 1, 0));
  frames.clear();
  display_set_dump_callback(record_frame);
  kkconfirm_capture_start();
  fsm_test_clearLastFailure();
  fsm_msgHiveGetPublicKey(&msg);
  const auto screens = kkconfirm_capture_finish();
  display_set_dump_callback(nullptr);
  EXPECT_EQ(0, fsm_test_lastFailureCode());
  EXPECT_EQ(0, kkconfirm_drain());
  std::vector<std::string> expected_screens = pages;
  expected_screens.push_back(key);
  ASSERT_EQ(expected_screens, screens);

  for (size_t i = 0; i < pages.size(); i++) {
    SCOPED_TRACE(i);
    std::string title = "Hive Owner Key";
    if (pages.size() > 1)
      title += " " + std::to_string(i + 1) + "/" + std::to_string(pages.size());
    const auto reference = standard_screen(title.c_str(), pages[i].c_str());
    bool shown = false;
    for (const auto& frame : frames) shown = shown || frame == reference;
    EXPECT_TRUE(shown) << "page not drawn by the measured body renderer";
  }

  // Independent QR of the key (layout_address()'s large-code parameters):
  // some frame must carry exactly these modules where the QR is drawn.
  uint8_t code[qrcodegen_BUFFER_LEN_MAX], temp[qrcodegen_BUFFER_LEN_MAX];
  ASSERT_TRUE(qrcodegen_encodeText(key.c_str(), temp, code, qrcodegen_Ecc_LOW,
                                   8, 9, qrcodegen_Mask_AUTO, true));
  const int side = qrcodegen_getSize(code);
  const int width = layout_get_canvas()->width;
  bool qr_shown = false;
  for (const auto& frame : frames) {
    bool match = true;
    for (int i = 0; match && i < side; i++) {
      for (int j = 0; match && j < side; j++) {
        const int x = QR_DISPLAY_SCALE + (i + QR_DISPLAY_X) * QR_DISPLAY_SCALE;
        const int y =
            QR_DISPLAY_SCALE + (j + QR_DISPLAY_Y - 4) * QR_DISPLAY_SCALE;
        match = frame[y * width + x] ==
                (qrcodegen_getModule(code, i, j) ? 0x00 : 0xFF);
      }
    }
    qr_shown = qr_shown || match;
  }
  EXPECT_TRUE(qr_shown) << "no screen shows a QR of the key";
}

// hive_deriveRawKey derives only a SLIP-0048 Hive role key: an unknown role or
// an unhardened account index is refused, never derived.
TEST(Hive, DeriveRawKeyRefusesNonHivePaths) {
  HDNode root = {};
  const uint8_t seed[32] = {1};
  ASSERT_EQ(1, hdnode_from_seed(seed, sizeof(seed), SECP256K1_NAME, &root));
  uint8_t key[33] = {};
  EXPECT_TRUE(hive_deriveRawKey(&root, HIVE_ROLE_ACTIVE, 0x80000000u, key));
  for (uint32_t role : {0x80000002u, 0x80000005u, 1u}) {
    EXPECT_FALSE(hive_deriveRawKey(&root, role, 0x80000000u, key)) << role;
  }
  EXPECT_FALSE(hive_deriveRawKey(&root, HIVE_ROLE_OWNER, 0u, key));
}
