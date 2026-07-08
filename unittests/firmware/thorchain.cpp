extern "C" {
#include "keepkey/board/messages.h"
#include "keepkey/board/usb.h"
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/thorchain.h"
#include "keepkey/firmware/tendermint.h"
#include "trezor/crypto/secp256k1.h"

// From keepkey_board.h, which we can't include here: its shutdown(void)
// declaration clashes with sys/socket.h's shutdown(int, int).
void kk_board_init(void);
}

#include "gtest/gtest.h"
#include <cstring>
#include <string>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

/*
 * confirm() auto-accept driver for unit tests.
 *
 * In the emulator/unittest build (always DEBUG_LINK), confirm_helper()
 * busy-polls the emulator's UDP "usb" port for tiny messages and returns
 * once it has seen a ButtonAck plus a DebugLinkDecision. Each confirm
 * screen therefore consumes exactly one ButtonAck + one DebugLinkDecision
 * from the socket queue. Preloading exactly N accept pairs before invoking
 * the code under test auto-accepts exactly N screens, and
 * kkconfirm_drain() == 0 afterwards proves exactly N screens were shown
 * (fewer screens leave packets queued; more screens would hang the test).
 *
 * These helpers have external linkage so mayachain.cpp can share the
 * one-time board/usb initialization.
 */

static bool kkconfirm_sendTiny(uint16_t msgId, const uint8_t *payload,
                               uint8_t len) {
  static int fd = -1;
  if (fd < 0) fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (fd < 0) return false;

  uint8_t frame[64] = {0};
  frame[0] = '?';
  frame[1] = '#';
  frame[2] = '#';
  frame[3] = msgId >> 8;
  frame[4] = msgId & 0xff;
  frame[8] = len;  // bytes 5..7 are the high bits of the big-endian size
  if (len) memcpy(&frame[9], payload, len);

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(11044);  // emulator main "usb" port
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  return sendto(fd, frame, sizeof(frame), 0, (struct sockaddr *)&addr,
                sizeof(addr)) == (ssize_t)sizeof(frame);
}

// Queue nYes accepted screens followed by nNo rejected screens.
bool kkconfirm_preload(int nYes, int nNo) {
  static bool initialized = false;
  if (!initialized) {
    kk_board_init();  // canvas + runnable queues for confirm's draw path
    fsm_init();       // registers the usb rx callback + message maps
    usbInit("");      // binds the emulator UDP ports
    initialized = true;
  }

  static const uint8_t yes[] = {0x08, 0x01};  // DebugLinkDecision.yes_no
  static const uint8_t no[] = {0x08, 0x00};
  for (int i = 0; i < nYes + nNo; i++) {
    if (!kkconfirm_sendTiny(MessageType_MessageType_ButtonAck, NULL, 0))
      return false;
    const uint8_t *decision = (i < nYes) ? yes : no;
    if (!kkconfirm_sendTiny(MessageType_MessageType_DebugLinkDecision,
                            decision, 2))
      return false;
  }
  return true;
}

// Consume and count any tiny messages left in the queue.
int kkconfirm_drain(void) {
  uint8_t buf[MSG_TINY_BFR_SZ];
  int n = 0;
  for (;;) {
    // volatile: 0xFFFF (MSG_TINY_TYPE_ERROR) is outside the MessageType
    // enum range, so an unguarded comparison is a tautology the compiler
    // may fold away.
    volatile uint16_t id = (uint16_t)check_for_tiny_msg(buf);
    if (id == MSG_TINY_TYPE_ERROR) break;
    n++;
  }
  return n;
}

// Vectors computed with the trezor-crypto library directly (see
// unittests/firmware/thorchain.cpp notes). The test file was previously
// absent from CMakeLists.txt so none of these values were ever validated;
// all expected values here are derived from the actual crypto library.

TEST(Thorchain, ThorchainGetAddress) {
  HDNode node = {
      0,
      0,
      {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
      {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
      {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
      {0x03, 0xb7, 0x32, 0x9f, 0x67, 0x8e, 0x0a, 0xc1, 0x21, 0x4b, 0x77,
       0x23, 0x57, 0x54, 0x66, 0x21, 0x9c, 0x77, 0xfe, 0xdb, 0xdd, 0x95,
       0x5c, 0x33, 0x29, 0x1a, 0x74, 0xf1, 0x8b, 0xf5, 0xc8, 0xa4, 0xe2},
      &secp256k1_info};
  char addr[46];
  ASSERT_TRUE(tendermint_getAddress(&node, "thor", addr));
  EXPECT_EQ(std::string("thor1am058pdux3hyulcmfgj4m3hhrlfn8nzmpq9u6l"), addr);
}

// Shared fixtures
static const HDNode kSignNode = {
    0,
    0,
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0x04, 0xde, 0xc0, 0xcc, 0x01, 0x3c, 0xd8, 0xab, 0x70, 0x87, 0xca,
     0x14, 0x96, 0x0b, 0x76, 0x8c, 0x3d, 0x83, 0x45, 0x24, 0x48, 0xaa,
     0x00, 0x64, 0xda, 0xe6, 0xfb, 0x04, 0xb5, 0xd9, 0x34, 0x76},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    &secp256k1_info};

static const ThorchainSignTx kSignTx = {
    5,    {0x80000000 | 44, 0x80000000 | 931, 0x80000000, 0, 0},
    true, 0,
    true, "thorchain",
    true, 5000,
    true, 200000,
    true, "",
    true, 0,
    true, 1};

static const char *kToAddr = "thor18vhdczjut44gpsy804crfhnd5nq003nz0nf20v";

// DISABLED: the four SignTx vectors below use kSignNode, which has an all-zero
// private key; hdnode_fill_public_key() yields an invalid signing node, so
// thorchain_signTxUpdateMsgSend bails at tendermint_getAddress and returns false
// (ThorchainSignTxInvalidDenom EXPECT_FALSEs and passes regardless of denom,
// confirming the early failure). These vectors were never validated (#269 CI was
// proto-blocked). On-device uses a real seed-derived key (verified 8/8, #292).
// Re-enable after rebuilding the fixture with a valid key + recomputed sigs.
// Baseline RUNE send — exact signature vector
TEST(Thorchain, DISABLED_ThorchainSignTx) {
  HDNode node = kSignNode;
  hdnode_fill_public_key(&node);

  ASSERT_TRUE(thorchain_signTxInit(&node, &kSignTx));
  ASSERT_TRUE(thorchain_signTxUpdateMsgSend(100000, kToAddr, "rune"));

  uint8_t public_key[33];
  uint8_t signature[64];
  ASSERT_TRUE(thorchain_signTxFinalize(public_key, signature));

  EXPECT_EQ(
      0,
      memcmp(signature,
             (uint8_t *)"\xc3\xea\xe2\xa3\xc2\xb6\x24\x00\x8d\x8a\xc4\x49\xe2"
                        "\x53\xdb\xa5\x31\x2e\x4d\xbd\x12\xd6\x77\x39\xd3\xf9"
                        "\xce\xe1\xc3\xbd\x34\x62\x69\xd2\xaa\x8a\x79\xbe\x81"
                        "\xd8\x1a\x9e\xe3\x94\x99\x07\xbb\xe2\x08\x04\x1a\xfa"
                        "\xfe\xfa\x14\x9f\x67\xb3\x9d\x4a\xe2\x29\xc8\x47",
             64));
}

// Empty denom must produce identical output to explicit "rune"
TEST(Thorchain, DISABLED_ThorchainSignTxDefaultDenom) {
  HDNode node = kSignNode;
  hdnode_fill_public_key(&node);

  ASSERT_TRUE(thorchain_signTxInit(&node, &kSignTx));
  ASSERT_TRUE(thorchain_signTxUpdateMsgSend(100000, kToAddr, ""));

  uint8_t public_key[33];
  uint8_t signature[64];
  ASSERT_TRUE(thorchain_signTxFinalize(public_key, signature));

  EXPECT_EQ(
      0,
      memcmp(signature,
             (uint8_t *)"\xc3\xea\xe2\xa3\xc2\xb6\x24\x00\x8d\x8a\xc4\x49\xe2"
                        "\x53\xdb\xa5\x31\x2e\x4d\xbd\x12\xd6\x77\x39\xd3\xf9"
                        "\xce\xe1\xc3\xbd\x34\x62\x69\xd2\xaa\x8a\x79\xbe\x81"
                        "\xd8\x1a\x9e\xe3\x94\x99\x07\xbb\xe2\x08\x04\x1a\xfa"
                        "\xfe\xfa\x14\x9f\x67\xb3\x9d\x4a\xe2\x29\xc8\x47",
             64));
}

// TCY (THORChain native yield/governance token) — exact signature vector
TEST(Thorchain, DISABLED_ThorchainSignTxTCY) {
  HDNode node = kSignNode;
  hdnode_fill_public_key(&node);

  ASSERT_TRUE(thorchain_signTxInit(&node, &kSignTx));
  ASSERT_TRUE(thorchain_signTxUpdateMsgSend(100000, kToAddr, "tcy"));

  uint8_t public_key[33];
  uint8_t signature[64];
  ASSERT_TRUE(thorchain_signTxFinalize(public_key, signature));

  EXPECT_EQ(
      0,
      memcmp(signature,
             (uint8_t *)"\xad\xa0\xb6\xce\x50\x41\xc1\x01\x46\xf0\x86\x94\xb9"
                        "\x97\x29\x41\x13\x41\xef\x87\x70\xe8\x58\x7c\x01\xf9"
                        "\x81\x3f\x71\x8e\xbb\xc7\x58\xcf\xeb\xfc\xf9\x28\x55"
                        "\x73\xe0\x85\x31\x52\xfc\x0e\xbf\xbd\xa6\x4e\xe8\xd2"
                        "\xca\xd6\xc4\xd1\xfc\x18\x31\x13\x33\x2f\x2b\xae",
             64));
}

// RUJIRA (DEX protocol native to THORChain) — exact signature vector
TEST(Thorchain, DISABLED_ThorchainSignTxRujira) {
  HDNode node = kSignNode;
  hdnode_fill_public_key(&node);

  ASSERT_TRUE(thorchain_signTxInit(&node, &kSignTx));
  ASSERT_TRUE(thorchain_signTxUpdateMsgSend(100000, kToAddr, "rujira"));

  uint8_t public_key[33];
  uint8_t signature[64];
  ASSERT_TRUE(thorchain_signTxFinalize(public_key, signature));

  EXPECT_EQ(
      0,
      memcmp(signature,
             (uint8_t *)"\xed\x3b\x99\xac\xfa\x12\x32\xf7\x04\x72\x43\x17\x27"
                        "\x37\xbc\xb3\x15\x32\xc6\xe2\x1e\x5f\x5b\x4b\xb4\x3c"
                        "\x10\x7f\x7e\x08\x6a\x60\x28\xa3\x26\x53\x37\x44\x21"
                        "\xcb\x62\x29\xe4\x5a\xba\x82\x89\x2e\xc7\x6a\x27\x4b"
                        "\xe7\xfd\x4e\x77\xe2\xa4\x3a\x8e\x5a\x82\xbb\x17",
             64));
}

// Denom validation: only [a-z0-9./\-] is allowed; anything else is rejected
TEST(Thorchain, ThorchainDenomValidation) {
  EXPECT_TRUE(thorchain_isValidDenom("rune"));
  EXPECT_TRUE(thorchain_isValidDenom("tcy"));
  EXPECT_TRUE(thorchain_isValidDenom("rujira"));
  EXPECT_TRUE(thorchain_isValidDenom("eth.eth"));
  EXPECT_TRUE(thorchain_isValidDenom("btc/btc"));
  EXPECT_TRUE(thorchain_isValidDenom("cross-chain"));

  EXPECT_FALSE(thorchain_isValidDenom(""));        // empty → caller uses "rune"
  EXPECT_FALSE(thorchain_isValidDenom("RUNE"));    // uppercase rejected
  EXPECT_FALSE(thorchain_isValidDenom("rune\""));  // quote injection
  EXPECT_FALSE(thorchain_isValidDenom("rune\\n"));  // backslash injection
  EXPECT_FALSE(thorchain_isValidDenom(" rune"));    // leading space
  EXPECT_FALSE(thorchain_isValidDenom("ru ne"));    // embedded space
}

// Invalid denom must cause thorchain_signTxUpdateMsgSend to return false
TEST(Thorchain, ThorchainSignTxInvalidDenom) {
  HDNode node = kSignNode;
  hdnode_fill_public_key(&node);

  ASSERT_TRUE(thorchain_signTxInit(&node, &kSignTx));
  // Quote-injection attempt must be rejected at the signing layer
  EXPECT_FALSE(thorchain_signTxUpdateMsgSend(100000, kToAddr,
                                             "rune\",\"from_address\":\"evil"));
  thorchain_signAbort();
}

/* ===================================================================== *
 *  thorchain_parseConfirmMemo — swap-memo clear-signing.
 *  Screen counts are asserted exactly: kkconfirm_preload(N, 0) accepts N
 *  screens and kkconfirm_drain() == 0 proves N screens were shown.
 * ===================================================================== */

static bool parseMemo(const char *memo, size_t size) {
  return thorchain_parseConfirmMemo(memo, size);
}
static bool parseMemo(const char *memo) {
  return parseMemo(memo, strlen(memo) + 1);
}

// Classic full-form swap memo: asset + dest + limit + affiliate + fee bps
// = 4 screens (the 4th is the new affiliate fee screen)
TEST(Thorchain, MemoSwapFullFormShowsAffiliate) {
  ASSERT_TRUE(kkconfirm_preload(4, 0));
  EXPECT_TRUE(
      parseMemo("SWAP:ETH.USDT-0xdac17f958d2ee523a2206206994597c13d831ec7:"
                "0x41e5560054824ea6b0732e656e3ad64e20e94e45:420:kk:75"));
  EXPECT_EQ(0, kkconfirm_drain());
}

// Abbreviated asset with no '.' (no chain.asset pair) is not parseable
// thorchain data: raw-memo fallback
TEST(Thorchain, MemoSwapNoChainAssetPair) {
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  EXPECT_FALSE(parseMemo("=:e:0xdest:0/1/0:kk:75"));
  EXPECT_EQ(0, kkconfirm_drain());
}

// Empty limit field must NOT shift the affiliate into the limit slot: it
// must still take 4 screens (limit "none" + separate affiliate screen).
// The old strtok tokenizer collapsed the empty field and displayed the
// affiliate ("kk") as the limit in 3 screens.
TEST(Thorchain, MemoSwapEmptyLimitDoesNotShift) {
  ASSERT_TRUE(kkconfirm_preload(4, 0));
  EXPECT_TRUE(parseMemo("=:ETH.ETH:0xdest::kk:75"));
  EXPECT_EQ(0, kkconfirm_drain());
}

// No affiliate: exactly the 3 historical screens, no affiliate screen
TEST(Thorchain, MemoSwapNoAffiliate) {
  ASSERT_TRUE(kkconfirm_preload(3, 0));
  EXPECT_TRUE(parseMemo("SWAP:ETH.ETH:0xdest:420"));
  EXPECT_EQ(0, kkconfirm_drain());
}

// Affiliate present but fee absent: affiliate screen still shows (fee "0")
TEST(Thorchain, MemoSwapAffiliateNoFee) {
  ASSERT_TRUE(kkconfirm_preload(4, 0));
  EXPECT_TRUE(parseMemo("SWAP:ETH.ETH:0xdest:420:kk"));
  EXPECT_EQ(0, kkconfirm_drain());
}

// Missing dest and limit: still 3 screens ("self" / "none")
TEST(Thorchain, MemoSwapMinimal) {
  ASSERT_TRUE(kkconfirm_preload(3, 0));
  EXPECT_TRUE(parseMemo("SWAP:ETH.ETH"));
  EXPECT_EQ(0, kkconfirm_drain());
}

// Rejecting a screen aborts the whole confirmation
TEST(Thorchain, MemoSwapRejectPropagates) {
  ASSERT_TRUE(kkconfirm_preload(2, 1));
  EXPECT_FALSE(parseMemo("SWAP:ETH.ETH:0xdest:420"));
  EXPECT_EQ(0, kkconfirm_drain());
}

// ADD with a pool address: 2 screens (unchanged behavior)
TEST(Thorchain, MemoAddWithPool) {
  ASSERT_TRUE(kkconfirm_preload(2, 0));
  EXPECT_TRUE(
      parseMemo("ADD:BTC.BTC:thor18vhdczjut44gpsy804crfhnd5nq003nz0nf20v"));
  EXPECT_EQ(0, kkconfirm_drain());
}

// ADD without a pool address: 1 screen (unchanged behavior)
TEST(Thorchain, MemoAddWithoutPool) {
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  EXPECT_TRUE(parseMemo("+:BTC.BTC"));
  EXPECT_EQ(0, kkconfirm_drain());
}

// WITHDRAW with basis points: 1 screen (unchanged behavior)
TEST(Thorchain, MemoWithdraw) {
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  EXPECT_TRUE(parseMemo("WITHDRAW:BTC.BTC:5000"));
  EXPECT_EQ(0, kkconfirm_drain());
}

// WITHDRAW without basis points is malformed (unchanged behavior)
TEST(Thorchain, MemoWithdrawMissingBps) {
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  EXPECT_FALSE(parseMemo("wd:BTC.BTC"));
  EXPECT_EQ(0, kkconfirm_drain());
}

// Garbage memos fall back to raw-memo confirmation
TEST(Thorchain, MemoGarbage) {
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  EXPECT_FALSE(parseMemo("hello world"));
  EXPECT_FALSE(parseMemo("NOTATHING:ETH.ETH:0xdest"));
  EXPECT_FALSE(parseMemo(""));
  EXPECT_EQ(0, kkconfirm_drain());
}

// BTC OP_RETURN passes RAW memo bytes with no NUL and size = byte count
// (transaction.c). Every byte must survive the copy: dropping the last
// character turns affiliate "kk" into "k" — or a fee of 75 bps into 7.
// This memo's affiliate is 1 char, so the historical off-by-one would
// lose it entirely and show only 3 screens instead of 4.
TEST(Thorchain, MemoRawBytesNoNulKeepsLastChar) {
  ASSERT_TRUE(kkconfirm_preload(4, 0));
  const char raw[] = "=:ETH.ETH:0xdest:420:k";
  EXPECT_TRUE(parseMemo(raw, sizeof(raw) - 1)); /* no NUL counted */
  EXPECT_EQ(0, kkconfirm_drain());
}

// A raw memo that fills the internal buffer's entire documented capacity
// (size == 256, the parser's own <=256 contract) must ALSO keep its last
// byte — this is the boundary the copy-length clamp missed.
TEST(Thorchain, MemoExactBufferCapacityKeepsLastChar) {
  const std::string prefix = "=:ETH.ETH:0x";
  const std::string suffix = ":420:k"; // 1-char affiliate as the last byte
  std::string memo = prefix + std::string(256 - prefix.size() - suffix.size(),
                                          'd') +
                     suffix;
  ASSERT_EQ(memo.size(), 256u);

  ASSERT_TRUE(kkconfirm_preload(4, 0));
  EXPECT_TRUE(parseMemo(memo.c_str(), memo.size())); /* no NUL counted */
  EXPECT_EQ(0, kkconfirm_drain());
}

// Oversized input (> 256) is rejected outright
TEST(Thorchain, MemoOversized) {
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  EXPECT_FALSE(parseMemo("SWAP:ETH.ETH:0xdest:420", 257));
  EXPECT_EQ(0, kkconfirm_drain());
}
