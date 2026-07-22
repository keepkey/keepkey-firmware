extern "C" {
#include "keepkey/board/messages.h"
#include "keepkey/board/usb.h"
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/app_confirm.h"
#include "keepkey/firmware/ethereum_contracts/thortx.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/thorchain.h"
#include "keepkey/firmware/tendermint.h"
#include "messages-ethereum.pb.h"
#include "trezor/crypto/secp256k1.h"

// From keepkey_board.h, which we can't include here: its shutdown(void)
// declaration clashes with sys/socket.h's shutdown(int, int).
void kk_board_init(void);
}

#include "gtest/gtest.h"
#include <cstring>
#include <string>
#include <vector>

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

static bool kkconfirm_sendTiny(uint16_t msgId, const uint8_t* payload,
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
  return sendto(fd, frame, sizeof(frame), 0, (struct sockaddr*)&addr,
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
    const uint8_t* decision = (i < nYes) ? yes : no;
    if (!kkconfirm_sendTiny(MessageType_MessageType_DebugLinkDecision, decision,
                            2))
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

static const char* kToAddr = "thor18vhdczjut44gpsy804crfhnd5nq003nz0nf20v";

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

static bool parseMemo(const char* memo, size_t size) {
  return thorchain_parseConfirmMemo(memo, size);
}
static bool parseMemo(const char* memo) {
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
  const std::string suffix = ":420:k";  // 1-char affiliate as the last byte
  std::string memo =
      prefix + std::string(256 - prefix.size() - suffix.size(), 'd') + suffix;
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

// Symmetric withdraw: pool + basis points on a single screen.
TEST(Thorchain, MemoWithdrawSymmetric) {
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  EXPECT_TRUE(parseMemo("WITHDRAW:BTC.BTC:10000"));
  EXPECT_EQ(0, kkconfirm_drain());
}

// Asymmetric withdraw: the 4th field selects a SINGLE-SIDED payout asset —
// it directs money, so it gets its own screen instead of signing unseen with
// screens identical to the symmetric form.
TEST(Thorchain, MemoWithdrawAsymmetricShowsPayoutAsset) {
  ASSERT_TRUE(kkconfirm_preload(2, 0));
  EXPECT_TRUE(parseMemo("-:BTC.BTC:10000:THOR.RUNE"));
  EXPECT_EQ(0, kkconfirm_drain());
}

// Rejecting the payout-asset screen aborts the withdrawal.
TEST(Thorchain, MemoWithdrawAsymmetricRejectPropagates) {
  ASSERT_TRUE(kkconfirm_preload(1, 1));  // approve summary, reject asset
  EXPECT_FALSE(parseMemo("wd:BTC.BTC:5000:BTC.BTC"));
  EXPECT_EQ(0, kkconfirm_drain());
}

// More fields than any withdraw grammar defines cannot be labeled and must
// not be hidden — mirrors the SWAP (>9) and ADD (>5) caps.
TEST(Thorchain, MemoWithdrawTooManyFieldsRejected) {
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  EXPECT_FALSE(parseMemo("WITHDRAW:BTC.BTC:10000:THOR.RUNE:extra"));
  EXPECT_EQ(0, kkconfirm_drain());
}

// DEX-aggregator swap: aggregator addr, final token and min-out are all
// router-executed and must be shown — asset/chain + dest + limit + affiliate +
// aggregator + final + min = 7 screens (none hidden).
TEST(Thorchain, MemoSwapAggregatorShowsAllFields) {
  ASSERT_TRUE(kkconfirm_preload(7, 0));
  EXPECT_TRUE(parseMemo(
      "SWAP:ETH.ETH:0xdest:420:kk:75:0xaggregator:0xfinaltoken:1000"));
  EXPECT_EQ(0, kkconfirm_drain());
}

// A '|' outbound-memo suffix (MinAmountOut|OUTBOUND_MEMO) is forwarded to the
// outbound contract and can contain ':' our split would scatter. It must be
// disclosed in full: swap header + the fully-paged raw memo = 2 screens here
// (memo < one page). Nothing falls back to blind-signing.
TEST(Thorchain, MemoSwapPipeOutboundIsFullyPaged) {
  ASSERT_TRUE(kkconfirm_preload(2, 0));
  const char memo[] = "=:ETH.ETH:0xdest|OUT:0xfinal:1";  // ':' after the pipe
  EXPECT_TRUE(parseMemo(memo, strlen(memo)));  // no NUL in the paged bytes
  EXPECT_EQ(0, kkconfirm_drain());
}

// More fields than any swap grammar defines (>9) is structure we cannot label;
// refuse it rather than sign an undisplayed tail. Rejected before any screen.
TEST(Thorchain, MemoSwapTooManyFieldsRejected) {
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  EXPECT_FALSE(parseMemo("SWAP:ETH.ETH:a:b:c:d:e:f:g:h"));
  EXPECT_EQ(0, kkconfirm_drain());
}

// ADD:POOL:PAIREDADDR:AFFILIATE:FEE — affiliate + fee must not be hidden:
// add asset + pool + affiliate-fee = 3 screens.
TEST(Thorchain, MemoAddShowsAffiliateAndFee) {
  ASSERT_TRUE(kkconfirm_preload(3, 0));
  EXPECT_TRUE(
      parseMemo("ADD:BTC.BTC:thor18vhdczjut44gpsy804crfhnd5nq003nz0nf20v"
                ":affil:50"));
  EXPECT_EQ(0, kkconfirm_drain());
}

// ADD with more than its 5 defined fields is refused (no hidden tail).
TEST(Thorchain, MemoAddTooManyFieldsRejected) {
  ASSERT_TRUE(kkconfirm_preload(0, 0));
  EXPECT_FALSE(parseMemo("ADD:BTC.BTC:pool:affil:50:extra"));
  EXPECT_EQ(0, kkconfirm_drain());
}

// The full-memo pager is the authoritative disclosure the native THOR/MAYA
// handlers page after their structured summary. A short ASCII memo is one page.
TEST(Thorchain, FullMemoShortAsciiIsOnePage) {
  const char memo[] = "=:ETH.ETH:0xdest:420:kk:75";
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  EXPECT_TRUE(thorchain_confirm_full_memo("Memo", memo, strlen(memo)));
  EXPECT_EQ(0, kkconfirm_drain());
}

// Page breaks use measured rendered rows, including word-wrap behavior.
TEST(Thorchain, FullMemoLongAsciiPagesAll) {
  const char memo[] =
      "%%%%%%%%%%%%%%%% %%%%%%%%%%%%%%%% %%%%%%%%%%%%%%%% %%%%%%%%%%%%%%%%";
  ASSERT_TRUE(kkconfirm_preload(2, 0));
  EXPECT_TRUE(thorchain_confirm_full_memo("Memo", memo, strlen(memo)));
  EXPECT_EQ(0, kkconfirm_drain());
}

// Rejecting any page aborts the whole disclosure (so the handler aborts
// signing).
TEST(Thorchain, FullMemoRejectPropagates) {
  const char memo[] =
      "%%%%%%%%%%%%%%%% %%%%%%%%%%%%%%%% %%%%%%%%%%%%%%%% %%%%%%%%%%%%%%%%";
  ASSERT_TRUE(kkconfirm_preload(1, 1));  // approve page 1, reject page 2
  EXPECT_FALSE(thorchain_confirm_full_memo("Memo", memo, strlen(memo)));
  EXPECT_EQ(0, kkconfirm_drain());
}

// Non-printable memo bytes are disclosed in complete renderer-measured hex
// pages, never hidden behind a byte-count summary.
TEST(Thorchain, FullMemoBinaryPagesAsHex) {
  char memo[100];
  memset(memo, 0x01, sizeof(memo));
  ASSERT_TRUE(kkconfirm_preload(2, 0));
  EXPECT_TRUE(thorchain_confirm_full_memo("Memo", memo, sizeof(memo)));
  EXPECT_EQ(0, kkconfirm_drain());
}

// An empty memo must show a single "(empty)" screen — not fall through to the
// hex branch, which would pass an uninitialized buffer to %s.
TEST(Thorchain, FullMemoEmptyShowsEmpty) {
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  EXPECT_TRUE(thorchain_confirm_full_memo("Memo", "", 0));
  EXPECT_EQ(0, kkconfirm_drain());
}

// Renderer-aware paging must split the exact 69-byte word-wrap exploit from
// the second-pass audit. A byte-count pager treated this as one screen even
// though the OLED renderer placed the final signed word on a fourth row.
TEST(Confirmation, ExactLengthPagerMeasuresRenderedRows) {
  const char payload[] =
      "%%%%%%%%%%%%%%%% %%%%%%%%%%%%%%%% %%%%%%%%%%%%%%%% %%%%%%%%%%%%%%%%";
  ASSERT_TRUE(kkconfirm_preload(2, 0));
  EXPECT_TRUE(confirm_bytes(ButtonRequestType_ButtonRequest_SignMessage,
                            "Signed Message", (const uint8_t*)payload,
                            strlen(payload)));
  EXPECT_EQ(0, kkconfirm_drain());
}

TEST(Confirmation, ExactLengthPagerRejectPropagates) {
  const char payload[] =
      "%%%%%%%%%%%%%%%% %%%%%%%%%%%%%%%% %%%%%%%%%%%%%%%% %%%%%%%%%%%%%%%%";
  ASSERT_TRUE(kkconfirm_preload(1, 1));
  EXPECT_FALSE(confirm_bytes(ButtonRequestType_ButtonRequest_SignMessage,
                             "Signed Message", (const uint8_t*)payload,
                             strlen(payload)));
  EXPECT_EQ(0, kkconfirm_drain());
}

/* =====================================================================
 *  thor_isThorchainTx — chain-scoped router pin.
 *
 *  A THORChain deposit uses a DIFFERENT router address on every EVM chain,
 *  so the pin must match on (chain_id, address) together. Before this was
 *  chain-scoped, only Ethereum-mainnet deposits ever matched and an
 *  Avalanche deposit fell into the blind-sign gate (the AVAX->ETH bug).
 * ===================================================================== */

// Lowercase-hex 40-char router -> 20 raw bytes.
static void hex20(const char* hex, uint8_t out[20]) {
  for (int i = 0; i < 20; i++) {
    auto nib = [](char c) -> int {
      return c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10;
    };
    out[i] = (uint8_t)((nib(hex[i * 2]) << 4) | nib(hex[i * 2 + 1]));
  }
}

static void make_deposit_msg(EthereumSignTx* msg, const uint8_t to[20],
                             const uint8_t* data, size_t data_len,
                             uint32_t chain_id, bool has_chain) {
  memset(msg, 0, sizeof(*msg));
  msg->has_to = true;
  msg->to.size = 20;
  memcpy(msg->to.bytes, to, 20);
  msg->has_data_initial_chunk = true;
  msg->data_initial_chunk.size = (pb_size_t)data_len;
  memcpy(msg->data_initial_chunk.bytes, data, data_len);
  msg->has_chain_id = has_chain;
  msg->chain_id = chain_id;
}

static const char* THOR_ETH_ROUTER = "d37bbe5744d730a1d98d8dc97c42f0ca46ad7146";
static const char* THOR_AVAX_ROUTER =
    "00dc6100103bc402d490aee3f9a5560cbd91f1d4";
static const uint8_t DEPOSIT_WITH_EXPIRY[4] = {0x44, 0xbc, 0x93, 0x7b};

TEST(Thorchain, IsThorchainTxEthRouterOnEthereum) {
  uint8_t to[20];
  hex20(THOR_ETH_ROUTER, to);
  EthereumSignTx msg;
  make_deposit_msg(&msg, to, DEPOSIT_WITH_EXPIRY, 4, 1, true);
  EXPECT_TRUE(thor_isThorchainTx(&msg));
}

TEST(Thorchain, IsThorchainTxAvaxRouterOnAvalanche) {
  uint8_t to[20];
  hex20(THOR_AVAX_ROUTER, to);
  EthereumSignTx msg;
  make_deposit_msg(&msg, to, DEPOSIT_WITH_EXPIRY, 4, 43114, true);
  EXPECT_TRUE(thor_isThorchainTx(&msg));  // the AVAX->ETH bug fix
}

// The AVAX router on the Ethereum chain (or vice versa) must NOT match — the
// pin is (chain, address) together, so a router borrowed onto the wrong chain
// can't inherit the trusted deposit UX.
TEST(Thorchain, IsThorchainTxRejectsRouterOnWrongChain) {
  uint8_t avax[20], eth[20];
  hex20(THOR_AVAX_ROUTER, avax);
  hex20(THOR_ETH_ROUTER, eth);
  EthereumSignTx msg;
  make_deposit_msg(&msg, avax, DEPOSIT_WITH_EXPIRY, 4, 1, true);
  EXPECT_FALSE(thor_isThorchainTx(&msg));  // AVAX router, ETH chain
  make_deposit_msg(&msg, eth, DEPOSIT_WITH_EXPIRY, 4, 43114, true);
  EXPECT_FALSE(thor_isThorchainTx(&msg));  // ETH router, AVAX chain
}

// A chain with no pinned THORChain router never clear-signs (falls to blind
// sign), even with a real deposit selector to some address.
TEST(Thorchain, IsThorchainTxRejectsUnpinnedChain) {
  uint8_t to[20];
  hex20(THOR_ETH_ROUTER, to);
  EthereumSignTx msg;
  make_deposit_msg(&msg, to, DEPOSIT_WITH_EXPIRY, 4, 137 /*polygon*/, true);
  EXPECT_FALSE(thor_isThorchainTx(&msg));
}

// A tx with NO chain_id at all gets no router: ethereum.c defaults an absent
// chain_id to mainnet for hashing, but an identity pin must never be
// inherited from a default the host merely omitted.
TEST(Thorchain, IsThorchainTxRejectsMissingChainId) {
  uint8_t to[20];
  hex20(THOR_ETH_ROUTER, to);
  EthereumSignTx msg;
  make_deposit_msg(&msg, to, DEPOSIT_WITH_EXPIRY, 4, 0, false);
  EXPECT_FALSE(thor_isThorchainTx(&msg));
}

// A random contract carrying the deposit selector must not match — this is the
// drain-vector guard the pin exists for.
TEST(Thorchain, IsThorchainTxRejectsUnpinnedAddress) {
  uint8_t to[20];
  hex20("00000000000000000000000000000000deadbeef", to);
  EthereumSignTx msg;
  make_deposit_msg(&msg, to, DEPOSIT_WITH_EXPIRY, 4, 43114, true);
  EXPECT_FALSE(thor_isThorchainTx(&msg));
}

/* =====================================================================
 *  thor_confirmThorTx on the Avalanche router — the full confirm path
 *  (router label, vault, native amount, structured memo, raw memo pages)
 *  runs for a non-mainnet deposit, and the exact-end memo bounds hold.
 * ===================================================================== */

// Assemble a canonical depositWithExpiry(address,address,uint256,string,
// uint256) calldata. declared_len overrides the ABI memo-length word so the
// adversarial case (length says more than is present) can be exercised.
static std::vector<uint8_t> build_thor_deposit(const uint8_t vault[20],
                                               const std::string& memo,
                                               uint32_t declared_len) {
  std::vector<uint8_t> d(DEPOSIT_WITH_EXPIRY, DEPOSIT_WITH_EXPIRY + 4);
  auto push_word = [&](const uint8_t* w) { d.insert(d.end(), w, w + 32); };
  auto push_u = [&](uint64_t v) {
    uint8_t w[32] = {0};
    for (int i = 0; i < 8; i++) w[31 - i] = (uint8_t)((v >> (8 * i)) & 0xff);
    push_word(w);
  };
  uint8_t vw[32] = {0};
  memcpy(vw + 12, vault, 20);
  push_word(vw);          // word0: vault
  push_u(0);              // word1: asset = native (address zero)
  push_u(1000000000ULL);  // word2: amount (router-ignored hint for native)
  push_u(0xa0);           // word3: memo offset (canonical for expiry variant)
  push_u(1893456000ULL);  // word4: expiry
  push_u(declared_len);   // word5: memo length
  d.insert(d.end(), memo.begin(), memo.end());
  while (d.size() % 32 != 4) d.push_back(0);  // pad memo to a 32-byte boundary
  return d;
}

// A 67-byte memo (longer than the once-hardcoded 64) must display in full
// through the memo screens, not silently truncate its trailing fields — on the
// AVALANCHE router, proving the whole confirm path is chain-scoped.
TEST(Thorchain, ConfirmThorTxAvaxLongMemoDecodesFully) {
  uint8_t vault[20];
  hex20("15a18266c5331ac3a7f6bc5cdf25bcc55561b4fa", vault);
  const std::string memo =
      "=:ETH.ETH:0x141D9959cAe3853b035000490C03991eB70Fc4aC:323935:keep:30";
  ASSERT_EQ(memo.size(), 67u);
  auto data = build_thor_deposit(vault, memo, (uint32_t)memo.size());

  uint8_t avax[20];
  hex20(THOR_AVAX_ROUTER, avax);
  EthereumSignTx msg;
  make_deposit_msg(&msg, avax, data.data(), data.size(), 43114, true);

  ASSERT_TRUE(kkconfirm_preload(12, 0));  // generous; extras drain below
  EXPECT_TRUE(thor_confirmThorTx((uint32_t)data.size(), &msg));
  kkconfirm_drain();
}

// A memo-length word claiming more bytes than are present must be REJECTED —
// otherwise the router would execute a longer memo than the device displayed
// (display-vs-execute divergence). Fail closed -> blind-sign path.
TEST(Thorchain, ConfirmThorTxRejectsOverlongDeclaredMemo) {
  uint8_t vault[20];
  hex20("15a18266c5331ac3a7f6bc5cdf25bcc55561b4fa", vault);
  const std::string memo = "=:ETH.ETH:0xdest:0:keep:30";
  // Declare 200 bytes while only ~26 (padded to 32) are present.
  auto data = build_thor_deposit(vault, memo, 200);

  uint8_t avax[20];
  hex20(THOR_AVAX_ROUTER, avax);
  EthereumSignTx msg;
  make_deposit_msg(&msg, avax, data.data(), data.size(), 43114, true);

  ASSERT_TRUE(kkconfirm_preload(12, 0));
  EXPECT_FALSE(thor_confirmThorTx((uint32_t)data.size(), &msg));
  kkconfirm_drain();
}
