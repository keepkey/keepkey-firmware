extern "C" {
#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/ethereum_contracts/zxappliquid.h"
#include "keepkey/firmware/ethereum_contracts/zxliquidtx.h"
#include "keepkey/firmware/ethereum_tokens.h"
#include "keepkey/firmware/eip712.h"
#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/ethereum_contracts.h"
#include "keepkey/firmware/ethereum_contracts/zxtransERC20.h"
#include "keepkey/firmware/tron.h"
#include "trezor/crypto/address.h"
#include "messages-ethereum.pb.h"
}

#include "gtest/gtest.h"

#include <cstring>
#include <string>

bool kkconfirm_preload(int nYes, int nNo);
int kkconfirm_drain(void);

static uint8_t bin_from_ascii(char c) {
  if ('a' <= c && c <= 'f') return c - 'a' + 0xa;

  if ('A' <= c && c <= 'F') return c - 'A' + 0xA;

  if ('0' <= c && c <= '9') return c - '0' + 0x0;

  __builtin_unreachable();
}

static void test_checksum(const std::string& addr) {
  uint8_t addr_bin[20];
  for (size_t i = 0; i < addr.size(); i += 2) {
    addr_bin[i / 2] = bin_from_ascii(addr[i + 1]) | bin_from_ascii(addr[i])
                                                        << 4;
  }

  char formatted[41];
  ethereum_address_checksum(addr_bin, formatted, false, 0);

  ASSERT_EQ(formatted[40], '\0') << "Must be null terminated";

  ASSERT_EQ(addr, std::string(formatted)) << "Checksum mismatch";
}

TEST(Ethereum, AddressChecksum) {
  // Testcases from: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md
  test_checksum("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
  test_checksum("fB6916095ca1df60bB79Ce92cE3Ea74c37c5d359");
  test_checksum("dbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB");
  test_checksum("D1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb");
}

TEST(Ethereum, ChainIdValidationCoversPresenceAndBounds) {
  EthereumSignTx msg = EthereumSignTx{};
  EXPECT_FALSE(ethereum_chainIdIsValid(&msg));

  msg.has_chain_id = true;
  msg.chain_id = 0;
  EXPECT_FALSE(ethereum_chainIdIsValid(&msg));

  msg.chain_id = 1;
  EXPECT_TRUE(ethereum_chainIdIsValid(&msg));

  /* The boundary is where v + 2 * chain_id + 35 stops fitting in a uint32_t
     at the worst-case v == 1. Pin both sides of it, in 64-bit arithmetic so
     the check itself cannot wrap. */
  msg.chain_id = 2147483629u;
  EXPECT_TRUE(ethereum_chainIdIsValid(&msg));
  EXPECT_EQ(2ull * 2147483629ull + 35ull + 1ull, 4294967294ull);

  /* One higher wraps to 0: a recovery id the device never produced. */
  EXPECT_EQ(2ull * 2147483630ull + 35ull + 1ull, 4294967296ull);
  EXPECT_EQ(static_cast<uint32_t>(2ull * 2147483630ull + 35ull + 1ull), 0u);

  msg.chain_id = 2147483630u;
  EXPECT_FALSE(ethereum_chainIdIsValid(&msg));

  msg.chain_id = 2147483631u;
  EXPECT_FALSE(ethereum_chainIdIsValid(&msg));
  EXPECT_FALSE(ethereum_chainIdIsValid(nullptr));
}

TEST(Ethereum, AmountFormattingNeverReturnsBlank) {
  uint8_t max_bytes[32];
  std::memset(max_bytes, 0xff, sizeof(max_bytes));
  bignum256 amount;
  bn_read_be(max_bytes, &amount);

  const TokenType token = {nullptr, " TEST", 1, 18};
  char rendered[32];
  EXPECT_FALSE(
      ethereumFormatAmount(&amount, &token, 1, rendered, sizeof(rendered)));
  EXPECT_STREQ("AMOUNT TOO LARGE TO DISPLAY", rendered);
}

TEST(Ethereum, NativeAmountsUseTheSigningChainsTicker) {
  bignum256 amount;
  bn_read_uint64(1500000000000000000ULL, &amount);
  char rendered[32];

  ASSERT_TRUE(ethereumFormatAmount(&amount, nullptr, 43114, rendered,
                                   sizeof(rendered)));
  EXPECT_STREQ("1.5 AVAX", rendered);

  ASSERT_TRUE(
      ethereumFormatAmount(&amount, nullptr, 10, rendered, sizeof(rendered)));
  EXPECT_STREQ("1.5 ETH", rendered);

  ASSERT_TRUE(ethereumFormatAmount(&amount, nullptr, 8453, rendered,
                                   sizeof(rendered)));
  EXPECT_STREQ("1.5 ETH", rendered);

  ASSERT_TRUE(ethereumFormatAmount(&amount, nullptr, 42161, rendered,
                                   sizeof(rendered)));
  EXPECT_STREQ("1.5 ETH", rendered);

  /* An unmapped chain must never render a bare, unit-less number. Wei is the
     base unit of every EVM chain, so the amount stays exact while the device
     stops claiming to know an asset name it does not have. */
  ASSERT_TRUE(ethereumFormatAmount(&amount, nullptr, 59144, rendered,
                                   sizeof(rendered)));
  EXPECT_STREQ("1500000000000000000 Wei", rendered);

  ASSERT_TRUE(
      ethereumFormatAmount(&amount, nullptr, 257, rendered, sizeof(rendered)));
  EXPECT_STREQ("1500000000000000000 Wei", rendered);
}

TEST(Ethereum, TransferAmountUsesTheRequestsSigningChain) {
  EthereumSignTx msg = EthereumSignTx{};
  msg.has_chain_id = true;
  msg.has_value = true;
  msg.value.size = 8;
  const uint64_t amount = 1500000000000000000ULL;
  for (size_t i = 0; i < msg.value.size; ++i) {
    msg.value.bytes[msg.value.size - 1 - i] =
        static_cast<uint8_t>(amount >> (8 * i));
  }

  char rendered[32];
  msg.chain_id = 56;
  ASSERT_TRUE(ethereumFormatTransferAmount(&msg, rendered, sizeof(rendered)));
  EXPECT_STREQ("1.5 BNB", rendered);

  msg.chain_id = 137;
  ASSERT_TRUE(ethereumFormatTransferAmount(&msg, rendered, sizeof(rendered)));
  EXPECT_STREQ("1.5 MATIC", rendered);
}

TEST(Ethereum, TypedHashSigningRequiresAdvancedMode) {
  EXPECT_FALSE(ethereum_typed_hash_policy_allows(false));
  EXPECT_TRUE(ethereum_typed_hash_policy_allows(true));
}

TEST(Ethereum, DomainOnlyPrimaryTypeRequiresExactMatch) {
  EXPECT_TRUE(ethereum_eip712_is_domain_primary_type("EIP712Domain"));
  EXPECT_FALSE(ethereum_eip712_is_domain_primary_type("EIP"));
  EXPECT_FALSE(ethereum_eip712_is_domain_primary_type("EIP712Domain[]"));
  EXPECT_FALSE(ethereum_eip712_is_domain_primary_type(""));
  EXPECT_FALSE(ethereum_eip712_is_domain_primary_type(nullptr));
}

static const uint8_t DAI_MAINNET_ADDRESS[20] = {
    0x6b, 0x17, 0x54, 0x74, 0xe8, 0x90, 0x94, 0xc4, 0x4d, 0xa9,
    0x8b, 0x95, 0x4e, 0xed, 0xea, 0xc4, 0x95, 0x27, 0x1d, 0x0f};
static const uint8_t USDC_MAINNET_ADDRESS[20] = {
    0xa0, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1,
    0x9d, 0x4a, 0x2e, 0x9e, 0xb0, 0xce, 0x36, 0x06, 0xeb, 0x48};

static EthereumSignTx liquidity_tx(
    bool known_token, bool add = true,
    const uint8_t* token_address = DAI_MAINNET_ADDRESS) {
  EthereumSignTx msg;
  memset(&msg, 0, sizeof(msg));
  msg.has_chain_id = true;
  msg.chain_id = 1;
  msg.has_to = true;
  msg.to.size = 20;
  memcpy(msg.to.bytes, UNISWAP_ROUTER_ADDRESS, 20);
  msg.has_data_initial_chunk = true;
  msg.data_initial_chunk.size = 4 + 6 * 32;
  memcpy(msg.data_initial_chunk.bytes,
         add ? "\xf3\x05\xd7\x19" : "\x02\x75\x1c\xec", 4);

  const TokenType* token = tokenByChainAddress(1, token_address);
  EXPECT_NE(UnknownToken, token);
  if (token == UnknownToken) return msg;
  uint8_t unknown[20];
  memset(unknown, 0xa5, sizeof(unknown));
  memcpy(
      msg.data_initial_chunk.bytes + 4 + 32 - 20,
      known_token ? reinterpret_cast<const uint8_t*>(token->address) : unknown,
      20);

  // Token desired/minimum and native minimum.
  msg.data_initial_chunk.bytes[4 + 2 * 32 - 1] = 1;
  msg.data_initial_chunk.bytes[4 + 3 * 32 - 1] = 1;
  msg.data_initial_chunk.bytes[4 + 4 * 32 - 1] = 1;
  // Recipient and deadline.
  memset(msg.data_initial_chunk.bytes + 4 + 5 * 32 - 20, 0x11, 20);
  msg.data_initial_chunk.bytes[4 + 6 * 32 - 1] = 1;
  msg.has_value = true;
  if (add) {
    msg.value.size = 1;
    msg.value.bytes[0] = 1;
  }
  return msg;
}

static void set_word_u64(EthereumSignTx& msg, size_t word, uint64_t value) {
  uint8_t* out = msg.data_initial_chunk.bytes + 4 + word * 32;
  memset(out, 0, 32);
  for (size_t i = 0; i < 8; i++) {
    out[31 - i] = static_cast<uint8_t>(value);
    value >>= 8;
  }
}

static EthereumSignTx approve_liquidity_tx() {
  EthereumSignTx msg;
  memset(&msg, 0, sizeof(msg));
  msg.has_chain_id = true;
  msg.chain_id = 1;
  msg.has_to = true;
  msg.to.size = 20;
  // Canonical mainnet DAI/WETH Uniswap V2 pair.
  const uint8_t pair[20] = {0xa4, 0x78, 0xc2, 0x97, 0x5a, 0xb1, 0xea,
                            0x89, 0xe8, 0x19, 0x68, 0x11, 0xf5, 0x1a,
                            0x7b, 0x7a, 0xde, 0x33, 0xeb, 0x11};
  memcpy(msg.to.bytes, pair, sizeof(pair));
  msg.has_data_initial_chunk = true;
  msg.data_initial_chunk.size = 4 + 2 * 32;
  memcpy(msg.data_initial_chunk.bytes, "\x09\x5e\xa7\xb3", 4);
  memcpy(msg.data_initial_chunk.bytes + 4 + 12, UNISWAP_ROUTER_ADDRESS, 20);
  msg.data_initial_chunk.bytes[4 + 2 * 32 - 1] = 1;
  msg.has_value = true;
  return msg;
}

TEST(Ethereum, LiquiditySelectorChecksDeclaredCalldataLength) {
  EthereumSignTx msg;
  memset(&msg, 0, sizeof(msg));
  msg.has_to = true;
  msg.to.size = 20;
  memcpy(msg.to.bytes, UNISWAP_ROUTER_ADDRESS, 20);
  msg.has_data_initial_chunk = true;
  msg.data_initial_chunk.size = 3;
  memcpy(msg.data_initial_chunk.bytes, "\xf3\x05\xd7", 3);
  EXPECT_FALSE(zx_isZxLiquidTx(&msg));

  msg.data_initial_chunk.size = 4;
  memcpy(msg.data_initial_chunk.bytes, "\x09\x5e\xa7\xb3", 4);
  EXPECT_FALSE(zx_isZxApproveLiquid(&msg));

  msg.data_initial_chunk.size = 4 + 2 * 32 + 1;
  memcpy(msg.data_initial_chunk.bytes, "\x09\x5e\xa7\xb3", 4);
  memcpy(msg.data_initial_chunk.bytes + 4 + 32 - 20, UNISWAP_ROUTER_ADDRESS,
         20);
  EXPECT_FALSE(zx_isZxApproveLiquid(&msg));

  msg.data_initial_chunk.size = 4 + 6 * 32 + 1;
  memcpy(msg.data_initial_chunk.bytes, "\xf3\x05\xd7\x19", 4);
  EXPECT_FALSE(zx_isZxLiquidTx(&msg));
}

TEST(Ethereum, LiquidityCancellationFailsClosed) {
  EthereumSignTx msg = liquidity_tx(true);
  ASSERT_TRUE(kkconfirm_preload(0, 1));
  EXPECT_FALSE(zx_confirmZxLiquidTx(msg.data_initial_chunk.size, &msg));
  EXPECT_EQ(0, kkconfirm_drain());
}

TEST(Ethereum, LiquidityRejectsUnknownTokenBeforeConfirmation) {
  EthereumSignTx msg = liquidity_tx(false);
  EXPECT_FALSE(zx_confirmZxLiquidTx(msg.data_initial_chunk.size, &msg));
}

TEST(Ethereum, LiquidityClearSigningIsMainnetOnly) {
  EthereumSignTx msg = liquidity_tx(true);
  EXPECT_TRUE(zx_isZxLiquidTx(&msg));

  msg.chain_id = 137;
  EXPECT_FALSE(zx_isZxLiquidTx(&msg));
  msg.chain_id = 1;
  msg.has_chain_id = false;
  EXPECT_FALSE(zx_isZxLiquidTx(&msg));
}

TEST(Ethereum, LiquidityRejectsTruncatedDeadlineAndNoncanonicalAddresses) {
  EthereumSignTx msg = liquidity_tx(true);
  msg.data_initial_chunk.bytes[4 + 5 * 32] = 1;
  EXPECT_FALSE(zx_isZxLiquidTx(&msg));
  EXPECT_FALSE(zx_confirmZxLiquidTx(msg.data_initial_chunk.size, &msg));

  msg = liquidity_tx(true);
  msg.data_initial_chunk.bytes[4] = 1;
  EXPECT_FALSE(zx_isZxLiquidTx(&msg));

  msg = liquidity_tx(true);
  msg.data_initial_chunk.bytes[4 + 4 * 32] = 1;
  EXPECT_FALSE(zx_isZxLiquidTx(&msg));
}

TEST(Ethereum, RemoveLiquidityRejectsNativeValue) {
  EthereumSignTx msg = liquidity_tx(true, false);
  EXPECT_TRUE(zx_isZxLiquidTx(&msg));
  msg.value.size = 1;
  msg.value.bytes[0] = 1;
  EXPECT_FALSE(zx_isZxLiquidTx(&msg));
}

TEST(Ethereum, RemoveLiquidityFormatsPrimaryAmountAsLpTokens) {
  EthereumSignTx add = liquidity_tx(true, true, USDC_MAINNET_ADDRESS);
  set_word_u64(add, 1, UINT64_C(1000000000000000000));
  char formatted[96];
  ASSERT_TRUE(
      zx_formatZxLiquidityPrimaryAmount(&add, formatted, sizeof(formatted)));
  EXPECT_STREQ("1000000000000 USDC", formatted);

  EthereumSignTx remove = liquidity_tx(true, false, USDC_MAINNET_ADDRESS);
  set_word_u64(remove, 1, UINT64_C(1000000000000000000));
  ASSERT_TRUE(
      zx_formatZxLiquidityPrimaryAmount(&remove, formatted, sizeof(formatted)));
  EXPECT_STREQ("1 LP", formatted);
}

TEST(Ethereum, LiquidityFormatsFullUint256WithoutBlankConfirmation) {
  EthereumSignTx msg = liquidity_tx(true);
  memset(msg.data_initial_chunk.bytes + 4 + 32, 0xff, 32);
  char formatted[96];
  ASSERT_TRUE(
      zx_formatZxLiquidityPrimaryAmount(&msg, formatted, sizeof(formatted)));
  EXPECT_GT(strlen(formatted), 32u);

  ASSERT_TRUE(kkconfirm_preload(0, 1));
  EXPECT_FALSE(zx_confirmZxLiquidTx(msg.data_initial_chunk.size, &msg));
  EXPECT_EQ(0, kkconfirm_drain());
}

TEST(Ethereum, LpApprovalRequiresMainnetDerivedPairAndCanonicalSpender) {
  EthereumSignTx msg = approve_liquidity_tx();
  EXPECT_TRUE(zx_isZxApproveLiquid(&msg));

  msg.to.bytes[0] ^= 1;
  EXPECT_FALSE(zx_isZxApproveLiquid(&msg));

  msg = approve_liquidity_tx();
  msg.chain_id = 137;
  EXPECT_FALSE(zx_isZxApproveLiquid(&msg));

  msg = approve_liquidity_tx();
  msg.data_initial_chunk.bytes[4] = 1;
  EXPECT_FALSE(zx_isZxApproveLiquid(&msg));
}

TEST(Ethereum, Eip712AddressRequiresCanonicalTwentyByteHex) {
  uint8_t encoded[32] = {0};
  ASSERT_EQ(SUCCESS,
            encAddress("0x00112233445566778899aabbccddeeff00112233", encoded));
  for (size_t i = 0; i < 12; i++) EXPECT_EQ(0, encoded[i]);
  EXPECT_EQ(0x00, encoded[12]);
  EXPECT_EQ(0x11, encoded[13]);
  EXPECT_EQ(0x33, encoded[31]);

  EXPECT_NE(SUCCESS, encAddress("0x112233", encoded));
  EXPECT_NE(SUCCESS,
            encAddress("00112233445566778899aabbccddeeff00112233", encoded));
  EXPECT_NE(SUCCESS,
            encAddress("0x00112233445566778899aabbccddeeff0011223g", encoded));
  EXPECT_NE(SUCCESS, encAddress(
                         "0x00112233445566778899aabbccddeeff0011223344",
                         encoded));
}

// Every EIP-712 field screen used to be a review(), which calls
// confirm_helper() and then returns true unconditionally, so a host that
// answered each screen with a protocol Cancel still got a hash back. The
// screens are confirm() now and refusal reaches ethereum.c as USER_CANCELLED.
//
// That code has to stay outside failMsgReturn[]. ethereum.c sizes the table
// LAST_ERROR - 2 and indexes it err - 3, so a cancellation code at or below
// LAST_ERROR would shift every message already in the table and would make
// failMessage() report a refusal as a parse error instead of an
// ActionCancelled. It also must not collide with the two non-error codes.
TEST(Ethereum, Eip712UserCancelledIsOutsideTheFailMessageTable) {
  EXPECT_GT(USER_CANCELLED, LAST_ERROR);
  EXPECT_NE(USER_CANCELLED, SUCCESS);
  EXPECT_NE(USER_CANCELLED, NULL_MSG_HASH);
}

TEST(Ethereum, PrecomputedTypedHashesRequireAdvancedMode) {
  EXPECT_FALSE(ethereum_typed_hash_policy_allows(false));
  EXPECT_TRUE(ethereum_typed_hash_policy_allows(true));
  EXPECT_FALSE(tron_typed_hash_policy_allows(false));
  EXPECT_TRUE(tron_typed_hash_policy_allows(true));
}

TEST(Ethereum, StructuredEip712IsDisabledForPointRelease) {
  EXPECT_FALSE(ethereum_structured_eip712_enabled());
}

// Two real chain-1 table entries, so the decoder's token lookups resolve.
// The table has no chain-1 zero-address entry, so an all-zero word is a
// reliable "unknown token".
static const char kTUSD[] =
    "\x00\x00\x00\x00\x00\x08\x5d\x47\x80\xB7\x31\x19\xb6\x44\xAE\x5e\xcd\x22"
    "\xb3\x76";
static const char kTGBP[] =
    "\x00\x00\x00\x00\x44\x13\x78\x00\x8E\xA6\x7F\x42\x84\xA5\x79\x32\xB1\xc0"
    "\x00\xa5";

// transformERC20(address,address,uint256,uint256,(uint32,bytes)[]) — the two
// address words carry the token in their low 20 bytes.
static void MakeTransformErc20(EthereumSignTx* msg, const char* in_token,
                               const char* out_token) {
  *msg = EthereumSignTx{};
  msg->has_to = true;
  msg->to.size = 20;
  std::memcpy(msg->to.bytes, ZXSWAP_ADDRESS, msg->to.size);
  msg->has_chain_id = true;
  msg->chain_id = 1;
  msg->has_data_initial_chunk = true;
  msg->data_initial_chunk.size = 4 + 4 * 32;
  std::memcpy(msg->data_initial_chunk.bytes, "\x41\x55\x65\xb0", 4);
  if (in_token) std::memcpy(msg->data_initial_chunk.bytes + 4 + 12, in_token, 20);
  if (out_token)
    std::memcpy(msg->data_initial_chunk.bytes + 4 + 32 + 12, out_token, 20);
}

TEST(Ethereum, TransformErc20RequiresCompleteCalldataForClearSigning) {
  EthereumSignTx msg;
  MakeTransformErc20(&msg, kTUSD, kTGBP);

  EXPECT_TRUE(
      ethereum_contractHandled(msg.data_initial_chunk.size, &msg, nullptr));
  EXPECT_FALSE(
      ethereum_contractHandled(msg.data_initial_chunk.size + 1, &msg, nullptr));
}

// The decoder shows four values and hides the transformations[] body. That is
// only defensible because the input amount and minimum output amount bound the
// outcome — and ethereumFormatAmount() renders the literal "Unknown token
// value" whenever tokenByChainAddress() misses, so an unresolved token turns
// the bound into nothing while the calldata still executes.
//
// Gating on the lookup rather than on a chain allowlist keeps this correct
// however the tables change. It matters in practice: the generated table
// carries ~1924 entries for chain 1, three each for BSC and Polygon, and NONE
// for Base, Arbitrum or Avalanche, so on those chains every pair fails here.
TEST(Ethereum, TransformErc20RequiresBothTokensResolvable) {
  EthereumSignTx msg;

  // Both known -> the device can name what it is showing.
  MakeTransformErc20(&msg, kTUSD, kTGBP);
  EXPECT_TRUE(ethereum_contractHandled(msg.data_initial_chunk.size, &msg,
                                       nullptr));

  // Either side unknown -> refuse to claim it, so ethereum.c falls through to
  // the raw-calldata path (AdvancedMode-gated, bytes shown).
  MakeTransformErc20(&msg, nullptr, kTGBP);
  EXPECT_FALSE(ethereum_contractHandled(msg.data_initial_chunk.size, &msg,
                                        nullptr))
      << "unknown INPUT token must not clear-sign";

  MakeTransformErc20(&msg, kTUSD, nullptr);
  EXPECT_FALSE(ethereum_contractHandled(msg.data_initial_chunk.size, &msg,
                                        nullptr))
      << "unknown OUTPUT token must not clear-sign";

  MakeTransformErc20(&msg, nullptr, nullptr);
  EXPECT_FALSE(ethereum_contractHandled(msg.data_initial_chunk.size, &msg,
                                        nullptr));

  // A chain with no token table entries at all cannot name either asset, so it
  // must refuse even though 0x deploys the same proxy there. This is what the
  // chain allowlist was previously being asked to approximate.
  for (uint32_t cid : {8453u, 42161u, 43114u}) {
    MakeTransformErc20(&msg, kTUSD, kTGBP);
    msg.chain_id = cid;
    EXPECT_FALSE(ethereum_contractHandled(msg.data_initial_chunk.size, &msg,
                                          nullptr))
        << "chain " << cid << " has no token entries; nothing is nameable";
  }
}

TEST(Ethereum, Eip712ChainIdRequiresCanonicalUint32) {
  uint32_t value = 0;
  EXPECT_TRUE(eip712_parse_canonical_u32("0", &value));
  EXPECT_EQ(0u, value);
  EXPECT_TRUE(eip712_parse_canonical_u32("4294967295", &value));
  EXPECT_EQ(UINT32_MAX, value);

  EXPECT_FALSE(eip712_parse_canonical_u32("", &value));
  EXPECT_FALSE(eip712_parse_canonical_u32("01", &value));
  EXPECT_FALSE(eip712_parse_canonical_u32("-1", &value));
  EXPECT_FALSE(eip712_parse_canonical_u32("1 ", &value));
  EXPECT_FALSE(eip712_parse_canonical_u32("4294967296", &value));
  EXPECT_FALSE(eip712_parse_canonical_u32(nullptr, &value));
  EXPECT_FALSE(eip712_parse_canonical_u32("1", nullptr));
}

extern "C" {
#include "keepkey/firmware/ethereum_contracts.h"
}

// The 0x Exchange Proxy lives at the same address on many chains, so the two 0x
// decoders cannot be pinned to mainnet the way the Uniswap and Sablier ones are.
// Optimism is the trap: 0x deploys a DIFFERENT proxy there
// (0xdef1abe32c034e558cdd535791643c58a13acc10), so allowing chain 10 for
// ZXSWAP_ADDRESS would narrate an unrelated contract.
TEST(Ethereum, ZxExchangeProxyChainAllowlist) {
  EXPECT_TRUE(zx_isExchangeProxyChain(1));      // Ethereum
  EXPECT_TRUE(zx_isExchangeProxyChain(56));     // BNB Chain
  EXPECT_TRUE(zx_isExchangeProxyChain(137));    // Polygon
  EXPECT_TRUE(zx_isExchangeProxyChain(8453));   // Base
  EXPECT_TRUE(zx_isExchangeProxyChain(42161));  // Arbitrum
  EXPECT_TRUE(zx_isExchangeProxyChain(43114));  // Avalanche

  EXPECT_FALSE(zx_isExchangeProxyChain(10)) << "Optimism uses a different 0x proxy";

  // Default-deny: anything unlisted falls through to generic disclosure.
  EXPECT_FALSE(zx_isExchangeProxyChain(0));
  EXPECT_FALSE(zx_isExchangeProxyChain(5));
  EXPECT_FALSE(zx_isExchangeProxyChain(250));
  EXPECT_FALSE(zx_isExchangeProxyChain(59144));
  EXPECT_FALSE(zx_isExchangeProxyChain(0xFFFFFFFFu));
}
