extern "C" {
#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/ethereum_contracts/zxappliquid.h"
#include "keepkey/firmware/ethereum_contracts/zxliquidtx.h"
#include "keepkey/firmware/ethereum_tokens.h"
#include "trezor/crypto/address.h"
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
