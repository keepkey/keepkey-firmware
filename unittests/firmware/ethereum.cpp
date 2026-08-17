extern "C" {
#include "keepkey/firmware/eip712.h"
#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/tron.h"
#include "trezor/crypto/address.h"
}

#include "gtest/gtest.h"

#include <string>

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
