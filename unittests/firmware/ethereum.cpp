extern "C" {
#include "keepkey/firmware/eip712.h"
#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/ethereum_contracts.h"
#include "keepkey/firmware/ethereum_contracts/saproxy.h"
#include "keepkey/firmware/ethereum_contracts/thortx.h"
#include "keepkey/firmware/ethereum_contracts/zxtransERC20.h"
#include "keepkey/firmware/ethereum_tokens.h"
#include "keepkey/firmware/tron.h"
#include "trezor/crypto/address.h"
#include "messages-ethereum.pb.h"
}

#include "gtest/gtest.h"

#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>

bool kkconfirm_preload(int nYes, int nNo);
int kkconfirm_drain(void);
void kkconfirm_capture_start(void);
std::vector<std::string> kkconfirm_capture_finish(void);

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

TEST(Ethereum, ContractAmountCallsitesFailClosedAtDisplayBoundary) {
  uint8_t max_word[32];
  std::memset(max_word, 0xff, sizeof(max_word));
  char rendered[41];

  EXPECT_FALSE(sa_formatUint256(max_word, "", rendered, sizeof(rendered)));
  EXPECT_FALSE(
      sa_formatUint256(max_word, " Token Units", rendered, sizeof(rendered)));
  EXPECT_FALSE(
      thor_formatUnknownAssetAmount(max_word, rendered, sizeof(rendered)));

  uint8_t one[32] = {};
  one[31] = 1;
  ASSERT_TRUE(
      sa_formatUint256(one, " Token Units", rendered, sizeof(rendered)));
  EXPECT_STREQ("1 Token Units", rendered);
  ASSERT_TRUE(thor_formatUnknownAssetAmount(one, rendered, sizeof(rendered)));
  EXPECT_STREQ("1 unformatted", rendered);
}

TEST(Ethereum, NativeAmountsUseTheSigningChainsTicker) {
  bignum256 amount;
  bn_read_uint64(1500000000000000000ULL, &amount);
  char rendered[32];

  ASSERT_TRUE(ethereumFormatAmount(&amount, nullptr, 43114, rendered,
                                   sizeof(rendered)));
  EXPECT_STREQ("1.5 AVAX", rendered);

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
  EXPECT_NE(SUCCESS, encAddress("0x00112233445566778899aabbccddeeff0011223344",
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
static const uint8_t kNativePseudoAddress[20] = {
    0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee};

TEST(Ethereum, TransferDisplayDoesNotAliasHighChainTokenMetadata) {
  EthereumSignTx msg = EthereumSignTx{};
  msg.has_chain_id = true;
  msg.chain_id = 257;
  msg.has_to = true;
  msg.to.size = 20;
  std::memcpy(msg.to.bytes, kTUSD, msg.to.size);
  msg.has_data_initial_chunk = true;
  msg.data_initial_chunk.size = 68;
  std::memcpy(msg.data_initial_chunk.bytes, "\xa9\x05\x9c\xbb", 4);
  msg.data_initial_chunk.bytes[67] = 1;
  msg.address_type = OutputAddressType_TRANSFER;

  ASSERT_TRUE(ethereum_isStandardERC20Transfer(&msg));
  char rendered[32];
  ASSERT_TRUE(ethereumFormatTransferAmount(&msg, rendered, sizeof(rendered)));
  EXPECT_STREQ("Unknown token value", rendered);
}

TEST(Ethereum, NativePseudoAddressCallsRenderUnknownOffMainnet) {
  static const uint8_t selectors[][4] = {
      {0xa9, 0x05, 0x9c, 0xbb}, /* transfer(address,uint256) */
      {0x09, 0x5e, 0xa7, 0xb3}, /* approve(address,uint256) */
  };

  for (size_t i = 0; i < sizeof(selectors) / sizeof(selectors[0]); ++i) {
    EthereumSignTx msg = EthereumSignTx{};
    msg.has_chain_id = true;
    msg.chain_id = 257;
    msg.has_to = true;
    msg.to.size = sizeof(kNativePseudoAddress);
    std::memcpy(msg.to.bytes, kNativePseudoAddress, msg.to.size);
    msg.has_data_initial_chunk = true;
    msg.data_initial_chunk.size = 68;
    std::memcpy(msg.data_initial_chunk.bytes, selectors[i], 4);
    msg.data_initial_chunk.bytes[67] = 1;

    if (i == 0) {
      ASSERT_TRUE(ethereum_isStandardERC20Transfer(&msg));
    } else {
      ASSERT_FALSE(ethereum_isStandardERC20Transfer(&msg));
    }

    const TokenType* token = tokenByChainAddress(msg.chain_id, msg.to.bytes);
    ASSERT_EQ(UnknownToken, token);

    bignum256 amount;
    bn_from_bytes(msg.data_initial_chunk.bytes + 36, 32, &amount);
    char rendered[32];
    ASSERT_TRUE(ethereumFormatAmount(&amount, token, msg.chain_id, rendered,
                                     sizeof(rendered)));
    EXPECT_STREQ("Unknown token value", rendered);
  }
}

TEST(Ethereum, NativePseudoAddressTransferFormatterIsUnknownOffMainnet) {
  EthereumSignTx msg = EthereumSignTx{};
  msg.has_chain_id = true;
  msg.chain_id = 257;
  msg.has_to = true;
  msg.to.size = sizeof(kNativePseudoAddress);
  std::memcpy(msg.to.bytes, kNativePseudoAddress, msg.to.size);
  msg.has_data_initial_chunk = true;
  msg.data_initial_chunk.size = 68;
  std::memcpy(msg.data_initial_chunk.bytes, "\xa9\x05\x9c\xbb", 4);
  msg.data_initial_chunk.bytes[67] = 1;
  msg.address_type = OutputAddressType_TRANSFER;

  ASSERT_TRUE(ethereum_isStandardERC20Transfer(&msg));
  char rendered[32];
  ASSERT_TRUE(ethereumFormatTransferAmount(&msg, rendered, sizeof(rendered)));
  EXPECT_STREQ("Unknown token value", rendered);
}

TEST(Ethereum, ThorchainNativeAssetUsesOnlyItsZeroAddressSentinel) {
  static const uint8_t kZeroAddress[20] = {};
  static const uint8_t kTokenAddress[20] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                            0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

  EXPECT_TRUE(thor_assetIsNative(kZeroAddress));
  EXPECT_FALSE(thor_assetIsNative(kNativePseudoAddress));
  EXPECT_FALSE(thor_assetIsNative(kTokenAddress));
  EXPECT_FALSE(thor_assetIsNative(nullptr));
}

// A deposit-shaped call is only THORChain's if it goes to THORChain's router
// ON THIS CHAIN. Without the pin, any contract carrying the selector inherited
// the deposit clear-sign UX and skipped the AdvancedMode blind-sign gate.
static void MakeThorDeposit(EthereumSignTx* msg, const char* to_hex,
                            uint32_t chain_id) {
  *msg = EthereumSignTx{};
  msg->has_to = true;
  msg->to.size = 20;
  for (size_t i = 0; i < 20; i++) {
    char byte[3] = {to_hex[i * 2], to_hex[i * 2 + 1], 0};
    msg->to.bytes[i] = (uint8_t)strtoul(byte, nullptr, 16);
  }
  msg->has_chain_id = true;
  msg->chain_id = chain_id;
  msg->has_data_initial_chunk = true;
  msg->data_initial_chunk.size = 4 + 6 * 32;
  std::memcpy(msg->data_initial_chunk.bytes, THOR_SELECTOR_DEPOSIT_WITH_EXPIRY,
              4);
}

TEST(Ethereum, ThorchainDepositIsPinnedToItsRouterOnItsChain) {
  EthereumSignTx msg;

  MakeThorDeposit(&msg, THOR_ROUTER, 1);
  EXPECT_TRUE(thor_isThorchainTx(&msg));

  MakeThorDeposit(&msg, THOR_ROUTER_AVAX, 43114);
  EXPECT_TRUE(thor_isThorchainTx(&msg));

  // An attacker contract with the same calldata shape.
  MakeThorDeposit(&msg, "1234567890123456789012345678901234567890", 1);
  EXPECT_FALSE(thor_isThorchainTx(&msg));

  // The right address on the wrong chain: those 20 bytes are unrelated code
  // there, so it cannot borrow the trusted UX.
  MakeThorDeposit(&msg, THOR_ROUTER, 43114);
  EXPECT_FALSE(thor_isThorchainTx(&msg));
  MakeThorDeposit(&msg, THOR_ROUTER_AVAX, 1);
  EXPECT_FALSE(thor_isThorchainTx(&msg));

  // Maya Protocol deposits with the same calldata shape through its own
  // mainnet router, and this decoder narrates both.
  MakeThorDeposit(&msg, MAYA_ROUTER, 1);
  EXPECT_TRUE(thor_isThorchainTx(&msg));
  MakeThorDeposit(&msg, MAYA_ROUTER, 43114);
  EXPECT_FALSE(thor_isThorchainTx(&msg)) << "mainnet identity, mainnet only";

  // A chain with no pinned router, and a tx with no chain at all.
  MakeThorDeposit(&msg, THOR_ROUTER, 56);
  EXPECT_FALSE(thor_isThorchainTx(&msg));
  MakeThorDeposit(&msg, THOR_ROUTER, 1);
  msg.has_chain_id = false;
  EXPECT_FALSE(thor_isThorchainTx(&msg));
}

// A canonical transformERC20 call with one transformation whose data is one
// byte. The transformation byte is deliberately outside the four static words
// that the retired decoder displayed.
static void MakeTransformErc20(EthereumSignTx* msg, uint8_t transform_byte) {
  *msg = EthereumSignTx{};
  msg->has_to = true;
  msg->to.size = 20;
  std::memcpy(msg->to.bytes, ZXSWAP_ADDRESS, msg->to.size);
  msg->has_chain_id = true;
  msg->chain_id = 1;
  msg->has_data_initial_chunk = true;
  msg->data_initial_chunk.size = 4 + 11 * 32;
  std::memcpy(msg->data_initial_chunk.bytes, "\x41\x55\x65\xb0", 4);
  std::memcpy(msg->data_initial_chunk.bytes + 4 + 12, kTUSD, 20);
  std::memcpy(msg->data_initial_chunk.bytes + 4 + 32 + 12, kTGBP, 20);
  msg->data_initial_chunk.bytes[4 + 3 * 32 - 1] = 1;     // input amount
  msg->data_initial_chunk.bytes[4 + 4 * 32 - 1] = 1;     // minimum output
  msg->data_initial_chunk.bytes[4 + 5 * 32 - 1] = 0xa0;  // array offset
  msg->data_initial_chunk.bytes[4 + 6 * 32 - 1] = 1;     // array length
  msg->data_initial_chunk.bytes[4 + 7 * 32 - 1] = 0x20;  // element offset
  msg->data_initial_chunk.bytes[4 + 8 * 32 - 1] = 1;     // deployment nonce
  msg->data_initial_chunk.bytes[4 + 9 * 32 - 1] = 0x40;  // data offset
  msg->data_initial_chunk.bytes[4 + 10 * 32 - 1] = 1;    // data length
  msg->data_initial_chunk.bytes[4 + 10 * 32] = transform_byte;
}

TEST(Ethereum, TransformErc20AlwaysRequiresAdvancedMode) {
  EthereumSignTx first, second;
  MakeTransformErc20(&first, 0x41);
  MakeTransformErc20(&second, 0x42);

  ASSERT_EQ(first.data_initial_chunk.size, second.data_initial_chunk.size);
  ASSERT_EQ(0, std::memcmp(first.data_initial_chunk.bytes,
                           second.data_initial_chunk.bytes,
                           first.data_initial_chunk.size - 32));
  ASSERT_NE(0, std::memcmp(first.data_initial_chunk.bytes,
                           second.data_initial_chunk.bytes,
                           first.data_initial_chunk.size));

  EXPECT_FALSE(
      ethereum_contractHandled(first.data_initial_chunk.size, &first, nullptr));
  EXPECT_FALSE(ethereum_contractHandled(second.data_initial_chunk.size, &second,
                                        nullptr));
}

TEST(Ethereum, MakerDaoSelectorsAreNotSpecializedForPointRelease) {
  struct MakerCall {
    const uint8_t selector[4];
    size_t argument_count;
  };
  static const MakerCall kCalls[] = {
      {{0xc7, 0x40, 0x73, 0xa1}, 1},  // open(address)
      {{0x1b, 0x96, 0x81, 0x60}, 5},  // wipeAndFree(...,address)
  };

  for (const MakerCall& call : kCalls) {
    EthereumSignTx msg = EthereumSignTx{};
    msg.has_chain_id = true;
    msg.chain_id = 1;
    msg.has_to = true;
    msg.to.size = 20;
    msg.has_data_initial_chunk = true;
    msg.data_initial_chunk.size = 4 + call.argument_count * 32;
    std::memcpy(msg.data_initial_chunk.bytes, call.selector,
                sizeof(call.selector));

    EXPECT_FALSE(
        ethereum_contractHandled(msg.data_initial_chunk.size, &msg, nullptr));
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
// decoders cannot be pinned to mainnet the way the Uniswap and Sablier ones
// are. Optimism is the trap: 0x deploys a DIFFERENT proxy there
// (0xdef1abe32c034e558cdd535791643c58a13acc10), so allowing chain 10 for
// ZXSWAP_ADDRESS would narrate an unrelated contract.
TEST(Ethereum, ZxExchangeProxyChainAllowlist) {
  EXPECT_TRUE(zx_isExchangeProxyChain(1));      // Ethereum
  EXPECT_TRUE(zx_isExchangeProxyChain(56));     // BNB Chain
  EXPECT_TRUE(zx_isExchangeProxyChain(137));    // Polygon
  EXPECT_TRUE(zx_isExchangeProxyChain(8453));   // Base
  EXPECT_TRUE(zx_isExchangeProxyChain(42161));  // Arbitrum
  EXPECT_TRUE(zx_isExchangeProxyChain(43114));  // Avalanche

  EXPECT_FALSE(zx_isExchangeProxyChain(10))
      << "Optimism uses a different 0x proxy";

  // Default-deny: anything unlisted falls through to generic disclosure.
  EXPECT_FALSE(zx_isExchangeProxyChain(0));
  EXPECT_FALSE(zx_isExchangeProxyChain(5));
  EXPECT_FALSE(zx_isExchangeProxyChain(250));
  EXPECT_FALSE(zx_isExchangeProxyChain(59144));
  EXPECT_FALSE(zx_isExchangeProxyChain(0xFFFFFFFFu));
}

TEST(Ethereum, NativePseudoAddressIsStrictlyChainScoped) {
  EXPECT_EQ(tokenByChainAddress(1, kNativePseudoAddress), EthTestToken);
  EXPECT_EQ(tokenByChainAddress(56, kNativePseudoAddress), UnknownToken);
  EXPECT_EQ(tokenByChainAddress(137, kNativePseudoAddress), UnknownToken);
  EXPECT_EQ(tokenByChainAddress(257, kNativePseudoAddress), UnknownToken);

  /* The sentinel is ETH metadata and must remain a chain-1-only value. */
  EXPECT_STREQ(EthTestToken->ticker, "  ETH");
  EXPECT_TRUE(zx_tokenLabelsThisChain(1, EthTestToken));
  EXPECT_FALSE(zx_tokenLabelsThisChain(56, EthTestToken));
  EXPECT_FALSE(zx_tokenLabelsThisChain(137, EthTestToken));
  EXPECT_FALSE(zx_tokenLabelsThisChain(8453, EthTestToken));
  EXPECT_FALSE(zx_tokenLabelsThisChain(42161, EthTestToken));
  EXPECT_FALSE(zx_tokenLabelsThisChain(43114, EthTestToken));

  /* Unresolved and NULL stay refused, on every chain -- this helper replaced
     the UnknownToken check, so it has to still do that job. */
  EXPECT_FALSE(zx_tokenLabelsThisChain(1, UnknownToken));
  EXPECT_FALSE(zx_tokenLabelsThisChain(56, UnknownToken));
  EXPECT_FALSE(zx_tokenLabelsThisChain(1, NULL));

  /* An ordinary chain-1 table entry is unaffected. */
  const TokenType* usdc = NULL;
  if (tokenByTicker(1, "USDC", &usdc) && usdc != UnknownToken) {
    EXPECT_TRUE(zx_tokenLabelsThisChain(1, usdc));
  }
}
/* ethereumFormatAmount() takes the Wanchain tx type from a module static that
 * ethereum_signing_init() owns -- and on the transfer path the amount screen is
 * drawn before signing_init() runs. A Wanchain transaction therefore left its
 * type behind, and the NEXT transfer's amount screen named the asset " WAN" on
 * whatever chain it was really on. The Wanchain leg is the in-test control: it
 * must still say " WAN", or a build that simply never set the ticker would
 * pass the Ethereum assertion for the wrong reason. */
TEST(Ethereum, TransferTickerComesFromThisMessageNotTheLastOne) {
  EthereumSignTx wan;
  memset(&wan, 0, sizeof(wan));
  wan.has_chain_id = true;
  wan.chain_id = 888;  // Wanchain
  wan.has_tx_type = true;
  wan.tx_type = 1;
  wan.has_value = true;
  wan.value.size = 8;
  wan.value.bytes[7] = 0x01;  // 1 wei short of nothing, but > 1e9 after padding
  wan.value.bytes[0] = 0x0d;
  char buf[64] = {0};
  ASSERT_TRUE(ethereumFormatTransferAmount(&wan, buf, sizeof(buf)));
  EXPECT_NE(nullptr, strstr(buf, " WAN")) << buf;

  EthereumSignTx eth;
  memset(&eth, 0, sizeof(eth));
  eth.has_chain_id = true;
  eth.chain_id = 1;  // Ethereum mainnet, no tx_type at all
  eth.has_value = true;
  eth.value.size = 8;
  eth.value.bytes[0] = 0x0d;
  eth.value.bytes[7] = 0x01;
  memset(buf, 0, sizeof(buf));
  ASSERT_TRUE(ethereumFormatTransferAmount(&eth, buf, sizeof(buf)));
  EXPECT_EQ(nullptr, strstr(buf, " WAN")) << buf;
  EXPECT_NE(nullptr, strstr(buf, " ETH")) << buf;
}

TEST(Ethereum, NativeThorConfirmationDisplaysValueInsteadOfAbiAmount) {
  EthereumSignTx msg;
  MakeThorDeposit(&msg, THOR_ROUTER, 1);
  msg.data_initial_chunk.bytes[4 + 3 * 32 + 31] = 0xa0;
  // Native zero-address deposit: ABI amount is one ETH; msg.value is two.
  const uint8_t one_eth[8] = {0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0, 0};
  const uint8_t two_eth[8] = {0x1b, 0xc1, 0x6d, 0x67, 0x4e, 0xc8, 0, 0};
  memcpy(msg.data_initial_chunk.bytes + 4 + 2 * 32 + 24, one_eth, 8);
  msg.has_value = true;
  msg.value.size = 8;
  memcpy(msg.value.bytes, two_eth, 8);

  // Accept router and vault, then reject the amount screen. Inspect the
  // rendered body at the real screen boundary, independent of memo parsing.
  ASSERT_TRUE(kkconfirm_preload(2, 1));
  kkconfirm_capture_start();
  EXPECT_FALSE(thor_confirmThorTx(msg.data_initial_chunk.size, &msg));
  const auto screens = kkconfirm_capture_finish();
  EXPECT_EQ(0, kkconfirm_drain());
  EXPECT_NE(screens.end(),
            std::find(screens.begin(), screens.end(), "Confirm sending 2 ETH"));
  EXPECT_EQ(screens.end(),
            std::find(screens.begin(), screens.end(), "Confirm sending 1 ETH"));
}
