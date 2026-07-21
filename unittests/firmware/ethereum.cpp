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

static EthereumSignTx liquidity_tx(bool known_token) {
  EthereumSignTx msg;
  memset(&msg, 0, sizeof(msg));
  msg.has_chain_id = true;
  msg.chain_id = 1;
  msg.has_to = true;
  msg.to.size = 20;
  memcpy(msg.to.bytes, UNISWAP_ROUTER_ADDRESS, 20);
  msg.has_data_initial_chunk = true;
  msg.data_initial_chunk.size = 4 + 6 * 32;
  memcpy(msg.data_initial_chunk.bytes, "\xf3\x05\xd7\x19", 4);

  const TokenType* token = nullptr;
  EXPECT_TRUE(tokenByTicker(1, "DAI", &token));
  if (token == nullptr) return msg;
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
  msg.value.size = 1;
  msg.value.bytes[0] = 1;
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
