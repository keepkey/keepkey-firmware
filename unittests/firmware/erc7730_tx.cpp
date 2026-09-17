extern "C" {
#include "keepkey/firmware/erc7730_tx.h"
}

#include <gtest/gtest.h>

#include <cstring>

TEST(Erc7730TxContinuation, RoundTripsSelectorOnlyTransaction) {
  EthereumSignTx input{};
  input.address_n_count = 5;
  const uint32_t path[] = {0x8000002c, 0x8000003c, 0x80000000, 0, 7};
  memcpy(input.address_n, path, sizeof(path));
  input.has_nonce = true;
  input.nonce.size = 1;
  input.nonce.bytes[0] = 9;
  input.has_gas_price = true;
  input.gas_price.size = 2;
  input.gas_price.bytes[0] = 1;
  input.gas_price.bytes[1] = 2;
  input.has_gas_limit = true;
  input.gas_limit.size = 3;
  input.has_to = true;
  input.to.size = 20;
  memset(input.to.bytes, 0x33, 20);
  input.has_value = true;
  input.value.size = 0;
  input.has_data_initial_chunk = true;
  input.data_initial_chunk.size = 4;
  const uint8_t selector[4] = {0xa9, 0x05, 0x9c, 0xbb};
  memcpy(input.data_initial_chunk.bytes, selector, sizeof(selector));
  input.has_data_length = true;
  input.data_length = 68;
  input.has_chain_id = true;
  input.chain_id = 1;

  Erc7730TxContinuation continuation;
  ASSERT_TRUE(erc7730_tx_continuation_capture(&continuation, &input));
  EXPECT_LT(continuation.length, ERC7730_TX_CONTINUATION_MAX);
  EthereumSignTx restored;
  ASSERT_TRUE(erc7730_tx_continuation_restore(&continuation, &restored));
  EXPECT_EQ(restored.address_n_count, input.address_n_count);
  EXPECT_EQ(memcmp(restored.address_n, input.address_n, sizeof(path)), 0);
  EXPECT_EQ(restored.chain_id, 1u);
  EXPECT_EQ(restored.data_length, 68u);
  EXPECT_EQ(restored.data_initial_chunk.size, 4u);
  EXPECT_EQ(memcmp(restored.data_initial_chunk.bytes, selector, 4), 0);

  erc7730_tx_continuation_clear(&continuation);
  for (uint8_t byte : continuation.encoded) EXPECT_EQ(byte, 0);
}

TEST(Erc7730TxContinuation, RejectsNonSelectorInitialChunks) {
  EthereumSignTx tx{};
  tx.has_data_length = true;
  tx.data_length = 68;
  tx.has_data_initial_chunk = true;
  Erc7730TxContinuation continuation;
  for (pb_size_t size : {0u, 3u, 5u, 1024u}) {
    tx.data_initial_chunk.size = size;
    EXPECT_FALSE(erc7730_tx_continuation_capture(&continuation, &tx));
  }
}

TEST(Erc7730TxContinuation, RejectsCorruptEncodingAndScrubsOutput) {
  Erc7730TxContinuation continuation{};
  continuation.length = 1;
  continuation.encoded[0] = 0xff;
  EthereumSignTx restored;
  memset(&restored, 0xaa, sizeof(restored));
  EXPECT_FALSE(erc7730_tx_continuation_restore(&continuation, &restored));
  const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&restored);
  for (size_t i = 0; i < sizeof(restored); ++i) EXPECT_EQ(bytes[i], 0);
}
