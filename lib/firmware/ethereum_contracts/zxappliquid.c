/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2021 ShapeShift
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "keepkey/firmware/ethereum_contracts/zxappliquid.h"
#include "keepkey/firmware/ethereum_contracts/zxliquidtx.h"

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/font.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/ethereum_tokens.h"
#include "trezor/crypto/bignum.h"
#include "trezor/crypto/sha3.h"

#include <stdio.h>
#include <string.h>

#define UNISWAP_APPROVE_CALL_SIZE (4 + 2 * 32)
#define UNISWAP_AMOUNT_TEXT_SIZE 96

static const uint8_t UNISWAP_FACTORY_ADDRESS[20] = {
    0x5c, 0x69, 0xbe, 0xe7, 0x01, 0xef, 0x81, 0x4a, 0x2b, 0x6a,
    0x3e, 0xdd, 0x4b, 0x16, 0x52, 0xcb, 0x9c, 0xc5, 0xaa, 0x6f};
static const uint8_t UNISWAP_PAIR_INIT_CODE_HASH[32] = {
    0x96, 0xe8, 0xac, 0x42, 0x77, 0x19, 0x8f, 0xf8, 0xb6, 0xf7, 0x85,
    0x47, 0x8a, 0xa9, 0xa3, 0x9f, 0x40, 0x3c, 0xb7, 0x68, 0xdd, 0x02,
    0xcb, 0xee, 0x32, 0x6c, 0x3e, 0x7d, 0xa3, 0x48, 0x84, 0x5f};
static const uint8_t WETH_MAINNET_ADDRESS[20] = {
    0xc0, 0x2a, 0xaa, 0x39, 0xb2, 0x23, 0xfe, 0x8d, 0x0a, 0x0e,
    0x5c, 0x4f, 0x27, 0xea, 0xd9, 0x08, 0x3c, 0x75, 0x6c, 0xc2};

static bool tx_value_is_zero(const EthereumSignTx* msg) {
  if (!msg->has_value && msg->value.size != 0) return false;
  for (size_t i = 0; i < msg->value.size; i++) {
    if (msg->value.bytes[i] != 0) return false;
  }
  return true;
}

static bool spender_word_is_router(const EthereumSignTx* msg) {
  const uint8_t* word = msg->data_initial_chunk.bytes + 4;
  for (size_t i = 0; i < 12; i++) {
    if (word[i] != 0) return false;
  }
  return memcmp(word + 12, UNISWAP_ROUTER_ADDRESS, 20) == 0;
}

static void derive_pair_address(const uint8_t* token_a, const uint8_t* token_b,
                                uint8_t pair[20]) {
  uint8_t ordered[40];
  if (memcmp(token_a, token_b, 20) < 0) {
    memcpy(ordered, token_a, 20);
    memcpy(ordered + 20, token_b, 20);
  } else {
    memcpy(ordered, token_b, 20);
    memcpy(ordered + 20, token_a, 20);
  }

  uint8_t salt[SHA3_256_DIGEST_LENGTH];
  uint8_t digest[SHA3_256_DIGEST_LENGTH];
  keccak_256(ordered, sizeof(ordered), salt);
  SHA3_CTX ctx = {0};
  keccak_256_Init(&ctx);
  const uint8_t prefix = 0xff;
  keccak_Update(&ctx, &prefix, 1);
  keccak_Update(&ctx, UNISWAP_FACTORY_ADDRESS, sizeof(UNISWAP_FACTORY_ADDRESS));
  keccak_Update(&ctx, salt, sizeof(salt));
  keccak_Update(&ctx, UNISWAP_PAIR_INIT_CODE_HASH,
                sizeof(UNISWAP_PAIR_INIT_CODE_HASH));
  keccak_Final(&ctx, digest);
  memcpy(pair, digest + 12, 20);
}

static const TokenType* pool_underlying_token(const EthereumSignTx* msg) {
  int32_t token_index = 0;
  while (token_index >= 0) {
    const TokenType* token = tokenIter(&token_index);
    if (token == UnknownToken) break;
    if (token->chain_id != 1 ||
        memcmp(token->address, WETH_MAINNET_ADDRESS, 20) == 0)
      continue;
    uint8_t pair[20];
    derive_pair_address((const uint8_t*)token->address, WETH_MAINNET_ADDRESS,
                        pair);
    if (memcmp(msg->to.bytes, pair, 20) == 0) return token;
  }
  return NULL;
}

static bool approve_shape_is_clear_signable(const EthereumSignTx* msg) {
  if (!msg->has_chain_id || msg->chain_id != 1 || !msg->has_to ||
      msg->to.size != 20 || !msg->has_data_initial_chunk ||
      msg->data_initial_chunk.size != UNISWAP_APPROVE_CALL_SIZE ||
      memcmp(msg->data_initial_chunk.bytes, "\x09\x5e\xa7\xb3", 4) != 0 ||
      msg->value.size > 32 || !tx_value_is_zero(msg) ||
      !spender_word_is_router(msg))
    return false;
  return pool_underlying_token(msg) != NULL;
}

bool zx_confirmApproveLiquidity(uint32_t data_total,
                                const EthereumSignTx* msg) {
  if (data_total != UNISWAP_APPROVE_CALL_SIZE ||
      !approve_shape_is_clear_signable(msg))
    return false;

  const TokenType* token = pool_underlying_token(msg);
  const uint8_t* allowance = msg->data_initial_chunk.bytes + 4 + 32;
  char amount_text[UNISWAP_AMOUNT_TEXT_SIZE];
  if (memcmp(allowance, (const uint8_t*)MAX_ALLOWANCE, 32) == 0) {
    strlcpy(amount_text, "full LP balance", sizeof(amount_text));
  } else {
    bignum256 amount;
    bn_from_bytes(allowance, 32, &amount);
    if (bn_format(&amount, NULL, " LP", 18, 0, false, amount_text,
                  sizeof(amount_text)) == 0 ||
        calc_str_line(get_body_font(), amount_text, BODY_WIDTH) > BODY_ROWS)
      return false;
  }

  if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
               "Uniswap LP Approval", "%s", amount_text))
    return false;

  char pair_text[43] = {'0', 'x', '\0'};
  for (size_t i = 0; i < 20; i++) {
    snprintf(pair_text + 2 + i * 2, 3, "%02x", msg->to.bytes[i]);
  }
  return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Uniswap LP Pool", "%s\n%s", token->ticker, pair_text);
}

bool zx_isZxApproveLiquid(const EthereumSignTx* msg) {
  return approve_shape_is_clear_signable(msg);
}
