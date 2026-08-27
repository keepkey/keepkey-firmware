/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2021 ShapeShift
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "keepkey/firmware/ethereum_contracts/zxliquidtx.h"

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/font.h"
#include "keepkey/board/layout.h"
#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/ethereum_tokens.h"
#include "keepkey/firmware/storage.h"
#include "trezor/crypto/address.h"
#include "trezor/crypto/bignum.h"
#include "trezor/crypto/bip32.h"
#include "trezor/crypto/curves.h"
#include "trezor/crypto/memzero.h"

#include <stdio.h>
#include <string.h>

#define UNISWAP_LIQUIDITY_CALL_SIZE (4 + 6 * 32)
#define UNISWAP_TOKEN_WORD 0
#define UNISWAP_PRIMARY_AMOUNT_WORD 1
#define UNISWAP_TOKEN_MIN_WORD 2
#define UNISWAP_NATIVE_MIN_WORD 3
#define UNISWAP_RECIPIENT_WORD 4
#define UNISWAP_DEADLINE_WORD 5
#define UNISWAP_AMOUNT_TEXT_SIZE 96

static const uint8_t* abi_word(const EthereumSignTx* msg, size_t word) {
  return msg->data_initial_chunk.bytes + 4 + word * 32;
}

static bool abi_address_is_canonical(const uint8_t* word) {
  for (size_t i = 0; i < 12; i++) {
    if (word[i] != 0) return false;
  }
  return true;
}

static bool uint256_fits_u64(const uint8_t* word) {
  for (size_t i = 0; i < 24; i++) {
    if (word[i] != 0) return false;
  }
  return true;
}

static bool tx_value_is_zero(const EthereumSignTx* msg) {
  if (!msg->has_value && msg->value.size != 0) return false;
  for (size_t i = 0; i < msg->value.size; i++) {
    if (msg->value.bytes[i] != 0) return false;
  }
  return true;
}

static bool isAddLiquidityEthCall(const EthereumSignTx* msg) {
  return memcmp(msg->data_initial_chunk.bytes, "\xf3\x05\xd7\x19", 4) == 0;
}

static bool isRemoveLiquidityEthCall(const EthereumSignTx* msg) {
  return memcmp(msg->data_initial_chunk.bytes, "\x02\x75\x1c\xec", 4) == 0;
}

static const TokenType* liquidity_token(const EthereumSignTx* msg) {
  const uint8_t* token_address = abi_word(msg, UNISWAP_TOKEN_WORD) + 12;
  const TokenType* token = tokenByChainAddress(1, token_address);
  return token == UnknownToken ? NULL : token;
}

static bool liquidity_shape_is_clear_signable(const EthereumSignTx* msg) {
  if (!msg->has_chain_id || msg->chain_id != 1 || !msg->has_to ||
      msg->to.size != 20 ||
      memcmp(msg->to.bytes, UNISWAP_ROUTER_ADDRESS, 20) != 0 ||
      !msg->has_data_initial_chunk ||
      msg->data_initial_chunk.size != UNISWAP_LIQUIDITY_CALL_SIZE ||
      msg->value.size > 32 || (!msg->has_value && msg->value.size != 0))
    return false;

  if (!isAddLiquidityEthCall(msg) && !isRemoveLiquidityEthCall(msg))
    return false;
  if (!abi_address_is_canonical(abi_word(msg, UNISWAP_TOKEN_WORD)) ||
      !abi_address_is_canonical(abi_word(msg, UNISWAP_RECIPIENT_WORD)) ||
      !uint256_fits_u64(abi_word(msg, UNISWAP_DEADLINE_WORD)))
    return false;
  if (liquidity_token(msg) == NULL) return false;
  if (isRemoveLiquidityEthCall(msg) && !tx_value_is_zero(msg)) return false;
  return true;
}

static bool format_amount(const bignum256* amount, const char* suffix,
                          unsigned int decimals, char* out, size_t out_len) {
  if (bn_format(amount, NULL, suffix, decimals, 0, false, out, out_len) == 0)
    return false;
  return calc_str_line(get_body_font(), out, BODY_WIDTH) <= BODY_ROWS;
}

bool zx_formatZxLiquidityPrimaryAmount(const EthereumSignTx* msg, char* out,
                                       size_t out_len) {
  if (!out || out_len == 0 || !liquidity_shape_is_clear_signable(msg))
    return false;

  bignum256 amount;
  bn_from_bytes(abi_word(msg, UNISWAP_PRIMARY_AMOUNT_WORD), 32, &amount);
  if (isAddLiquidityEthCall(msg)) {
    const TokenType* token = liquidity_token(msg);
    return format_amount(&amount, token->ticker, token->decimals, out, out_len);
  }
  return format_amount(&amount, " LP", 18, out, out_len);
}

static HDNode* zx_getDerivedNode(const char* curve, const uint32_t* address_n,
                                 size_t address_n_count,
                                 uint32_t* fingerprint) {
  static HDNode CONFIDENTIAL node;
  if (fingerprint) *fingerprint = 0;
  if (!get_curve_by_name(curve)) return NULL;
  if (!storage_getRootNode(curve, true, &node)) return NULL;
  if (!address_n || address_n_count == 0) return &node;
  if (hdnode_private_ckd_cached(&node, address_n, address_n_count,
                                fingerprint) == 0)
    return NULL;
  return &node;
}

static bool confirmFromAccountMatch(const EthereumSignTx* msg) {
  char address_str[43] = {'0', 'x', '\0'};
  uint8_t address_bytes[20];

  HDNode* node = zx_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                   msg->address_n_count, NULL);
  if (!node) return false;
  if (!hdnode_get_ethereum_pubkeyhash(node, address_bytes)) {
    memzero(node, sizeof(*node));
    return false;
  }
  memzero(node, sizeof(*node));

  const uint8_t* recipient = abi_word(msg, UNISWAP_RECIPIENT_WORD) + 12;
  bool is_self = memcmp(recipient, address_bytes, 20) == 0;
  for (uint32_t i = 0; i < 20; i++) {
    snprintf(&address_str[2 + i * 2], 3, "%02x", recipient[i]);
  }

  /* The screen states plainly which of the two cases this is and shows the
   * recipient's full address, so a press here is informed consent to exactly
   * that recipient. Return whether the USER approved -- not whether the
   * recipient happened to be us.
   *
   * `return is_self` refused the transaction AFTER the user approved it, and
   * ethereum.c turns that false into ActionCancelled, so the device reported
   * "Signing cancelled by user" for a transaction the user had just confirmed.
   * That made every removeLiquidityETH to a third party unsignable, which is
   * the normal way to withdraw a pool position to another address. Withholding
   * the disclosure is not what makes this safe; showing "NOT this wallet" and
   * the address is. */
  if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
               "Uniswap Recipient", "%s\n%s",
               is_self ? "this wallet" : "NOT this wallet", address_str))
    return false;
  return true;
}

bool zx_isZxLiquidTx(const EthereumSignTx* msg) {
  return liquidity_shape_is_clear_signable(msg);
}

bool zx_confirmZxLiquidTx(uint32_t data_total, const EthereumSignTx* msg) {
  if (data_total != UNISWAP_LIQUIDITY_CALL_SIZE ||
      !liquidity_shape_is_clear_signable(msg))
    return false;

  const TokenType* token = liquidity_token(msg);
  bignum256 amount;
  char amount_text[UNISWAP_AMOUNT_TEXT_SIZE];

  if (!zx_formatZxLiquidityPrimaryAmount(msg, amount_text,
                                         sizeof(amount_text)) ||
      !confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
               isAddLiquidityEthCall(msg) ? "Uniswap Token" : "Uniswap LP Burn",
               "%s", amount_text))
    return false;

  bn_from_bytes(abi_word(msg, UNISWAP_TOKEN_MIN_WORD), 32, &amount);
  if (!format_amount(&amount, token->ticker, token->decimals, amount_text,
                     sizeof(amount_text)) ||
      !confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
               "Uniswap Token Min", "%s", amount_text))
    return false;

  if (!confirmFromAccountMatch(msg)) return false;

  if (isAddLiquidityEthCall(msg)) {
    bn_from_bytes(msg->value.bytes, msg->value.size, &amount);
    if (!format_amount(&amount, " ETH", 18, amount_text, sizeof(amount_text)) ||
        !confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Uniswap ETH",
                 "%s", amount_text))
      return false;
  }

  bn_from_bytes(abi_word(msg, UNISWAP_NATIVE_MIN_WORD), 32, &amount);
  if (!format_amount(&amount, " ETH", 18, amount_text, sizeof(amount_text)) ||
      !confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Uniswap ETH Min",
               "%s", amount_text))
    return false;

  const uint8_t* deadline_word = abi_word(msg, UNISWAP_DEADLINE_WORD);
  uint64_t deadline = 0;
  for (size_t i = 24; i < 32; i++) {
    deadline = (deadline << 8) | deadline_word[i];
  }
  char deadline_text[21];
  snprintf(deadline_text, sizeof(deadline_text), "%" PRIu64, deadline);
  return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Uniswap Deadline", "%s", deadline_text);
}
