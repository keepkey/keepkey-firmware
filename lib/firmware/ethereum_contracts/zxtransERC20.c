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

#include "keepkey/firmware/ethereum_contracts/zxtransERC20.h"

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/app_confirm.h"
#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/ethereum_contracts.h"
#include "keepkey/firmware/ethereum_tokens.h"
#include "keepkey/firmware/fsm.h"
#include "trezor/crypto/address.h"

static bool isTransERC20Call(const EthereumSignTx* msg) {
  if (memcmp(msg->data_initial_chunk.bytes, "\x41\x55\x65\xb0", 4) == 0)
    return true;

  return false;
}

static bool tx_value_is_zero(const EthereumSignTx* msg) {
  if (msg->value.size > 32 || (!msg->has_value && msg->value.size != 0))
    return false;
  for (size_t i = 0; i < msg->value.size; i++) {
    if (msg->value.bytes[i] != 0) return false;
  }
  return true;
}

static bool transformations_offset_is_canonical(const EthereumSignTx* msg) {
  const uint8_t* offset =
      msg->data_initial_chunk.bytes + ZX_TRANSFORM_ERC20_HEAD_LEN - 32;
  for (size_t i = 0; i < 31; i++) {
    if (offset[i] != 0) return false;
  }
  return offset[31] == 0xa0;
}

/* Resolve both traded assets, or refuse.
 *
 * The structured screen names both traded assets and shows the input and
 * minimum-output bounds; a following raw screen now discloses the complete
 * transformations[] route. A bound the user cannot read is not a bound, and
 * ethereumFormatAmount() renders the literal "Unknown token value" whenever
 * tokenByChainAddress() misses -- so an unresolved token turns the screen into
 * a blind signature wearing a decoder's title.
 *
 * Misses are not rare or hypothetical. The generated table carries 1924 entries
 * for chain 1 and three each for BSC and Polygon, and none at all for Base,
 * Arbitrum or Avalanche, so on those chains EVERY pair fails to resolve. Gating
 * on the lookup rather than on a chain allowlist keeps this correct however the
 * tables change: incomplete today, expanded tomorrow, stale in between.
 *
 * Used by both the predicate and the confirm so the two cannot disagree about
 * what is displayable.
 */
static bool resolveBothTokens(const EthereumSignTx* msg, const TokenType** in,
                              const TokenType** out) {
  /* Require a complete canonical ABI head and the dynamic array's length word.
   * Past .size the chunk buffer can still hold bytes from an earlier message.
   */
  if (msg->data_initial_chunk.size < ZX_TRANSFORM_ERC20_MIN_LEN) return false;

  const TokenType* i = tokenByChainAddress(
      msg->chain_id, msg->data_initial_chunk.bytes + 4 + 12);
  const TokenType* o = tokenByChainAddress(
      msg->chain_id, msg->data_initial_chunk.bytes + 4 + 32 + 12);

  if (!zx_tokenLabelsThisChain(msg->chain_id, i) ||
      !zx_tokenLabelsThisChain(msg->chain_id, o))
    return false;

  if (in) *in = i;
  if (out) *out = o;
  return true;
}

bool zx_isZxTransformERC20(const EthereumSignTx* msg) {
  /* ZXSWAP_ADDRESS is an Ethereum-mainnet identity. See GH #431. */
  /* ZXSWAP_ADDRESS is the 0x Exchange Proxy, which is deployed at the same
     address on many chains, unlike the mainnet-only Uniswap router and
     Sablier proxy that the sibling decoders match. Pinning this one to
     chain_id == 1 (as GH #431 originally did) stopped legitimate 0x swaps
     on BSC, Polygon and the rest from being clear-signed and dropped them
     to the raw-calldata path. Use the per-chain allowlist instead; unknown
     chains still fall through, which is the safe direction. */
  if (!msg->has_chain_id || !zx_isExchangeProxyChain(msg->chain_id) ||
      !msg->has_to || msg->to.size != 20 || !msg->has_data_initial_chunk)
    return false;
  if (memcmp(msg->to.bytes, ZXSWAP_ADDRESS, 20) != 0) return false;
  if (msg->data_initial_chunk.size < ZX_TRANSFORM_ERC20_MIN_LEN) return false;
  if (!isTransERC20Call(msg)) return false;
  if (!transformations_offset_is_canonical(msg) || !tx_value_is_zero(msg))
    return false;

  /* Claim the transaction only if the screen can name both assets. Refusing
     here is what makes it fall through to the raw-calldata path, which is
     AdvancedMode-gated and shows the bytes; refusing in the confirm would be
     read as a user cancel (see ethereum.c, ethereum_contractConfirmed). */
  return resolveBothTokens(msg, NULL, NULL);
}

bool zx_confirmZxTransERC20(uint32_t data_total, const EthereumSignTx* msg) {
  /* transformERC20()'s four displayed arguments (input/output token, input
   * amount, minimum output amount) are STATIC head words, so their fixed
   * offsets stay correct wherever the dynamic transformations[] tail lands and
   * there is no offset pointer to validate here.
   *
   * resolveBothTokens() re-checks the received length and both lookups. The
   * predicate already required them, so reaching this with either unresolved
   * would mean the two disagreed; failing closed here keeps
   * "Unknown token value" off a screen that claims to bound a trade. */
  const TokenType *in, *out;
  if (data_total != msg->data_initial_chunk.size ||
      !zx_isZxTransformERC20(msg) || !resolveBothTokens(msg, &in, &out))
    return false;

  char constr1[40], constr2[40];
  bignum256 inAmount, outAmount;
  char inToken[32], outToken[32];

  // Get amount data
  bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 2 * 32, 32, &inAmount);
  bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 3 * 32, 32, &outAmount);

  if (!ethereumFormatAmount(&inAmount, in, msg->chain_id, inToken,
                            sizeof(inToken)) ||
      !ethereumFormatAmount(&outAmount, out, msg->chain_id, outToken,
                            sizeof(outToken)))
    return false;
  snprintf(constr1, 32, "%s", inToken);
  snprintf(constr2, 32, "%s", outToken);

  if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Transform ERC20",
               "Input %s\nOutput %s", constr1, constr2))
    return false;

  /* The route is executable calldata too. Showing the complete dynamic tail
   * makes transformations[] auditable instead of asking the user to trust a
   * decoder that narrates only the four static arguments. */
  return zx_confirmZxTransformRoute(
      msg->data_initial_chunk.bytes + ZX_TRANSFORM_ERC20_HEAD_LEN,
      msg->data_initial_chunk.size - ZX_TRANSFORM_ERC20_HEAD_LEN);
}

bool zx_confirmZxTransformRoute(const uint8_t* data, size_t size) {
  if (!data || size < 32) return false;
  return confirm_bytes(ButtonRequestType_ButtonRequest_ConfirmOutput,
                       "Transform Route", data, size);
}
