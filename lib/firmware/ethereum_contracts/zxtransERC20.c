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

/* Resolve both traded assets, or refuse.
 *
 * This is the whole basis on which transformERC20 is clear-signable. The
 * decoder shows four values and hides the transformations[] body; that is only
 * defensible because the input amount and the minimum output amount bound the
 * outcome. A bound the user cannot read is not a bound, and
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
  /* The two address words end at byte 68, but the confirm also reads the two
   * amount words, so require what the confirm requires. Past .size the chunk
   * buffer still holds bytes from an earlier message. */
  if (msg->data_initial_chunk.size < 4 + 4 * 32) return false;

  const TokenType* i = tokenByChainAddress(
      msg->chain_id, msg->data_initial_chunk.bytes + 4 + 12);
  const TokenType* o = tokenByChainAddress(
      msg->chain_id, msg->data_initial_chunk.bytes + 4 + 32 + 12);

  if (i == NULL || o == NULL || i == UnknownToken || o == UnknownToken)
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
  if (!msg->has_chain_id || !zx_isExchangeProxyChain(msg->chain_id))
    return false;
  if (memcmp(msg->to.bytes, ZXSWAP_ADDRESS, 20) != 0) return false;
  if (!isTransERC20Call(msg)) return false;

  /* Claim the transaction only if the screen can name both assets. Refusing
     here is what makes it fall through to the raw-calldata path, which is
     AdvancedMode-gated and shows the bytes; refusing in the confirm would be
     read as a user cancel (see ethereum.c, ethereum_contractConfirmed). */
  return resolveBothTokens(msg, NULL, NULL);
}

bool zx_confirmZxTransERC20(uint32_t data_total, const EthereumSignTx* msg) {
  (void)data_total;

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
  if (!resolveBothTokens(msg, &in, &out)) return false;

  char constr1[40], constr2[40];
  bignum256 inAmount, outAmount;
  char inToken[32], outToken[32];

  // Get amount data
  bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 2 * 32, 32, &inAmount);
  bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 3 * 32, 32, &outAmount);

  ethereumFormatAmount(&inAmount, in, msg->chain_id, inToken, sizeof(inToken));
  ethereumFormatAmount(&outAmount, out, msg->chain_id, outToken,
                       sizeof(outToken));
  snprintf(constr1, 32, "%s", inToken);
  snprintf(constr2, 32, "%s", outToken);

  return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Transform ERC20", "Input %s\nOutput %s", constr1, constr2);
}
