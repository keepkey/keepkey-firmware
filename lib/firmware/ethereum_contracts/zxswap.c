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

#include "keepkey/firmware/ethereum_contracts/zxswap.h"

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/ethereum_contracts.h"
#include "keepkey/firmware/ethereum_tokens.h"
#include "keepkey/firmware/fsm.h"
#include "trezor/crypto/address.h"

static bool isSellToUniswapCall(const EthereumSignTx* msg) {
  if (memcmp(msg->data_initial_chunk.bytes, "\xd9\x62\x7a\xa4", 4) == 0)
    return true;

  return false;
}

/* Decode the head far enough to name both traded assets, or refuse.
 *
 * Everything the screen asserts about this trade -- which asset is sold, which
 * is bought, and the amounts that bound it -- depends on both lookups landing.
 * ethereumFormatAmount() renders the literal "Unknown token value" when
 * tokenByChainAddress() misses, so an unresolved token produces a screen that
 * states no amount while the calldata executes: a blind signature with a
 * decoder's title.
 *
 * The generated token table has 1924 entries for chain 1, three each for BSC
 * and Polygon, and none for Base, Arbitrum or Avalanche. Gating on the lookup
 * rather than on a chain allowlist stays correct however those tables change.
 *
 * Shared by the predicate and the confirm so the two cannot disagree about what
 * is displayable.
 */
static bool zxswap_resolveBothTokens(const EthereumSignTx* msg,
                                     const TokenType** from,
                                     const TokenType** to,
                                     const char** exchange) {
  /* Everything read before the token count is known lives in the selector plus
   * the first five words. Bound against the RECEIVED chunk: past .size the
   * buffer still holds bytes from an earlier message, which would otherwise be
   * shown as this transaction's amounts. */
  if (msg->data_initial_chunk.size < 4 + 5 * 32) return false;

  /* Head word 0 is the ABI offset pointer to the dynamic `tokens[]` argument.
   * The token count and the token addresses are read below at FIXED offsets
   * that are only where the router's decoder will look when that pointer is
   * canonical (0x80 == four head words). A host is free to place the array
   * anywhere; if it does, the screen would describe words the contract never
   * executes. Refuse to clear-sign a non-canonical encoding. */
  if (memcmp(msg->data_initial_chunk.bytes + 4,
             "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
             "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80",
             32) != 0) {
    return false;
  }

  const uint32_t numOfTokens =
      read_be(msg->data_initial_chunk.bytes + 4 + 5 * 32 - 4);
  const uint32_t isSushi =
      read_be(msg->data_initial_chunk.bytes + 4 + 4 * 32 - 4);

  uint32_t adder;
  switch (numOfTokens) {
    case 2:
      adder = 0;  // only two tokens, swap to token second
      break;
    case 3:
      adder = 1;  // swap to token last in the list of 3
      break;
    default:  // can't interpret 0, 1, or >3 tokens
      return false;
  }

  /* The toAddress word ends at 4 + (7 + adder) * 32. Re-bound now that the
   * token count is known, so a legitimate 2-token swap (228 bytes of calldata)
   * is not rejected by an over-tight fixed floor. */
  const size_t tokens_end = (size_t)(4 + (7 + adder) * 32);
  if (msg->data_initial_chunk.size < tokens_end) return false;

  const TokenType* f = tokenByChainAddress(
      msg->chain_id, msg->data_initial_chunk.bytes + 4 + 5 * 32 + 12);
  const TokenType* t = tokenByChainAddress(
      msg->chain_id, msg->data_initial_chunk.bytes + 4 + (6 + adder) * 32 + 12);

  if (f == NULL || t == NULL || f == UnknownToken || t == UnknownToken)
    return false;

  if (from) *from = f;
  if (to) *to = t;
  if (exchange) *exchange = (isSushi == 0) ? "Uniswap" : "Sushiswap";
  return true;
}

bool zx_isZxSwap(const EthereumSignTx* msg) {
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
  if (!isSellToUniswapCall(msg)) return false;

  /* Claim the transaction only if the screen can name both assets. Refusing
     here is what makes it fall through to the raw-calldata path, which is
     AdvancedMode-gated and shows the bytes; refusing in the confirm would be
     read as a user cancel (see ethereum.c, ethereum_contractConfirmed). */
  return zxswap_resolveBothTokens(msg, NULL, NULL, NULL);
}

bool zx_confirmZxSwap(uint32_t data_total, const EthereumSignTx* msg) {
  (void)data_total;

  /* Everything read before the token count is known lives in the selector plus
   * the first five words. Bound against the RECEIVED chunk: past .size the
   * buffer still holds bytes from an earlier message, which would otherwise be
   * shown as this transaction's amounts. */
  if (msg->data_initial_chunk.size < 4 + 5 * 32) return false;

  /* Head word 0 is the ABI offset pointer to the dynamic `tokens[]` argument.
   * The token count and the token addresses are read below at FIXED offsets
   * that are only where the router's decoder will look when that pointer is
   * canonical (0x80 == four head words). A host is free to place the array
   * anywhere; if it does, the screen would describe words the contract never
   * executes. Refuse to clear-sign a non-canonical encoding. */
  if (memcmp(msg->data_initial_chunk.bytes + 4,
             "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
             "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80",
             32) != 0) {
    return false;
  }

  const TokenType *from, *to;
  const char* exchange;
  if (!zxswap_resolveBothTokens(msg, &from, &to, &exchange)) return false;

  char constr1[40], constr2[40];

  // Get token trade amount data
  bignum256 sellTokenAmount, minBuyTokenAmount;
  bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 32, 32, &sellTokenAmount);
  bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 2 * 32, 32,
                &minBuyTokenAmount);

  char sellToken[32];
  char minBuyToken[32];
  ethereumFormatAmount(&sellTokenAmount, from, msg->chain_id, sellToken,
                       sizeof(sellToken));
  ethereumFormatAmount(&minBuyTokenAmount, to, msg->chain_id, minBuyToken,
                       sizeof(minBuyToken));

  snprintf(constr1, 32, "%s", sellToken);
  snprintf(constr2, 32, "%s", minBuyToken);

  return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, exchange,
                 "Sell %s\nBuy at least %s", constr1, constr2);
}
