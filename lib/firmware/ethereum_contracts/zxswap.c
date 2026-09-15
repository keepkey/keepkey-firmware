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
#include "keepkey/firmware/app_confirm.h"
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
                                     const TokenType** via,
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

  /* The toAddress word ends at 4 + (7 + adder) * 32, which is also the end of
   * the ABI encoding of sellToUniswap(address[],uint256,uint256,bool):
   * 4 + 4 head words + the array length word + numOfTokens address words.
   * 228 bytes for a two-token swap, 260 for three.
   *
   * A lower bound and not an equality, deliberately. Real 0x quotes append 68
   * bytes past the ABI extent -- a `869584cd` tag, an affiliate address and a
   * nonce word -- and both pinned integration vectors carry it (296 bytes for
   * a 228-byte call). Requiring equality here would drop every genuine 0x swap
   * to the blind-sign path, which trains users into AdvancedMode and is a worse
   * outcome than the thing it fixes.
   *
   * That suffix is still signed, so it is not ignored either: it cannot be
   * silently dropped, and zx_confirmZxSwap() below discloses whatever lies past
   * this point on its own screen before the trade is approved. */
  const size_t tokens_end = (size_t)(4 + (7 + adder) * 32);
  if (msg->data_initial_chunk.size < tokens_end) return false;

  const TokenType* f = tokenByChainAddress(
      msg->chain_id, msg->data_initial_chunk.bytes + 4 + 5 * 32 + 12);
  const TokenType* t = tokenByChainAddress(
      msg->chain_id, msg->data_initial_chunk.bytes + 4 + (6 + adder) * 32 + 12);

  /* The MIDDLE token of a three-token route, which the screen used to omit.
   *
   * sellToUniswap() executes one swap per adjacent pair, so tokens[1] selects
   * the pair contracts the trade actually routes through. Reading only
   * tokens[0] and tokens[last] meant every tokens[1] produced the same
   * "Sell X / Buy at least Y" screen while the route underneath it changed --
   * a different set of pools, a different counterparty, the same approval.
   *
   * Resolve it on the same terms as the endpoints, and hold it to the same
   * chain-scoped check: an unresolvable hop makes the whole call
   * undisplayable, so it falls through to the AdvancedMode raw-calldata path
   * rather than being shown as a two-token trade it is not. */
  const TokenType* v = NULL;
  if (adder) {
    v = tokenByChainAddress(msg->chain_id,
                            msg->data_initial_chunk.bytes + 4 + 6 * 32 + 12);
    if (!zx_tokenLabelsThisChain(msg->chain_id, v)) return false;
  }

  /* Not just "resolved" -- resolved to metadata for this exact chain.  The
   * lookup is chain-scoped, and this second check keeps the decoder fail-closed
   * if a future caller ever supplies metadata directly. */
  if (!zx_tokenLabelsThisChain(msg->chain_id, f) ||
      !zx_tokenLabelsThisChain(msg->chain_id, t))
    return false;

  if (from) *from = f;
  if (via) *via = v;
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
  return zxswap_resolveBothTokens(msg, NULL, NULL, NULL, NULL);
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

  const TokenType *from, *via, *to;
  const char* exchange;
  if (!zxswap_resolveBothTokens(msg, &from, &via, &to, &exchange)) return false;

  char constr1[40], constr2[40];

  // Get token trade amount data
  bignum256 sellTokenAmount, minBuyTokenAmount;
  bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 32, 32, &sellTokenAmount);
  bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 2 * 32, 32,
                &minBuyTokenAmount);

  char sellToken[32];
  char minBuyToken[32];
  if (!ethereumFormatAmount(&sellTokenAmount, from, msg->chain_id, sellToken,
                            sizeof(sellToken)))
    return false;
  if (!ethereumFormatAmount(&minBuyTokenAmount, to, msg->chain_id, minBuyToken,
                            sizeof(minBuyToken)))
    return false;

  snprintf(constr1, 32, "%s", sellToken);
  snprintf(constr2, 32, "%s", minBuyToken);

  if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, exchange,
               "Sell %s\nBuy at least %s", constr1, constr2)) {
    return false;
  }

  /* Name the intermediate hop on its own screen. The amounts above bound only
     the ends of the route; this is the asset the trade passes through, and it
     is as much a part of what is being signed as they are.

     Tickers in the generated table lead with a space (" USDC") because
     ethereumFormatAmount() appends them straight after a number. Step over it
     rather than emitting "Route via  USDC". */
  if (via) {
    const char* via_ticker = via->ticker ? via->ticker : "";
    while (*via_ticker == ' ') via_ticker++;
    if (*via_ticker == '\0') return false;
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, exchange,
                 "Route via %s", via_ticker)) {
      return false;
    }
  }

  /* Anything past the ABI encoding is signed but describes nothing this screen
   * asserted. In practice it is 0x's 68-byte affiliate suffix, present on every
   * quote their API returns, which is why refusing it outright is not an option
   * -- see zxswap_resolveBothTokens(). It is host-supplied all the same, so
   * show it rather than vouch for it: confirm_bytes() takes an explicit length
   * and escapes every non-printable byte, so nothing hides behind a NUL.
   *
   * Recompute the extent from the token count rather than threading it out of
   * the resolver, so this bound and the one that gated the reads above cannot
   * drift apart. */
  {
    const uint32_t numOfTokens =
        read_be(msg->data_initial_chunk.bytes + 4 + 5 * 32 - 4);
    const size_t abi_end = (size_t)(4 + (7 + (numOfTokens == 3 ? 1 : 0)) * 32);
    if (msg->data_initial_chunk.size > abi_end) {
      if (!confirm_bytes(ButtonRequestType_ButtonRequest_Other,
                         "Extra calldata",
                         msg->data_initial_chunk.bytes + abi_end,
                         msg->data_initial_chunk.size - abi_end)) {
        return false;
      }
    }
  }

  return true;
}
