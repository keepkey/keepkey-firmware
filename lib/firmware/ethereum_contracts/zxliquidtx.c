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
#include "keepkey/board/util.h"
#include "keepkey/firmware/app_confirm.h"
#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/ethereum_tokens.h"
#include "trezor/crypto/bip32.h"

#include <time.h>

static bool isAddLiquidityEthCall(const EthereumSignTx* msg) {
  if (memcmp(msg->data_initial_chunk.bytes, "\xf3\x05\xd7\x19", 4) == 0)
    return true;

  return false;
}

static bool isRemoveLiquidityEthCall(const EthereumSignTx* msg) {
  if (memcmp(msg->data_initial_chunk.bytes, "\x02\x75\x1c\xec", 4) == 0)
    return true;

  return false;
}

static bool confirmFromAccountMatch(const EthereumSignTx* msg,
                                    const char* addremStr, const HDNode* node) {
  // Determine withdrawal address
  char addressStr[43] = {'0', 'x', '\0'};
  const char* fromSrc;
  const uint8_t* fromAddress;
  uint8_t addressBytes[20];

  if (!node) return false;

  if (!hdnode_get_ethereum_pubkeyhash(node, addressBytes)) return false;

  fromAddress =
      (const uint8_t*)(msg->data_initial_chunk.bytes + 4 + 5 * 32 - 20);

  if (memcmp(fromAddress, addressBytes, 20) == 0) {
    fromSrc = "self";
  } else {
    fromSrc = "NOT this wallet";
  }

  for (uint32_t ctr = 0; ctr < 20; ctr++) {
    snprintf(&addressStr[2 + ctr * 2], 3, "%02x", fromAddress[ctr]);
  }

  if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, addremStr,
               "Confirming ETH address is %s: %s", fromSrc, addressStr)) {
    return false;
  }
  return true;
}

/* Decode the head far enough to name the pool token, or refuse.
 *
 * Both screens this handler draws state a token amount and a token minimum,
 * and both come from ethereumFormatAmount(), which renders the literal
 * "Unknown token value" when tokenByChainAddress() misses. An unlisted pool
 * token therefore produces a screen that asserts no amount at all while the
 * calldata executes: a blind signature wearing a decoder's title. Worse than
 * the generic case, because claiming the transaction here is exactly what
 * skips the AdvancedMode raw-calldata fallback that would have shown the
 * bytes.
 *
 * Refuse in the PREDICATE, not the confirm: ethereum.c reads a false return
 * from ethereum_contractConfirmed() as a user cancel, while a false predicate
 * falls through to raw disclosure. Same split as zxswap.c and zxtransERC20.c.
 *
 * Shared by the predicate and the confirm so the two cannot disagree about
 * what is displayable.
 */
static bool zxliquid_resolveToken(const EthereumSignTx* msg,
                                  const TokenType** token) {
  /* addLiquidityETH / removeLiquidityETH are both
   *   (address, uint256, uint256, uint256, address, uint256)
   * with no dynamic argument, so the calldata is exactly 4 + 6 * 32 = 196
   * bytes. Everything this handler reads -- the token at offset 16, three
   * amounts, the `to` address at 144, and the deadline at 188 -- lies inside
   * it.
   *
   * Exactly 196, in both directions. Short, and the confirm would read bytes
   * an earlier message left in the chunk buffer past .size and show them as
   * this transaction's amounts and deadline. Long, and the extra words are
   * hashed into the signature with no screen showing them. */
  if (msg->data_initial_chunk.size != 4 + 6 * 32) return false;

  /* The deadline is a full uint256, but the screen renders only its low 64
   * bits (see the epoch formatter in zx_confirmZxLiquidTx). Anything set above
   * bit 63 is therefore invisible: a deadline of 2^64 + 1 is effectively
   * "never expires", and the device would state "Deadline epoch 1" -- a
   * long-past time, the opposite of what the router will enforce.
   *
   * Require the upper 24 bytes to be zero rather than widen the formatter. A
   * real Uniswap deadline is a Unix timestamp and fits comfortably; a word that
   * does not is not something this screen can describe, so it belongs on the
   * raw-calldata path. Checked in the resolver, which the PREDICATE calls, so
   * the refusal falls through to disclosure instead of being reported as a
   * user cancel. */
  const uint8_t* deadline_word =
      (const uint8_t*)(msg->data_initial_chunk.bytes + 4 + 5 * 32);
  for (size_t i = 0; i < 24; i++) {
    if (deadline_word[i] != 0) return false;
  }

  const TokenType* t = tokenByChainAddress(
      msg->chain_id,
      (const uint8_t*)(msg->data_initial_chunk.bytes + 4 + 32 - 20));
  if (t == NULL || t == UnknownToken) return false;

  if (token) *token = t;
  return true;
}

bool zx_isZxLiquidTx(const EthereumSignTx* msg) {
  /* UNISWAP_ROUTER_ADDRESS is an Ethereum-mainnet identity. The same 20 bytes
   * on another EVM chain are an unrelated contract; clear-sign only on mainnet.
   * See GH #431. */
  if (!msg->has_chain_id || msg->chain_id != 1) return false;
  if (memcmp(msg->to.bytes, UNISWAP_ROUTER_ADDRESS, 20) !=
      0)  // correct contract address?
    return false;

  if (!isAddLiquidityEthCall(msg) && !isRemoveLiquidityEthCall(msg))
    return false;

  /* Claim the transaction only if the screen can name the pool token. */
  return zxliquid_resolveToken(msg, NULL);
}

bool zx_confirmZxLiquidTx(uint32_t data_total, const EthereumSignTx* msg,
                          const HDNode* node) {
  (void)data_total;
  const TokenType* token;
  char constr1[40], constr2[40], constr3[40], tokbuf[32];
  const char* arStr = "";
  const uint8_t* deadlineBytes;
  bignum256 Amount;
  uint64_t deadline;

  if (isAddLiquidityEthCall(msg)) {
    arStr = "uniswap add liquidity";
  } else if (isRemoveLiquidityEthCall(msg)) {
    arStr = "uniswap remove liquidity";
  } else {
    return false;
  }

  /* Re-resolve rather than trust the predicate's verdict from a distance: the
     length bound and the token lookup are the preconditions for every read
     below, so they belong on the same code path that performs them. */
  if (!zxliquid_resolveToken(msg, &token)) return false;
  deadlineBytes =
      (const uint8_t*)(msg->data_initial_chunk.bytes + 4 + 6 * 32 - 8);
  deadline = ((uint64_t)deadlineBytes[0] << 8 * 7) |
             ((uint64_t)deadlineBytes[1] << 8 * 6) |
             ((uint64_t)deadlineBytes[2] << 8 * 5) |
             ((uint64_t)deadlineBytes[3] << 8 * 4) |
             ((uint64_t)deadlineBytes[4] << 8 * 3) |
             ((uint64_t)deadlineBytes[5] << 8 * 2) |
             ((uint64_t)deadlineBytes[6] << 8 * 1) |
             ((uint64_t)deadlineBytes[7]);

  bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 32, 32,
                &Amount);  // token amount
  if (!ethereumFormatAmount(&Amount, token, msg->chain_id, tokbuf,
                            sizeof(tokbuf)))
    return false;
  snprintf(constr1, 32, "%s", tokbuf);
  bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 2 * 32, 32,
                &Amount);  // token min amount
  if (!ethereumFormatAmount(&Amount, token, msg->chain_id, tokbuf,
                            sizeof(tokbuf)))
    return false;
  snprintf(constr2, 32, "%s", tokbuf);

  /* Validate every amount before drawing the first approval screen. A later
   * formatting failure must not leave the user with a partial review flow. */
  bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 3 * 32, 32,
                &Amount);  // eth min amount
  if (!ethereumFormatAmount(&Amount, NULL, msg->chain_id, tokbuf,
                            sizeof(tokbuf)))
    return false;
  snprintf(constr3, 32, "%s", tokbuf);

  if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, arStr,
               "%s\nMinimum %s", constr1, constr2)) {
    return false;
  }
  if (!confirmFromAccountMatch(msg, arStr, node)) {
    return false;
  }

  if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, arStr,
               "Minimum %s", constr3)) {
    return false;
  }

  /* Render the 64-bit deadline as a decimal epoch string. The prior code
   * used ctime((const time_t*)&deadline), which on the STM32F2 target reads
   * only the low 4 bytes of the 64-bit deadline (time_t is 32-bit long), so
   * post-2038 deadlines render as the wrong date. The decimal epoch is
   * unambiguous and avoids the 32-bit time_t truncation and ctime()'s stray
   * newline. See GH #435. */
  {
    char deadline_str[21] = {0};
    /* uint64 -> decimal string (manual, no printf %llu portability concerns) */
    uint64_t d = deadline;
    char tmp[21];
    int len = 0;
    if (d == 0) {
      tmp[len++] = '0';
    } else {
      while (d > 0 && len < (int)sizeof(tmp)) {
        tmp[len++] = '0' + (int)(d % 10);
        d /= 10;
      }
    }
    for (int i = 0; i < len; i++) {
      deadline_str[i] = tmp[len - 1 - i];
    }
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, arStr,
                 "Deadline epoch %s", deadline_str)) {
      return false;
    }
  }

  return true;
}
