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

#include "keepkey/firmware/ethereum_contracts/saproxy.h"

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/ethereum_tokens.h"
#include "keepkey/firmware/fsm.h"
#include "trezor/crypto/address.h"

static bool isWithFromSalary(const EthereumSignTx* msg) {
  if (memcmp(msg->data_initial_chunk.bytes, "\xfe\xa7\xc5\x3f", 4) == 0)
    return true;

  return false;
}

/* withdrawFromSalary(uint256,uint256) has no dynamic arguments, so its
 * calldata is exactly 4 + 2 * 32 = 68 bytes and both words sit at fixed head
 * positions. Exactly 68, not at least 68: past .size the chunk buffer still
 * holds bytes from an earlier message, and a longer calldata is hashed in full
 * by the signer while only these two words are drawn.
 *
 * Shared by the predicate and the confirm so the two cannot disagree about
 * what is displayable. */
static bool sa_withdrawFromSalaryExtentOk(const EthereumSignTx* msg) {
  return msg->data_initial_chunk.size == 4 + 2 * 32;
}

bool sa_formatUint256(const uint8_t word[32], const char* suffix, char* out,
                      size_t out_len) {
  if (!word || !suffix || !out || out_len == 0) return false;
  bignum256 value;
  bn_from_bytes(word, 32, &value);
  return bn_format(&value, NULL, suffix, 0, 0, false, out, out_len) != 0;
}

bool sa_isWithdrawFromSalary(const EthereumSignTx* msg) {
  /* SAPROXY_ADDRESS is an Ethereum-mainnet identity. See GH #431. */
  if (!msg->has_chain_id || msg->chain_id != 1) return false;
  if (memcmp(msg->to.bytes, SAPROXY_ADDRESS, 20) ==
      0) {                        // correct proxy address?
    if (isWithFromSalary(msg)) {  // does kk handle call?
      /* The extent has to be checked HERE, not only in the confirm.
       * ethereum.c reads a false return from ethereum_contractConfirmed() as a
       * user cancel and aborts; only a false PREDICATE falls through to the
       * AdvancedMode raw-calldata path. Claiming the call and then refusing it
       * turns "this device cannot show you the whole thing" into "you pressed
       * cancel", which is both wrong and unrecoverable for the host. */
      return sa_withdrawFromSalaryExtentOk(msg);
    }
  }
  return false;
}

bool sa_confirmWithdrawFromSalary(uint32_t data_total,
                                  const EthereumSignTx* msg) {
  (void)data_total;

  /* Belt and braces: the predicate already required this, and the two must not
   * be able to drift apart. See sa_withdrawFromSalaryExtentOk(). */
  if (!sa_withdrawFromSalaryExtentOk(msg)) return false;

  char confStr[41];
  // confirm raw unformatted numbers
  /* bn_format() BLANKS its output buffer and returns 0 when the value does
   * not fit -- ignoring the return renders an EMPTY amount on the
   * confirmation screen, the one rendering a user cannot read as wrong. */
  if (!sa_formatUint256(msg->data_initial_chunk.bytes + 4, "", confStr,
                        sizeof(confStr)))
    return false;
  if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Sablier",
               "Salary ID %s", confStr)) {
    return false;
  }

  // confirm raw unformatted numbers
  if (!sa_formatUint256(msg->data_initial_chunk.bytes + 4 + 32, " Token Units",
                        confStr, sizeof(confStr)))
    return false;
  if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Sablier",
               "Withdraw Amount %s", confStr)) {
    return false;
  }
  return true;
}
