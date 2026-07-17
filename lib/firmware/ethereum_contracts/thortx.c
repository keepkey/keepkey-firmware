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

#include "keepkey/firmware/ethereum_contracts/thortx.h"

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/ethereum_tokens.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/thorchain.h"
#include "trezor/crypto/address.h"

bool thor_has_deposit_selector(const EthereumSignTx* msg) {
  if (msg->data_initial_chunk.size < 4) return false;
  return (memcmp(msg->data_initial_chunk.bytes, THOR_SELECTOR_DEPOSIT, 4) ==
              0 ||
          memcmp(msg->data_initial_chunk.bytes,
                 THOR_SELECTOR_DEPOSIT_WITH_EXPIRY, 4) == 0);
}

bool thor_is_expiry_variant(const EthereumSignTx* msg) {
  if (msg->data_initial_chunk.size < 4) return false;
  return memcmp(msg->data_initial_chunk.bytes,
                THOR_SELECTOR_DEPOSIT_WITH_EXPIRY, 4) == 0;
}

/* Format msg->to as lowercase hex string (40 chars + NUL) */
static void thor_format_to_addr(const EthereumSignTx* msg, char out[41]) {
  for (uint32_t i = 0; i < 20; i++) {
    snprintf(&out[i * 2], 3, "%02x", msg->to.bytes[i]);
  }
  out[40] = '\0';
}

bool thor_isMayachainTx(const EthereumSignTx* msg) {
  if (!msg->has_to || msg->to.size != 20) return false;
  /* MAYA_ROUTER is an Ethereum-mainnet identity; the same address on another
   * EVM chain may hold unrelated attacker code. Bind to mainnet so a
   * host-selected chain_id cannot borrow the trusted router UX. */
  if (!msg->has_chain_id || msg->chain_id != 1) return false;
  if (!thor_has_deposit_selector(msg)) return false;
  char toStr[41];
  thor_format_to_addr(msg, toStr);
  return strncmp(toStr, MAYA_ROUTER, 40) == 0;
}

bool thor_isThorchainTx(const EthereumSignTx* msg) {
  if (!msg->has_to || msg->to.size != 20) return false;
  /* THOR_ROUTER is an Ethereum-mainnet identity; bind to mainnet for the same
   * reason as thor_isMayachainTx above. */
  if (!msg->has_chain_id || msg->chain_id != 1) return false;
  if (!thor_has_deposit_selector(msg)) return false;
  /* Pin to the THORChain router. Without this, ANY contract carrying the
   * deposit selector would get the THORChain clear-sign UX and bypass the
   * AdvancedMode blind-sign gate, letting an attacker contract drain while the
   * device shows a benign deposit. Mirrors thor_isMayachainTx. */
  char toStr[41];
  thor_format_to_addr(msg, toStr);
  return strncmp(toStr, THOR_ROUTER, 40) == 0;
}

static bool thor_confirm_deposit_tx(uint32_t data_total,
                                    const EthereumSignTx* msg,
                                    const char* protocol_label,
                                    const char* router_label) {
  (void)data_total;

  /* Minimum calldata to read the fixed head through the memo_length word:
   * selector(4) + vault(32) + asset(32) + amount(32) + memo_offset(32) +
   * memo_length(32) = 164 bytes for deposit(), + expiry(32) = 196 for
   * depositWithExpiry(). The exact memo bounds are enforced below from the ABI
   * memo length, so a short memo (e.g. "ADD:ETH.ETH") still clear-signs rather
   * than being rejected by an over-tight fixed floor. */
  const bool is_expiry = thor_is_expiry_variant(msg);
  const size_t min_chunk = is_expiry ? 196 : 164;
  if (msg->data_initial_chunk.size < min_chunk) return false;

  /* The memo is a dynamic `string`; its ABI head pointer (word 3, offset
   * 4+3*32) must be canonical (0x80 for deposit's 4 head words, 0xa0 for
   * depositWithExpiry's 5), else abi.decode on the router reads the memo from a
   * different location than we display from the fixed offset below -> the
   * executed swap destination can differ from what the user approved. */
  {
    static const uint8_t MEMO_OFF_DEPOSIT[32] = {[31] = 0x80};
    static const uint8_t MEMO_OFF_EXPIRY[32] = {[31] = 0xa0};
    const uint8_t* expected = is_expiry ? MEMO_OFF_EXPIRY : MEMO_OFF_DEPOSIT;
    if (memcmp(msg->data_initial_chunk.bytes + 4 + 3 * 32, expected, 32) != 0) {
      return false;
    }
  }

  /* The memo is a dynamic `string`: read its ABI length word instead of
   * assuming a fixed 64 bytes. A longer memo places router-executed fields
   * (destination, affiliate, aggregator, min-out) past byte 64 that a fixed
   * parse never displays. Reject dirty high bytes, cap at THORChain's 256-byte
   * memo max, require the whole calldata to be in this chunk, and require the
   * padded memo to end exactly at the calldata end so no trailing bytes hide. */
  const uint8_t* memo_len_word =
      msg->data_initial_chunk.bytes + 4 + (is_expiry ? 5 : 4) * 32;
  for (int i = 0; i < 28; i++) {
    if (memo_len_word[i] != 0) return false;
  }
  const uint32_t memo_len = ((uint32_t)memo_len_word[28] << 24) |
                            ((uint32_t)memo_len_word[29] << 16) |
                            ((uint32_t)memo_len_word[30] << 8) |
                            (uint32_t)memo_len_word[31];
  if (memo_len > 256) return false;
  const size_t memo_off = (size_t)(4 + (is_expiry ? 6 : 5) * 32);
  const size_t memo_padded = ((memo_len + 31u) / 32u) * 32u;
  if (msg->has_data_length &&
      msg->data_length != msg->data_initial_chunk.size) {
    return false;  /* whole calldata must be in the initial chunk to bound it */
  }
  if (memo_off + memo_padded != msg->data_initial_chunk.size) {
    return false;  /* trailing bytes after the memo would be executed but hidden */
  }

  char confStr[41];
  const char* conf;
  const TokenType* assetToken;
  uint8_t* thorchainData;
  const uint8_t* contractAssetAddress;
  const uint8_t *vaultAddress, *assetAddress;
  uint32_t ctr;
  bignum256 Amount;

  vaultAddress = (const uint8_t*)(msg->data_initial_chunk.bytes + 4 + 12);
  contractAssetAddress =
      (const uint8_t*)(msg->data_initial_chunk.bytes + 4 + 32 + 12);
  bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 2 * 32, 32, &Amount);
  /* deposit(): memo at 4 + 5*32; depositWithExpiry(): memo at 4 + 6*32 */
  thorchainData =
      (uint8_t*)(msg->data_initial_chunk.bytes + 4 + (is_expiry ? 6 : 5) * 32);

  // Start confirmations
  thor_format_to_addr(msg, confStr);
  if (strncmp(confStr, THOR_ROUTER, 40) == 0) {
    conf = "Thorchain router";
  } else if (strncmp(confStr, MAYA_ROUTER, 40) == 0) {
    conf = router_label;
  } else {
    conf = confStr;
  }
  if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, protocol_label,
               "Routing through %s", conf)) {
    return false;
  }

  // just display token address and amount as string
  for (ctr = 0; ctr < 20; ctr++) {
    snprintf(&confStr[ctr * 2], 3, "%02x", vaultAddress[ctr]);
  }
  if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, protocol_label,
               "Using Asgard vault %s", confStr)) {
    return false;
  }

  /* For native ETH the router forwards msg.value and ignores the ABI amount
   * word, so the ABI amount can read 0.01 while the tx sends 100 ETH. Display
   * the value actually sent, and refuse if the ABI amount disagrees (0 is the
   * canonical "unset" and is allowed). For token deposits the router pulls via
   * transferFrom; native value must not ride along or it is swept unshown. */
  const bool is_native =
      memcmp(contractAssetAddress, ETH_ADDRESS, sizeof(ETH_ADDRESS)) == 0;
  bignum256 Value;
  bn_from_bytes(msg->value.bytes, msg->value.size, &Value);
  if (is_native) {
    if (!bn_is_zero(&Amount) && !bn_is_equal(&Amount, &Value)) {
      return false;
    }
    assetAddress = (const uint8_t*)ETH_NATIVE;
  } else {
    if (!bn_is_zero(&Value)) {
      return false;
    }
    assetAddress = contractAssetAddress;
  }
  const bignum256* displayAmount = is_native ? &Value : &Amount;

  assetToken = tokenByChainAddress(msg->chain_id, assetAddress);

  if (strncmp(assetToken->ticker, " UNKN", 5) == 0) {
    // just display token address and amount as string
    for (ctr = 0; ctr < 20; ctr++) {
      snprintf(&confStr[ctr * 2], 3, "%02x", assetAddress[ctr]);
    }
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, protocol_label,
                 "from asset %s", confStr)) {
      return false;
    }
    // We don't know what the exponent should be so just confirm raw unformatted
    // number
    bn_format(displayAmount, NULL, " unformatted", 0, 0, false, confStr,
              sizeof(confStr));

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, protocol_label,
                 "amount %s", confStr)) {
      return false;
    }

  } else {
    ethereumFormatAmount(displayAmount, assetToken, msg->chain_id, confStr,
                         sizeof(confStr));

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, protocol_label,
                 "Confirm sending %s", confStr)) {
      return false;
    }
  }

  if (!thorchain_parseConfirmMemo((const char*)thorchainData, memo_len))
    return false;

  return true;
}

bool thor_confirmThorTx(uint32_t data_total, const EthereumSignTx* msg) {
  return thor_confirm_deposit_tx(data_total, msg, "Thorchain data",
                                 "Thorchain router");
}

bool thor_confirmMayaTx(uint32_t data_total, const EthereumSignTx* msg) {
  return thor_confirm_deposit_tx(data_total, msg, "Maya data", "Maya router");
}
