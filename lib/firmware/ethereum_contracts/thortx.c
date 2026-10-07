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

static void thor_format_to_addr(const EthereumSignTx* msg, char out[41]) {
  for (uint32_t i = 0; i < 20; i++) {
    snprintf(&out[i * 2], 3, "%02x", msg->to.bytes[i]);
  }
  out[40] = '\0';
}

bool thor_isMayachainTx(const EthereumSignTx* msg) {
  if (!msg->has_to || msg->to.size != 20) return false;
  /* MAYA_ROUTER is a mainnet identity; other chains may hold attacker code. */
  if (!msg->has_chain_id || msg->chain_id != 1) return false;
  if (!thor_has_deposit_selector(msg)) return false;
  char toStr[41];
  thor_format_to_addr(msg, toStr);
  return strncmp(toStr, MAYA_ROUTER, 40) == 0;
}

/* Router pinned by (chain_id, address), or NULL (blind-sign gate). No
 * chain_id means no router: a pin is never inherited from a default. */
static const char* thor_router_for_chain(const EthereumSignTx* msg) {
  if (!msg->has_chain_id) return NULL;
  switch (msg->chain_id) {
    case 1:
      return THOR_ROUTER; /* Ethereum */
    case 43114:
      return THOR_ROUTER_AVAX; /* Avalanche C-Chain */
    default:
      return NULL;
  }
}

bool thor_isThorchainTx(const EthereumSignTx* msg) {
  if (!msg->has_to || msg->to.size != 20) return false;
  if (!thor_has_deposit_selector(msg)) return false;
  /* Pin to the THORChain router FOR THIS CHAIN. Without the pin, ANY contract
   * carrying the deposit selector would get the THORChain clear-sign UX and
   * bypass the AdvancedMode blind-sign gate, letting an attacker contract
   * drain funds while the device shows a benign deposit. Without the chain
   * scope, only mainnet deposits ever match (the AVAX->ETH blind-sign bug). */
  const char* router = thor_router_for_chain(msg);
  if (!router) return false;
  char toStr[41];
  thor_format_to_addr(msg, toStr);
  return strncmp(toStr, router, 40) == 0;
}

static bool thor_confirm_deposit_tx(uint32_t data_total,
                                    const EthereumSignTx* msg,
                                    const char* protocol_label,
                                    const char* router_label) {
  (void)data_total;

  /* Head through memo_length: 4 + 5*32 = 164 (deposit), +32 = 196 with
   * expiry. Exact memo bounds are enforced below. */
  const bool is_expiry = thor_is_expiry_variant(msg);
  const size_t min_chunk = is_expiry ? 196 : 164;
  if (msg->data_initial_chunk.size < min_chunk) return false;

  /* Memo head pointer must be canonical (0x80 / 0xa0 with expiry), else the
   * router decodes a different memo than the one displayed. */
  {
    static const uint8_t MEMO_OFF_DEPOSIT[32] = {[31] = 0x80};
    static const uint8_t MEMO_OFF_EXPIRY[32] = {[31] = 0xa0};
    const uint8_t* expected = is_expiry ? MEMO_OFF_EXPIRY : MEMO_OFF_DEPOSIT;
    if (memcmp(msg->data_initial_chunk.bytes + 4 + 3 * 32, expected, 32) != 0) {
      return false;
    }
  }

  /* Use the ABI memo length (cap 256, clean high bytes); the padded memo must
   * end exactly at the calldata end so no executed bytes go unshown. */
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
    return false; /* whole calldata must be in the initial chunk to bound it */
  }
  if (memo_off + memo_padded != msg->data_initial_chunk.size) {
    return false; /* trailing bytes would execute unseen */
  }

  /* Tail padding is signed but not shown: it must be zero. */
  for (size_t i = memo_off + memo_len; i < memo_off + memo_padded; i++) {
    if (msg->data_initial_chunk.bytes[i] != 0) return false;
  }

  char confStr[41];
  const char* conf;
  uint8_t* thorchainData;
  const uint8_t* contractAssetAddress;
  const uint8_t* vaultAddress;
  uint32_t ctr;
  bignum256 Amount;

  vaultAddress = (const uint8_t*)(msg->data_initial_chunk.bytes + 4 + 12);
  contractAssetAddress =
      (const uint8_t*)(msg->data_initial_chunk.bytes + 4 + 32 + 12);
  bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 2 * 32, 32, &Amount);
  /* deposit(): memo at 4 + 5*32; depositWithExpiry(): memo at 4 + 6*32 */
  thorchainData =
      (uint8_t*)(msg->data_initial_chunk.bytes + 4 + (is_expiry ? 6 : 5) * 32);

  /* Render the amount before any confirm. The routers treat ONLY address(0)
   * as native (not 0xEeee..Ee); compare 20 bytes, not sizeof (NUL). */
  const bool is_native = memcmp(contractAssetAddress, ETH_ADDRESS, 20) == 0;
  bignum256 Value;
  bn_from_bytes(msg->value.bytes, msg->value.size, &Value);
  char amountStr[41];
  const TokenType* assetToken = NULL;
  bool is_unknown = false;
  if (is_native) {
    /* Show msg.value (what the router forwards), not the ignored ABI amount;
     * NULL token so the ticker is this chain's native asset. */
    if (!ethereumFormatAmount(&Value, NULL, msg->chain_id, amountStr,
                              sizeof(amountStr)))
      return false;
  } else {
    /* Token deposits must carry no native value: it would go unshown. */
    if (!bn_is_zero(&Value)) {
      return false;
    }
    assetToken = tokenByChainAddress(msg->chain_id, contractAssetAddress);
    is_unknown = strncmp(assetToken->ticker, " UNKN", 5) == 0;
    if (is_unknown) {
      // We don't know what the exponent should be so just confirm raw
      // unformatted number
      if (bn_format(&Amount, NULL, " unformatted", 0, 0, false, amountStr,
                    sizeof(amountStr)) == 0)
        return false;
    } else {
      if (!ethereumFormatAmount(&Amount, assetToken, msg->chain_id, amountStr,
                                sizeof(amountStr)))
        return false;
    }
  }

  /* depositWithExpiry() carries a fifth head word the deposit() variant does
   * not: the expiry. It was validated into the length arithmetic and signed,
   * but no screen ever named it, so a host could pick any 256-bit value while
   * this decoder suppressed the raw-calldata review that would have shown it.
   * An expiry is a deadline -- it decides whether the swap can still execute
   * -- so it has to be on screen.
   *
   * Rendered as a decimal epoch for the same reason as the Uniswap deadline
   * (zxliquidtx.c): ctime() on this target reads only the low 4 bytes of a
   * 64-bit time_t. Words above 2^64 are refused rather than shown truncated,
   * because a far-future expiry displayed as a small epoch is worse than no
   * screen at all -- it reads as "already expired" when it means the
   * opposite. */
  char expiry_str[21] = {0};
  if (is_expiry) {
    const uint8_t* expiry_word = msg->data_initial_chunk.bytes + 4 + 4 * 32;
    for (size_t i = 0; i < 24; i++) {
      if (expiry_word[i] != 0) return false;
    }
    uint64_t expiry = 0;
    for (size_t i = 24; i < 32; i++) {
      expiry = (expiry << 8) | expiry_word[i];
    }

    char tmp[21];
    int len = 0;
    if (expiry == 0) {
      tmp[len++] = '0';
    } else {
      while (expiry > 0 && len < (int)sizeof(tmp)) {
        tmp[len++] = (char)('0' + (int)(expiry % 10));
        expiry /= 10;
      }
    }
    for (int i = 0; i < len; i++) {
      expiry_str[i] = tmp[len - 1 - i];
    }
  }

  // Start confirmations
  thor_format_to_addr(msg, confStr);
  const char* thor_router = thor_router_for_chain(msg);
  if (thor_router && strncmp(confStr, thor_router, 40) == 0) {
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

  if (is_unknown) {
    for (ctr = 0; ctr < 20; ctr++) {
      snprintf(&confStr[ctr * 2], 3, "%02x", contractAssetAddress[ctr]);
    }
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, protocol_label,
                 "from asset %s", confStr)) {
      return false;
    }
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, protocol_label,
                 "amount %s", amountStr)) {
      return false;
    }
  } else {
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, protocol_label,
                 "Confirm sending %s", amountStr)) {
      return false;
    }
  }

  if (is_expiry && !confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                            protocol_label, "Expiry epoch %s", expiry_str)) {
    return false;
  }

  const ThorchainMemoResult memo_result =
      thorchain_parseConfirmMemo((const char*)thorchainData, memo_len);
  if (memo_result == THORCHAIN_MEMO_CANCELLED) return false;

  /* Page the full raw memo: structured fields may truncate. */
  if (!thorchain_confirm_full_memo("Memo", (const char*)thorchainData,
                                   memo_len))
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
