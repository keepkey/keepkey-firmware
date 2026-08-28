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

static bool thor_assetIsNative(const uint8_t asset_address[20]) {
  return asset_address != NULL && memcmp(asset_address, ETH_ADDRESS, 20) == 0;
}

static bool thor_formatUnknownAssetAmount(const uint8_t word[32], char* out,
                                          size_t out_len) {
  if (!word || !out || out_len == 0) return false;
  bignum256 amount;
  bn_from_bytes(word, 32, &amount);
  return bn_format(&amount, NULL, " unformatted", 0, 0, false, out, out_len) !=
         0;
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

/* The THORChain router address for this tx's chain, or NULL if the chain has
 * no pinned router (then the deposit is not clear-signed and falls to the
 * blind-sign gate). Each router address is a per-chain identity — the same
 * address on another chain may hold unrelated attacker code — so the pin is
 * (chain_id, address) together. A tx with NO chain_id gets no router at all:
 * ethereum.c would default it to mainnet for hashing, but an identity pin
 * must never be inherited from a default the host simply omitted. */
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
   * drain while the device shows a benign deposit. Without the chain scope,
   * only mainnet deposits ever match (the AVAX->ETH blind-sign bug). */
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
   * padded memo to end exactly at the calldata end so no trailing bytes hide.
   */
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
  if (data_total != msg->data_initial_chunk.size) {
    return false; /* whole calldata must be in the initial chunk to bound it;
                     unconditional, so a message that simply omits data_length
                     cannot skip the bound */
  }
  if (memo_off + memo_padded != msg->data_initial_chunk.size) {
    return false; /* trailing bytes after the memo would be executed but hidden
                   */
  }

  char confStr[41];
  const char* conf;
  const TokenType* assetToken;
  uint8_t* thorchainData;
  const uint8_t* contractAssetAddress;
  const uint8_t *vaultAddress, *assetAddress;
  uint32_t ctr;
  bignum256 Amount, Value;

  vaultAddress = (const uint8_t*)(msg->data_initial_chunk.bytes + 4 + 12);
  contractAssetAddress =
      (const uint8_t*)(msg->data_initial_chunk.bytes + 4 + 32 + 12);
  bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 2 * 32, 32, &Amount);
  bn_from_bytes(msg->value.bytes, msg->value.size, &Value);
  /* deposit(): memo at 4 + 5*32; depositWithExpiry(): memo at 4 + 6*32 */
  thorchainData =
      (uint8_t*)(msg->data_initial_chunk.bytes + 4 + (is_expiry ? 6 : 5) * 32);

  /* Everything non-interactive FIRST, so an unrenderable call fails before any
   * approval is taken.
   *
   * The amount used to be formatted after the router, vault and asset screens
   * had been approved, and the expiry word validated after that. bn_format()
   * refuses a value it cannot render, and ethereum.c turns a false return from
   * this decoder into ActionCancelled -- so a large but valid amount, or a
   * non-canonical expiry, told the owner they had cancelled a transaction they
   * had already approved three screens of. Resolve the asset, render the
   * amount, and check the expiry up here; the confirmations below then only
   * display what is already known to be displayable. */
  assetAddress = contractAssetAddress;
  /* The THORChain ABI uses the zero address to mean this signing chain's
   * native asset.  Resolve that router-specific meaning directly instead of
   * routing it through the Ethereum-only 0xeeee..eeee token sentinel.  A NULL
   * token makes ethereumFormatAmount() select the native ticker from chain_id.
   */
  const bool is_native = thor_assetIsNative(contractAssetAddress);
  if (is_native) {
    assetToken = NULL;
  } else {
    /* Token deposits pull through transferFrom; any native value would be
     * swept without being represented by the ABI amount screen. */
    if (!bn_is_zero(&Value)) return false;
    assetToken = tokenByChainAddress(msg->chain_id, assetAddress);
  }

  char amountStr[41];
  if (assetToken == UnknownToken) {
    /* We don't know what the exponent should be, so confirm the raw
     * unformatted number. */
    if (!thor_formatUnknownAssetAmount(
            msg->data_initial_chunk.bytes + 4 + 2 * 32, amountStr,
            sizeof(amountStr)))
      return false;
  } else {
    /* Native deposits forward msg.value; the ABI amount word is only a router
     * hint and may legitimately differ. Token deposits use the ABI amount. */
    const bignum256* displayed_amount = is_native ? &Value : &Amount;
    if (!ethereumFormatAmount(displayed_amount, assetToken, msg->chain_id,
                              amountStr, sizeof(amountStr)))
      return false;
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

  if (assetToken == UnknownToken) {
    // just display token address and amount as string
    for (ctr = 0; ctr < 20; ctr++) {
      snprintf(&confStr[ctr * 2], 3, "%02x", assetAddress[ctr]);
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

  /* Pass the memo's true ABI length, not a fixed 64. There is no raw-memo
   * fallback screen on this path -- ethereum.c turns a false return into
   * ActionCancelled -- so anything short of a confirmed parse must refuse
   * rather than sign bytes that were never displayed. */
  if (thorchain_parseConfirmMemo((const char*)thorchainData, memo_len) !=
      THORCHAIN_MEMO_CONFIRMED) {
    return false;
  }

  /* Page the complete raw memo as the authoritative disclosure: a long
   * structured field (dest/affiliate/aggregator) would otherwise truncate in
   * its single confirm and hide the tail that the router still executes. */
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
