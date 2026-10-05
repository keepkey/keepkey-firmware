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

bool thor_isThorchainTx(const EthereumSignTx* msg) {
  if (msg->has_to && msg->to.size == 20 && thor_has_deposit_selector(msg)) {
    return true;
  }
  return false;
}

bool thor_assetIsNative(const uint8_t asset_address[20]) {
  return asset_address != NULL && memcmp(asset_address, ETH_ADDRESS, 20) == 0;
}

bool thor_formatUnknownAssetAmount(const uint8_t word[32], char* out,
                                   size_t out_len) {
  if (!word || !out || out_len == 0) return false;
  bignum256 amount;
  bn_from_bytes(word, 32, &amount);
  return bn_format(&amount, NULL, " unformatted", 0, 0, false, out, out_len) !=
         0;
}

bool thor_confirmThorTx(uint32_t data_total, const EthereumSignTx* msg) {
  /* Minimum calldata: selector(4) + vault(32) + asset(32) + amount(32) +
   * memo_offset(32) + memo_length(32) = 164 bytes for deposit(),
   * + expiry(32) = 196 bytes for depositWithExpiry(). */
  const bool is_expiry = thor_is_expiry_variant(msg);
  /* Exactly the bound needed to read the memo's ABI length word below, which
   * sits at 4 + 4*32 for deposit() and 4 + 5*32 for depositWithExpiry(). The
   * previous 228/260 floor assumed a fixed 64-byte memo and rejected valid
   * short ones: `+:BTC/BTC::t:10` pads to 32 bytes, giving 196 bytes of
   * calldata for deposit(). The exact-length equality check further down is
   * what actually bounds the memo. */
  const size_t min_chunk = is_expiry ? 196 : 164;
  if (msg->data_initial_chunk.size < min_chunk) return false;

  /* The memo is a dynamic `string`. Its ABI head pointer (word 3) must be the
   * canonical one - 0x80 for deposit()'s 4 head words, 0xa0 for
   * depositWithExpiry()'s 5 - because the memo is read below at that FIXED
   * offset, which is only where the router's abi.decode will look when the
   * pointer matches. A host that points the memo elsewhere would have the
   * device display a benign memo while the router executes a different swap
   * destination. Refuse to clear-sign a non-canonical encoding. */
  const uint8_t* memo_off_word = msg->data_initial_chunk.bytes + 4 + 3 * 32;
  for (size_t i = 0; i < 31; i++) {
    if (memo_off_word[i] != 0) return false;
  }
  if (memo_off_word[31] != (is_expiry ? 0xa0 : 0x80)) return false;

  /* Read the memo's ABI length word instead of assuming a fixed 64 bytes: a
   * longer memo places router-executed fields (destination, affiliate fee,
   * aggregator routing) past byte 64, which the fixed-length parse never
   * displayed but the router still executes. Reject dirty high bytes and cap
   * at THORChain's 256-byte memo maximum. */
  const uint8_t* memo_len_word =
      msg->data_initial_chunk.bytes + 4 + (is_expiry ? 5 : 4) * 32;
  for (size_t i = 0; i < 28; i++) {
    if (memo_len_word[i] != 0) return false;
  }
  const uint32_t memo_len = ((uint32_t)memo_len_word[28] << 24) |
                            ((uint32_t)memo_len_word[29] << 16) |
                            ((uint32_t)memo_len_word[30] << 8) |
                            (uint32_t)memo_len_word[31];
  if (memo_len > 256) return false;

  /* The whole calldata must be in this chunk, and must end exactly where the
   * 32-byte-padded memo ends. A second chunk, or trailing words after the
   * memo, would be signed but never displayed. */
  const size_t memo_off = (size_t)(4 + (is_expiry ? 6 : 5) * 32);
  const size_t memo_padded = (((size_t)memo_len + 31u) / 32u) * 32u;
  if (data_total != msg->data_initial_chunk.size) return false;
  if (memo_off + memo_padded != msg->data_initial_chunk.size) return false;

  /* The equality above bounds the calldata but says nothing about what is IN
   * the ABI tail padding. Only memo_len bytes are handed to the parser and
   * drawn, while all memo_padded bytes are signed, so a host can carry up to
   * 31 arbitrary bytes per transaction in a region no screen ever shows. The
   * router ignores them - abi.decode reads memo_len - which is exactly why
   * they are attractive: they cost the sender nothing and the device vouches
   * for them. Canonical ABI pads with zeroes; anything else is a non-canonical
   * encoding this path already refuses elsewhere (dirty high bytes in the
   * length word, a non-canonical offset pointer). Refuse it here too rather
   * than sign bytes that were never displayed. */
  for (size_t i = memo_off + memo_len; i < memo_off + memo_padded; i++) {
    if (msg->data_initial_chunk.bytes[i] != 0) return false;
  }

  char confStr[41], *conf;
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
  if (thor_assetIsNative(contractAssetAddress)) {
    assetToken = NULL;
  } else {
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
    if (!ethereumFormatAmount(&Amount, assetToken, msg->chain_id, amountStr,
                              sizeof(amountStr)))
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
  for (ctr = 0; ctr < 20; ctr++) {
    snprintf(&confStr[ctr * 2], 3, "%02x", msg->to.bytes[ctr]);
  }
  /* THOR_ROUTER is an Ethereum-mainnet identity. The same 20 bytes on another
   * EVM chain are an unrelated contract, so the trusted label has to be bound
   * to the chain; otherwise a host-chosen chain_id borrows it. */
  if (msg->has_chain_id && msg->chain_id == 1 &&
      strncmp(confStr, THOR_ROUTER, sizeof(THOR_ROUTER)) == 0) {
    conf = "Thorchain router";
  } else {
    conf = confStr;
  }
  if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Thorchain data",
               "Routing through %s", conf)) {
    return false;
  }

  // just display token address and amount as string
  for (ctr = 0; ctr < 20; ctr++) {
    snprintf(&confStr[ctr * 2], 3, "%02x", vaultAddress[ctr]);
  }
  if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Thorchain data",
               "Using Asgard vault %s", confStr)) {
    return false;
  }

  if (assetToken == UnknownToken) {
    // just display token address and amount as string
    for (ctr = 0; ctr < 20; ctr++) {
      snprintf(&confStr[ctr * 2], 3, "%02x", assetAddress[ctr]);
    }
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Thorchain data", "from asset %s", confStr)) {
      return false;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Thorchain data", "amount %s", amountStr)) {
      return false;
    }

  } else {
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Thorchain data", "Confirm sending %s", amountStr)) {
      return false;
    }
  }

  if (is_expiry && !confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                            "Thorchain data", "Expiry epoch %s", expiry_str)) {
    return false;
  }

  /* Pass the memo's true ABI length, not a fixed 64. There is no raw-memo
   * fallback screen on this path - ethereum.c turns a false return into
   * ActionCancelled - so an unparsed memo must refuse rather than sign bytes
   * that were never displayed. */
  if (thorchain_parseConfirmMemo((const char*)thorchainData, memo_len) !=
      THORCHAIN_MEMO_CONFIRMED) {
    return false;
  }

  return true;
}
