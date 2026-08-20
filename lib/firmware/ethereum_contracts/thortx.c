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
   * depositWithExpiry()'s 5 - otherwise the router's abi.decode reads the memo
   * from somewhere other than the fixed offset we display it from, and the
   * swap that executes can differ from the one that was approved. */
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

  /* Head word 3 (offset 4 + 3 * 32) is the ABI offset pointer to the dynamic
   * `memo` string. The memo is read below at a FIXED offset, which is only
   * where the router's abi.decode will look when that pointer is canonical:
   * 0x80 for deposit()'s four head words, 0xa0 for depositWithExpiry()'s five.
   * A host that points the memo elsewhere would have the device display a
   * benign memo while the router executes a different swap destination.
   * Refuse to clear-sign a non-canonical encoding. */
  const char* memo_offset_canon =
      is_expiry
          ? "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa0"
          : "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80";
  if (memcmp(msg->data_initial_chunk.bytes + 4 + 3 * 32, memo_offset_canon,
             32) != 0) {
    return false;
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

  if (memcmp(contractAssetAddress, ETH_ADDRESS, sizeof(ETH_ADDRESS)) == 0) {
    assetAddress = (const uint8_t*)
        ETH_NATIVE;  // get eth native parameters if asset is not a token
  } else {
    assetAddress = contractAssetAddress;
  }

  assetToken = tokenByChainAddress(msg->chain_id, assetAddress);

  if (strncmp(assetToken->ticker, " UNKN", 5) == 0) {
    // just display token address and amount as string
    for (ctr = 0; ctr < 20; ctr++) {
      snprintf(&confStr[ctr * 2], 3, "%02x", assetAddress[ctr]);
    }
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Thorchain data", "from asset %s", confStr)) {
      return false;
    }
    // We don't know what the exponent should be so just confirm raw unformatted
    // number
    bn_format(&Amount, NULL, " unformatted", 0, 0, false, confStr,
              sizeof(confStr));

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Thorchain data", "amount %s", confStr)) {
      return false;
    }

  } else {
    ethereumFormatAmount(&Amount, assetToken, msg->chain_id, confStr,
                         sizeof(confStr));

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Thorchain data", "Confirm sending %s", confStr)) {
      return false;
    }
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
