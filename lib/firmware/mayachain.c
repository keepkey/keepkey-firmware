/*
 * This file is part of the Keepkey project.
 *
 * Copyright (C) 2021 Shapeshift
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

#include "keepkey/firmware/mayachain.h"
#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/firmware/tendermint.h"
#include "trezor/crypto/secp256k1.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/segwit_addr.h"

#include <stdbool.h>
#include <string.h>
#include <time.h>

// Allow lowercase alpha, digits, and the punctuation used in MAYAChain asset
// identifiers (e.g. "eth.eth", "btc/btc", cross-chain synthetic prefixes).
// Rejects anything that needs JSON escaping (backslash, quote).
bool mayachain_isValidDenom(const char* denom) {
  if (!denom || !denom[0]) return false;
  for (size_t i = 0; denom[i]; i++) {
    char c = denom[i];
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' ||
          c == '/' || c == '-')) {
      return false;
    }
  }
  return true;
}

// Deposit assets share the denom grammar but are conventionally uppercase
// (e.g. MAYA.CACAO, ETH.USDT-0XDAC1...); allow both cases, digits, . / -.
bool mayachain_isValidAsset(const char* asset) {
  if (!asset || !asset[0]) return false;
  for (size_t i = 0; asset[i]; i++) {
    char c = asset[i];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') || c == '.' || c == '/' || c == '-')) {
      return false;
    }
  }
  return true;
}

static CONFIDENTIAL HDNode node;
static SHA256_CTX ctx;
static bool initialized;
static uint32_t msgs_remaining;
static MayachainSignTx msg;
static bool testnet;

// Deposit signer is host-supplied; require a valid bech32 address with the
// HRP of the active network before it is displayed or signed.
bool mayachain_isValidSigner(const char* signer) {
  size_t decoded_len;
  char hrp[45];
  uint8_t decoded[38];
  if (!signer || !bech32_decode(hrp, decoded, &decoded_len, signer)) {
    return false;
  }
  return 0 == strcmp(hrp, testnet ? "smaya" : "maya");
}

const MayachainSignTx* mayachain_getMayachainSignTx(void) { return &msg; }

bool mayachain_signTxInit(const HDNode* _node, const MayachainSignTx* _msg) {
  initialized = true;
  msgs_remaining = _msg->msg_count;
  testnet = false;

  if (_msg->has_testnet) {
    testnet = _msg->testnet;
  }

  memzero(&node, sizeof(node));
  memcpy(&node, _node, sizeof(node));
  memcpy(&msg, _msg, sizeof(msg));

  bool success = true;
  char buffer[64 + 1];

  sha256_Init(&ctx);

  // Each segment guaranteed to be less than or equal to 64 bytes
  // 19 + ^20 + 1 = ^40
  if (!tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                           "{\"account_number\":\"%" PRIu64 "\"",
                           msg.account_number))
    return false;

  // <escape chain_id>
  const char* const chainid_prefix = ",\"chain_id\":\"";
  sha256_Update(&ctx, (uint8_t*)chainid_prefix, strlen(chainid_prefix));
  tendermint_sha256UpdateEscaped(&ctx, msg.chain_id, strlen(msg.chain_id));

  // 30 + ^10 + 19 = ^59
  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                          "\",\"fee\":{\"amount\":[{\"amount\":\"%" PRIu32
                          "\",\"denom\":\"cacao\"}]",
                          msg.fee_amount);

  // 8 + ^10 + 2 = ^20
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 ",\"gas\":\"%" PRIu32 "\"}", msg.gas);

  // <escape memo>
  const char* const memo_prefix = ",\"memo\":\"";
  sha256_Update(&ctx, (uint8_t*)memo_prefix, strlen(memo_prefix));
  if (msg.has_memo) {
    tendermint_sha256UpdateEscaped(&ctx, msg.memo, strlen(msg.memo));
  }

  // 10
  sha256_Update(&ctx, (uint8_t*)"\",\"msgs\":[", 10);

  return success;
}

bool mayachain_signTxUpdateMsgSend(const uint64_t amount,
                                   const char* to_address, const char* denom) {
  const char mainnetp[] = "maya";
  const char testnetp[] = "smaya";
  const char* pfix;
  char buffer[64 + 1];

  size_t decoded_len;
  char hrp[45];
  uint8_t decoded[38];
  if (!bech32_decode(hrp, decoded, &decoded_len, to_address)) {
    return false;
  }

  char from_address[46];

  pfix = mainnetp;
  if (testnet) {
    pfix = testnetp;
  }

  if (!tendermint_getAddress(&node, pfix, from_address)) {
    return false;
  }

  // Default to "cacao" for backward compatibility; validate all non-default
  // denoms. Defended here too (not just by the FSM caller) so this signing
  // path is safe even if called directly or reused elsewhere later.
  const char* coin_denom = (denom && denom[0]) ? denom : "cacao";
  if (!mayachain_isValidDenom(coin_denom)) {
    return false;
  }

  bool success = true;

  const char* const prelude = "{\"type\":\"mayachain/MsgSend\",\"value\":{";
  sha256_Update(&ctx, (uint8_t*)prelude, strlen(prelude));

  // Write amount prefix: 21 + ^20 = ^41
  success &= tendermint_snprintf(
      &ctx, buffer, sizeof(buffer),
      "\"amount\":[{\"amount\":\"%" PRIu64 "\",\"denom\":\"", amount);
  // Use escaping as defense-in-depth; valid denoms have no escapable chars
  tendermint_sha256UpdateEscaped(&ctx, coin_denom, strlen(coin_denom));
  // Close coins array: 3 bytes
  sha256_Update(&ctx, (uint8_t*)"\"}]", 3);

  // 17 + 45 + 1 = 63
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 ",\"from_address\":\"%s\"", from_address);

  // 15 + 45 + 3 = 63
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 ",\"to_address\":\"%s\"}}", to_address);

  msgs_remaining--;
  return success;
}

bool mayachain_signTxUpdateMsgDeposit(const MayachainMsgDeposit* depmsg) {
  char buffer[64 + 1];

  // Defended here too (not just by the FSM caller) so this signing path is
  // safe even if called directly or reused elsewhere later.
  if (!mayachain_isValidAsset(depmsg->asset) ||
      !mayachain_isValidSigner(depmsg->signer)) {
    return false;
  }

  bool success = true;

  const char* const prelude = "{\"type\":\"mayachain/MsgDeposit\",\"value\":{";
  sha256_Update(&ctx, (uint8_t*)prelude, strlen(prelude));

  // 20 + ^20 + 1 = ^41
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"coins\":[{\"amount\":\"%" PRIu64 "\"",
                                 depmsg->amount);

  // Use escaping as defense-in-depth; valid assets have no escapable chars
  const char* const asset_prefix = ",\"asset\":\"";
  sha256_Update(&ctx, (uint8_t*)asset_prefix, strlen(asset_prefix));
  tendermint_sha256UpdateEscaped(&ctx, depmsg->asset, strlen(depmsg->asset));
  sha256_Update(&ctx, (uint8_t*)"\"}]", 3);

  // <escape memo>
  const char* const memo_prefix = ",\"memo\":\"";
  sha256_Update(&ctx, (uint8_t*)memo_prefix, strlen(memo_prefix));
  tendermint_sha256UpdateEscaped(&ctx, depmsg->memo, strlen(depmsg->memo));

  // 17 + 45 + 1 = 63
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\",\"signer\":\"%s\"}}", depmsg->signer);

  msgs_remaining--;
  return success;
}

bool mayachain_signTxFinalize(uint8_t* public_key, uint8_t* signature) {
  char buffer[64 + 1];

  // 16 + ^20 = ^36
  if (!tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                           "],\"sequence\":\"%" PRIu64 "\"}", msg.sequence))
    return false;

  hdnode_fill_public_key(&node);
  memcpy(public_key, node.public_key, 33);

  uint8_t hash[SHA256_DIGEST_LENGTH];
  sha256_Final(&ctx, hash);
  return ecdsa_sign_digest(&secp256k1, node.private_key, hash, signature, NULL,
                           NULL) == 0;
}

bool mayachain_signingIsInited(void) { return initialized; }

bool mayachain_signingIsFinished(void) { return msgs_remaining == 0; }

void mayachain_signAbort(void) {
  initialized = false;
  msgs_remaining = 0;
  memzero(&msg, sizeof(msg));
  memzero(&node, sizeof(node));
}

bool mayachain_parseConfirmMemo(const char* swapStr, size_t size) {
  /*
    Input: swapStr is candidate mayachain data
           size is the size of swapStr (<= 256)
    Memos should be of the form:
    transaction:chain.ticker-id:destination:limit:affiliate:fee_bps
                ^^^^^^^^^^^^^^----------asset

    So, swap USDT to dest address 0x41e55..., limit 420, affiliate "kk"
    skimming 75 basis points:
    SWAP:ETH.USDT-0xdac17f958d2ee523a2206206994597c13d831ec7:0x41e5560054824ea6b0732e656e3ad64e20e94e45:420:kk:75

    Swap transactions can be indicated by "SWAP" or "s" or "="

    Fields are split on ':' PRESERVING empty fields so a blank field (e.g.
    an empty limit in "=:ETH.ETH:0xdest::kk:75") can never shift a later
    field (e.g. the affiliate) into an earlier display slot.
  */

  char* fields[8] = {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};
  /* Memos are documented/accepted up to 256 bytes; memoBuf reserves one
   * extra byte so a full 256-byte memo still leaves a guaranteed NUL
   * terminator, instead of the copy silently dropping its last byte. */
  enum { MEMO_MAX = 256 };
  char memoBuf[MEMO_MAX + 1];
  size_t nfields, i;
  char *chain, *asset;

  // check if memo data is recognized

  if (size > MEMO_MAX) return false;
  memzero(memoBuf, sizeof(memoBuf));
  /* size is a byte count, not necessarily including a NUL: the BTC
   * OP_RETURN caller passes raw memo bytes with no terminator. strlcpy
   * would copy only size-1 bytes and silently drop the memo's last
   * character (turning an affiliate fee of "75" bps into "7"). Copy the
   * bytes exactly (size <= MEMO_MAX < sizeof(memoBuf), so this never
   * overflows and always leaves at least one zeroed terminator byte);
   * the zeroed buffer provides termination. */
  memcpy(memoBuf, swapStr, size);

  // Split on ':', keeping empty fields
  nfields = 0;
  fields[nfields++] = memoBuf;
  for (i = 0; memoBuf[i] != '\0' && nfields < 8; i++) {
    if (memoBuf[i] == ':') {
      memoBuf[i] = '\0';
      fields[nfields++] = &memoBuf[i + 1];
    }
  }

  if (nfields < 2) {
    // Must have at least transaction and chain.asset. If not, just confirm
    // data
    return false;
  }

  // Split chain.asset at the first '.'
  chain = fields[1];
  asset = strchr(chain, '.');
  if (asset == NULL) {
    // No chain.asset pair; not recognizable mayachain data, just confirm data
    return false;
  }
  *asset = '\0';
  asset++;

  // Check for swap
  if (strncmp(fields[0], "SWAP", 4) == 0 || *fields[0] == 's' ||
      *fields[0] == '=') {
    // This is a swap, set up destination and limit
    // The dest may be blank which means swap to self
    const char* dest =
        (nfields > 2 && fields[2][0] != '\0') ? fields[2] : "self";
    const char* limit =
        (nfields > 3 && fields[3][0] != '\0') ? fields[3] : "none";
    const char* affiliate =
        (nfields > 4 && fields[4][0] != '\0') ? fields[4] : NULL;
    const char* fee_bps =
        (nfields > 5 && fields[5][0] != '\0') ? fields[5] : "unspecified";

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Mayachain swap", "Confirm swap asset %s\n on chain %s", asset,
                 chain)) {
      return false;
    }
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Mayachain swap", "Confirm to %s", dest)) {
      return false;
    }
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Mayachain swap", "Confirm limit %s", limit)) {
      return false;
    }
    // Never hide the affiliate fee skim from the user
    if (affiliate != NULL) {
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                   "Mayachain swap", "Affiliate fee %s bps to %s", fee_bps,
                   affiliate)) {
        return false;
      }
    }
    return true;
  }

  // Check for add liquidity
  else if (strncmp(fields[0], "ADD", 3) == 0 || *fields[0] == 'a' ||
           *fields[0] == '+') {
    // add liquidity pool address (optional)
    const char* pool = (nfields > 2 && fields[2][0] != '\0') ? fields[2] : NULL;

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Mayachain add liquidity",
                 "Confirm add asset %s\n on chain %s pool", asset, chain)) {
      return false;
    }
    if (pool != NULL) {
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                   "Mayachain add liquidity", "Confirm to %s", pool)) {
        return false;
      }
    }
    return true;
  }

  // Check for withdraw liquidity
  else if (strncmp(fields[0], "WITHDRAW", 8) == 0 ||
           strncmp(fields[0], "wd", 2) == 0 || *fields[0] == '-') {
    if (nfields < 3 || fields[2][0] == '\0') {
      return false;  // malformed memo
    }

    float percent = (float)(atoi(fields[2])) / 100;
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Mayachain withdraw liquidity",
                 "Confirm withdraw %3.2f%% of asset %s on chain %s", percent,
                 asset, chain)) {
      return false;
    }
    return true;

  } else {
    // Just confirm whatever coin data if no mayachain intention data parsable
    return false;
  }
}
