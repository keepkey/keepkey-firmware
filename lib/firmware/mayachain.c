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

bool mayachain_isValidDenom(const char* denom) {
  return tendermint_isValidDenom(denom);
}

bool mayachain_isValidAsset(const char* asset) {
  return tendermint_isValidAsset(asset);
}

static CONFIDENTIAL HDNode node;
static SHA256_CTX ctx;
static bool initialized;
static uint32_t msgs_remaining;
static MayachainSignTx msg;
static bool testnet;

bool mayachain_isValidSigner(const char* signer) {
  return tendermint_isValidSigner(signer, testnet ? "smaya" : "maya");
}

const MayachainSignTx* mayachain_getMayachainSignTx(void) { return &msg; }

bool mayachain_formatAmount(uint64_t amount, const char* denom, char* out,
                            size_t out_len) {
  if (!tendermint_validateSafeText(denom) || !out || out_len == 0) return false;

  char suffix[MAYACHAIN_DENOM_SUFFIX_LEN + 2];
  const int suffix_len = snprintf(suffix, sizeof(suffix), " %s", denom);
  if (suffix_len <= 0 || (size_t)suffix_len >= sizeof(suffix)) return false;

  const int decimals = strcmp(denom, "cacao") == 0 ? 10 : 0;
  return bn_format_uint64(amount, NULL, suffix, decimals, 0, false, out,
                          out_len) != 0;
}

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
  /* Sized for the amount/denom segment below, which is the longest thing this
     function formats:

       "amount":[{"amount":"   21
       <uint64>                20
       ","denom":"             11
       <denom>                 68   (MayachainMsgSend.denom max_size 69)
       "}]                      3   = 123, + NUL = 124

     It was 65. tendermint_snprintf() fails closed when its output does not
     fit, so nothing was ever mis-signed -- but the failure landed AFTER
     fsm_msgMayachainMsgAck() had already shown the amount and taken the
     owner's approval, so a long yet perfectly valid denomination was approved
     and only then refused. This branch's rule is that anything unrenderable
     fails BEFORE the confirmation, so make the segment fit its own documented
     maximum. Unlike THORChain, which hardcodes "rune", this denom is
     host-supplied, which is why only MAYAChain hits it. */
  char buffer[128];

  char from_address[46];

  pfix = mainnetp;
  if (testnet) {
    pfix = testnetp;
  }

  /* Validate the recipient against THIS network's prefix and the 20-byte
     account length, before it reaches the bare "%s" JSON serialization below.
     This used to be a bare bech32_decode() into hrp[45]/decoded[38], which
     both overflowed on host-chosen input and checked neither the network nor
     the payload length -- so a wrong-chain address, a module or operator
     address, or a punctuation-bearing HRP all passed straight into the signed
     document. Select the prefix first so there is something to check against.
   */
  if (!tendermint_validateBech32Address(to_address, pfix)) {
    return false;
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

/* The account this session's key signs as.
 *
 * MsgDeposit's `signer` is serialized verbatim as the message authority, so a
 * merely well-formed thor/maya address let the device sign a document for an
 * account it cannot represent -- and the confirmation labels that address as
 * though it were a destination. There is exactly one authority a session can
 * act as; require the host to name it. */
bool mayachain_addressIsSigner(const char* address) {
  if (!initialized || !address) return false;

  char expected[46] = {0};
  if (!tendermint_getAddress(&node, testnet ? "smaya" : "maya", expected))
    return false;
  return strcmp(address, expected) == 0;
}

bool mayachain_signingIsInited(void) { return initialized; }

bool mayachain_signingIsFinished(void) { return msgs_remaining == 0; }

void mayachain_signAbort(void) {
  initialized = false;
  msgs_remaining = 0;
  memzero(&msg, sizeof(msg));
  memzero(&node, sizeof(node));
}

/* Validate the chain/asset separator before the positional parser labels
 * fields. Empty colon-delimited fields remain meaningful and supported. */
static bool mayachain_memo_has_canonical_separators(const char* memo,
                                                    size_t size) {
  /* The grammar requires OP:CHAIN.ASSET. Dots in later positional fields are
   * data, so they must not be confused with the one separator required in
   * field 1. */
  if (!memo || size == 0) return false;

  size_t field = 0;
  size_t dots_in_asset_field = 0;
  bool has_chain = false;
  bool has_asset = false;

  for (size_t i = 0; i < size; i++) {
    if (memo[i] == ':') {
      field++;
      continue;
    }
    if (field != 1) continue;
    if (memo[i] == '.')
      dots_in_asset_field++;
    else if (dots_in_asset_field == 0)
      has_chain = true;
    else
      has_asset = true;
  }

  return dots_in_asset_field == 1 && has_chain && has_asset;
}

static bool mayachain_memo_is_structured_text(const char* memo, size_t size) {
  if (!memo || size == 0) return false;

  for (size_t i = 0; i < size; i++) {
    const unsigned char c = (unsigned char)memo[i];
    if (c < 0x21 || c > 0x7e) return false;
  }
  return true;
}

static bool mayachain_parse_bps(const char* text, uint16_t* bps) {
  if (!text || !bps || text[0] == '\0') return false;
  if (text[0] == '0' && text[1] != '\0') return false;

  uint32_t value = 0;
  for (const char* p = text; *p; p++) {
    if (*p < '0' || *p > '9') return false;
    const uint32_t digit = (uint32_t)(*p - '0');
    if (value > (10000u - digit) / 10u) return false;
    value = value * 10u + digit;
  }

  *bps = (uint16_t)value;
  return true;
}

MayachainMemoResult mayachain_parseConfirmMemo(const char* swapStr,
                                               size_t size) {
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

  /* One byte short of the buffer, so a full-length memo is still terminated by
     the memzero below. */
  if (size >= sizeof(memoBuf) ||
      !mayachain_memo_is_structured_text(swapStr, size) ||
      !mayachain_memo_has_canonical_separators(swapStr, size)) {
    return MAYACHAIN_MEMO_UNPARSED;
  }
  memzero(memoBuf, sizeof(memoBuf));
  /* size is a byte count, not necessarily including a NUL: the BTC
   * OP_RETURN caller passes raw memo bytes with no terminator. strlcpy
   * would copy only size-1 bytes and silently drop the memo's last
   * character (turning an affiliate fee of "75" bps into "7"). Copy the
   * bytes exactly (size <= MEMO_MAX < sizeof(memoBuf), so this never
   * overflows and always leaves at least one zeroed terminator byte);
   * the zeroed buffer provides termination. */
  memcpy(memoBuf, swapStr, size);

  /* The field split below treats memoBuf as a C string and stops at the first
     NUL, but all `size` bytes are covered by the signature. A memo carrying an
     embedded zero would parse and confirm as if it ended there while the
     suffix stayed signed. A length word that does not describe its own content
     is a non-canonical encoding, so refuse it and let the caller disclose the
     raw bytes. Mirrors thorchain.c. */
  for (i = 0; i < size; i++) {
    if (memoBuf[i] == '\0') return MAYACHAIN_MEMO_UNPARSED;
  }

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
    return MAYACHAIN_MEMO_UNPARSED;
  }

  // Split chain.asset at the first '.'
  chain = fields[1];
  asset = strchr(chain, '.');
  if (asset == NULL) {
    // No chain.asset pair; not recognizable mayachain data, just confirm data
    return MAYACHAIN_MEMO_UNPARSED;
  }
  *asset = '\0';
  asset++;

  // Check for swap
  if (strcmp(fields[0], "SWAP") == 0 || strcmp(fields[0], "s") == 0 ||
      strcmp(fields[0], "=") == 0) {
    // This is a swap, set up destination and limit
    // The dest may be blank which means swap to self
    const char* dest =
        (nfields > 2 && fields[2][0] != '\0') ? fields[2] : "self";
    const char* limit =
        (nfields > 3 && fields[3][0] != '\0') ? fields[3] : "none";
    const char* affiliate =
        (nfields > 4 && fields[4][0] != '\0') ? fields[4] : NULL;
    const bool has_fee = nfields > 5 && fields[5][0] != '\0';
    const char* fee_bps = has_fee ? fields[5] : "unspecified";
    uint16_t parsed_fee_bps = 0;
    if (has_fee && !mayachain_parse_bps(fee_bps, &parsed_fee_bps)) {
      return MAYACHAIN_MEMO_UNPARSED;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Mayachain swap", "Confirm swap asset %s\n on chain %s", asset,
                 chain)) {
      return MAYACHAIN_MEMO_CANCELLED;
    }
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Mayachain swap", "Confirm to %s", dest)) {
      return MAYACHAIN_MEMO_CANCELLED;
    }
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Mayachain swap", "Confirm limit %s", limit)) {
      return MAYACHAIN_MEMO_CANCELLED;
    }
    // Never hide the affiliate fee skim from the user
    if (affiliate != NULL || has_fee) {
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                   "Mayachain swap", "Affiliate fee %s bps to %s", fee_bps,
                   affiliate ? affiliate : "(none given)")) {
        return MAYACHAIN_MEMO_CANCELLED;
      }
    }
    return MAYACHAIN_MEMO_CONFIRMED;
  }

  // Check for add liquidity
  else if (strcmp(fields[0], "ADD") == 0 || strcmp(fields[0], "a") == 0 ||
           strcmp(fields[0], "+") == 0) {
    // add liquidity pool address (optional)
    const char* pool = (nfields > 2 && fields[2][0] != '\0') ? fields[2] : NULL;

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Mayachain add liquidity",
                 "Confirm add asset %s\n on chain %s pool", asset, chain)) {
      return MAYACHAIN_MEMO_CANCELLED;
    }
    if (pool != NULL) {
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                   "Mayachain add liquidity", "Confirm to %s", pool)) {
        return MAYACHAIN_MEMO_CANCELLED;
      }
    }
    return MAYACHAIN_MEMO_CONFIRMED;
  }

  // Check for withdraw liquidity
  else if (strcmp(fields[0], "WITHDRAW") == 0 || strcmp(fields[0], "wd") == 0 ||
           strcmp(fields[0], "-") == 0) {
    if (nfields < 3 || fields[2][0] == '\0') {
      return MAYACHAIN_MEMO_UNPARSED;  // malformed memo
    }
    /* WD:POOL:BPS[:ASSET] — refuse only genuinely-unknown structure (>4
     * fields), mirroring thorchain.c. */
    if (nfields > 4) {
      return MAYACHAIN_MEMO_UNPARSED;
    }

    /* BPS rendered with integer math: snprintf is the integer-only sniprintf
     * on the device, so no float formats. Negative BPS is a malformed memo. */
    uint16_t bps = 0;
    if (!mayachain_parse_bps(fields[2], &bps)) {
      return MAYACHAIN_MEMO_UNPARSED;
    }
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Mayachain withdraw liquidity",
                 "Confirm withdraw %d.%02d%% of asset %s on chain %s",
                 bps / 100, bps % 100, asset, chain)) {
      return MAYACHAIN_MEMO_CANCELLED;
    }
    /* Field 4 selects an ASYMMETRIC (single-sided) withdrawal payout asset —
     * it directs money and must never sign unseen (see thorchain.c). */
    if (nfields > 3 && fields[3][0] != '\0') {
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                   "Mayachain withdraw liquidity",
                   "Withdraw single-sided as %s", fields[3])) {
        return MAYACHAIN_MEMO_CANCELLED;
      }
    }
    return MAYACHAIN_MEMO_CONFIRMED;

  } else {
    // Just confirm whatever coin data if no mayachain intention data parsable
    return MAYACHAIN_MEMO_UNPARSED;
  }
}
