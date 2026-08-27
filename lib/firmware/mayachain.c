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
#include <stdio.h>
#include <string.h>
#include <time.h>

static CONFIDENTIAL HDNode node;
static SHA256_CTX ctx;
static bool initialized;
static bool has_message;
static uint32_t msgs_remaining;
static MayachainSignTx msg;
static bool testnet;

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
  mayachain_signAbort();
  if (!_node || !_msg || !_msg->has_msg_count || _msg->msg_count == 0 ||
      !_msg->has_chain_id || !tendermint_validateSafeText(_msg->chain_id)) {
    return false;
  }

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

  if (!success) {
    mayachain_signAbort();
    return false;
  }
  initialized = true;
  return true;
}

bool mayachain_signTxUpdateMsgSend(const uint64_t amount,
                                   const char* to_address, const char* denom) {
  if (!initialized || msgs_remaining == 0) return false;
  if (!tendermint_validateSafeText(denom)) return false;

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

  if (has_message) {
    sha256_Update(&ctx, (uint8_t*)",", 1);
  }

  bool success = true;

  const char* const prelude = "{\"type\":\"mayachain/MsgSend\",\"value\":{";
  sha256_Update(&ctx, (uint8_t*)prelude, strlen(prelude));

  // 21 + ^20 + 11 + ^69 + 3 = ^124
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"amount\":[{\"amount\":\"%" PRIu64
                                 "\",\"denom\":\"%s\"}]",
                                 amount, denom);

  // 17 + 45 + 1 = 63
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 ",\"from_address\":\"%s\"", from_address);

  // 15 + 45 + 3 = 63
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 ",\"to_address\":\"%s\"}}", to_address);

  if (success) {
    has_message = true;
  }
  msgs_remaining--;
  return success;
}

bool mayachain_signTxUpdateMsgDeposit(const MayachainMsgDeposit* depmsg) {
  if (!initialized || msgs_remaining == 0) return false;

  const char* const signer_prefix = testnet ? "smaya" : "maya";
  if (!depmsg || !depmsg->has_asset ||
      !tendermint_validateSafeText(depmsg->asset) || !depmsg->has_signer ||
      !tendermint_validateBech32Address(depmsg->signer, signer_prefix)) {
    return false;
  }

  char buffer[64 + 1];

  if (has_message) {
    sha256_Update(&ctx, (uint8_t*)",", 1);
  }

  bool success = true;

  const char* const prelude = "{\"type\":\"mayachain/MsgDeposit\",\"value\":{";
  sha256_Update(&ctx, (uint8_t*)prelude, strlen(prelude));

  // 20 + ^20 + 1 = ^41
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"coins\":[{\"amount\":\"%" PRIu64 "\"",
                                 depmsg->amount);

  // 10 + ^20 + 3 = ^33
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 ",\"asset\":\"%s\"}]", depmsg->asset);

  // <escape memo>
  const char* const memo_prefix = ",\"memo\":\"";
  sha256_Update(&ctx, (uint8_t*)memo_prefix, strlen(memo_prefix));
  tendermint_sha256UpdateEscaped(&ctx, depmsg->memo, strlen(depmsg->memo));

  // 17 + 45 + 1 = 63
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\",\"signer\":\"%s\"}}", depmsg->signer);

  if (success) {
    has_message = true;
  }
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

bool mayachain_signingIsFinished(void) {
  return msgs_remaining == 0 && has_message;
}

void mayachain_signAbort(void) {
  initialized = false;
  has_message = false;
  msgs_remaining = 0;
  memzero(&msg, sizeof(msg));
  memzero(&node, sizeof(node));
}

/* Maya inherited THORChain's strtok-based parser. strtok() collapses empty
 * components even though memo fields are positional, so a valid `::` can
 * shift an affiliate into the limit slot while producing the same structured
 * screens as different signed bytes. Until this parser understands empty
 * positions explicitly, route such memos to the caller's raw-byte review. */
static bool mayachain_memo_has_empty_component(const char* memo, size_t size) {
  if (!memo || size == 0) return true;

  for (size_t i = 0; i < size; i++) {
    if (memo[i] != ':' && memo[i] != '.') continue;

    if (i == 0 || i + 1 == size || memo[i - 1] == ':' || memo[i - 1] == '.' ||
        memo[i + 1] == ':' || memo[i + 1] == '.') {
      return true;
    }
  }

  return false;
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
           size is the size of swapStr (<= 255)
    Memos should be of the form:
    transaction:chain.ticker-id:destination:limit[:affiliate:fee_bps...]
                ^^^^^^^^^^^^^^----------asset

    So, swap USDT to dest address 0x41e55..., limit 420
    SWAP:ETH.USDT-0xdac17f958d2ee523a2206206994597c13d831ec7:0x41e5560054824ea6b0732e656e3ad64e20e94e45:420

    Swap transactions can be indicated by "SWAP" or "s" or "="

    Fields past the ones labelled below (affiliate, affiliate fee, aggregator
    routing) are executed by MAYAChain, so each branch pages whatever is left
    rather than signing it unseen. Mirrors thorchain.c -- Maya is a fork of
    that path and kept the original code.
  */

  char* parseTokPtrs[7] = {NULL, NULL, NULL, NULL,
                           NULL, NULL, NULL};  // we can parse up to 7 tokens
  char* tok;
  char memoBuf[256];
  uint16_t ctr;

  // check if memo data is recognized

  /* One byte short of the buffer, so a full-length memo is still terminated by
     the memzero below. */
  if (size >= sizeof(memoBuf) ||
      mayachain_memo_has_empty_component(swapStr, size) ||
      !mayachain_memo_is_structured_text(swapStr, size)) {
    return MAYACHAIN_MEMO_UNPARSED;
  }
  memzero(memoBuf, sizeof(memoBuf));

  /* `size` is a byte count and swapStr is NOT guaranteed to be NUL terminated.
     strlcpy copied only size-1 of them, silently dropping the memo's last
     character -- an affiliate fee of "75" bps rendered as "7" -- and then
     walked past the end of the source looking for a terminator. Copy exactly
     `size` bytes; the memzero'd tail terminates them.
     Same defect as the THORChain path; Maya is a fork of it and kept the
     original code. */
  memcpy(memoBuf, swapStr, size);

  /* Refuse a declared length that does not describe its own content.

     Be exact about what this does and does not buy on THIS chain, because the
     wording copied from thorchain.c overstated it. On THORChain the same check
     closes a live disclosure gap: two of its callers pass an EXTERNALLY
     declared length -- a BTC OP_RETURN script length (transaction.c) and an
     ABI length word (thortx.c) -- and the signature covers every byte of it,
     so a memo carrying an embedded zero parsed as if it ended there while the
     suffix stayed signed.

     Maya has no such caller. Both call sites pass strnlen()
     (fsm_msg_mayachain.h), and the signer hashes strlen(memo) (lines 88 and 165
     above), so parsing and signing already stop at the same byte: nothing after
     an embedded NUL is signed, and there is no gap here to close.

     The check stays anyway, for two reasons that are worth stating rather than
     dressing up as a fix. A length that misdescribes its content is a
     non-canonical encoding and the device should not clear-sign one. And it
     keeps this parser safe by construction if Maya ever gains a length-passing
     caller of its own, which is exactly how THORChain acquired the real bug. */
  for (uint16_t i = 0; i < size; i++) {
    if (memoBuf[i] == '\0') return MAYACHAIN_MEMO_UNPARSED;
  }

  tok = strtok(memoBuf, ":");

  // get transaction and asset
  for (ctr = 0; ctr < 3; ctr++) {
    if (tok != NULL) {
      parseTokPtrs[ctr] = tok;
      tok = strtok(NULL, ":.");
    } else {
      break;
    }
  }

  if (ctr != 3) {
    // Must have three tokens at this point: transaction, chain, asset. If
    // not, just confirm data
    return MAYACHAIN_MEMO_UNPARSED;
  }

  // Check for swap
  if (strcmp(parseTokPtrs[0], "SWAP") == 0 ||
      strcmp(parseTokPtrs[0], "s") == 0 || strcmp(parseTokPtrs[0], "=") == 0) {
    // This is a swap, set up destination and limit
    // This is the dest, may be blank which means swap to self
    parseTokPtrs[3] = "self";
    parseTokPtrs[4] = "none";
    if (tok != NULL) {
      if ((uint32_t)(tok - (parseTokPtrs[2] + strlen(parseTokPtrs[2]))) == 1) {
        // has dest address
        parseTokPtrs[3] = tok;
        tok = strtok(NULL, ":");
      }
      if (tok != NULL) {
        // has limit
        parseTokPtrs[4] = tok;
      }
    }

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Mayachain swap", "Confirm swap asset %s\n on chain %s",
                 parseTokPtrs[2], parseTokPtrs[1])) {
      return MAYACHAIN_MEMO_CANCELLED;
    }
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Mayachain swap", "Confirm to %s", parseTokPtrs[3])) {
      return MAYACHAIN_MEMO_CANCELLED;
    }
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Mayachain swap", "Confirm limit %s", parseTokPtrs[4])) {
      return MAYACHAIN_MEMO_CANCELLED;
    }
    /* Everything after the limit - affiliate, affiliate fee in basis points,
       DEX-aggregator routing - is executed by MAYAChain but was never shown.
       The whole memo is hashed by strlen() in signTxUpdateMsgDeposit(), so a
       suffix such as ":affiliate:75" was signed unseen. Page each remaining
       field rather than sign it unseen. */
    while ((tok = strtok(NULL, ":")) != NULL) {
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                   "Mayachain swap", "Additional memo field\n%s", tok)) {
        return MAYACHAIN_MEMO_CANCELLED;
      }
    }
    return MAYACHAIN_MEMO_CONFIRMED;
  }

  // Check for add liquidity
  else if (strcmp(parseTokPtrs[0], "ADD") == 0 ||
           strcmp(parseTokPtrs[0], "a") == 0 ||
           strcmp(parseTokPtrs[0], "+") == 0) {
    if (tok != NULL) {
      // add liquidity pool address
      parseTokPtrs[3] = tok;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Mayachain add liquidity",
                 "Confirm add asset %s\n on chain %s pool", parseTokPtrs[2],
                 parseTokPtrs[1])) {
      return MAYACHAIN_MEMO_CANCELLED;
    }
    if (tok != NULL) {
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                   "Mayachain add liquidity", "Confirm to %s",
                   parseTokPtrs[3])) {
        return MAYACHAIN_MEMO_CANCELLED;
      }
    }
    /* ADD:POOL:PAIREDADDR:AFFILIATE:FEE - the affiliate and its fee are
       optional but router-executed, so neither may be hidden. */
    while ((tok = strtok(NULL, ":")) != NULL) {
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                   "Mayachain add liquidity", "Additional memo field\n%s",
                   tok)) {
        return MAYACHAIN_MEMO_CANCELLED;
      }
    }
    return MAYACHAIN_MEMO_CONFIRMED;
  }

  // Check for withdraw liquidity
  else if (strcmp(parseTokPtrs[0], "WITHDRAW") == 0 ||
           strcmp(parseTokPtrs[0], "wd") == 0 ||
           strcmp(parseTokPtrs[0], "-") == 0) {
    if (tok != NULL) {
      // add liquidity pool address
      parseTokPtrs[3] = tok;
    } else {
      return MAYACHAIN_MEMO_UNPARSED;  // malformed memo
    }

    uint16_t bps = 0;
    if (!mayachain_parse_bps(parseTokPtrs[3], &bps)) {
      return MAYACHAIN_MEMO_UNPARSED;
    }
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Mayachain withdraw liquidity",
                 "Confirm withdraw %u.%02u%% of asset %s on chain %s",
                 (unsigned)(bps / 100u), (unsigned)(bps % 100u),
                 parseTokPtrs[2], parseTokPtrs[1])) {
      return MAYACHAIN_MEMO_CANCELLED;
    }
    /* WD:POOL:BPS:ASSET - the optional 4th field pays the whole withdrawal
       out single-sided in ASSET instead of the symmetric split. It directs
       money and the screens are otherwise identical, so it must be shown. */
    while ((tok = strtok(NULL, ":")) != NULL) {
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                   "Mayachain withdraw liquidity", "Additional memo field\n%s",
                   tok)) {
        return MAYACHAIN_MEMO_CANCELLED;
      }
    }
    return MAYACHAIN_MEMO_CONFIRMED;

  } else {
    // Just confirm whatever coin data if no mayachain intention data parsable
    return MAYACHAIN_MEMO_UNPARSED;
  }
}
