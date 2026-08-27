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

#include "keepkey/firmware/thorchain.h"
#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/app_confirm.h"
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

bool thorchain_isValidDenom(const char* denom) {
  return tendermint_isValidDenom(denom);
}

bool thorchain_isValidAsset(const char* asset) {
  return tendermint_isValidAsset(asset);
}

static CONFIDENTIAL HDNode node;
static SHA256_CTX ctx;
static bool initialized;
static uint32_t msgs_remaining;
static ThorchainSignTx msg;
static bool testnet;

bool thorchain_isValidSigner(const char* signer) {
  return tendermint_isValidSigner(signer, testnet ? "tthor" : "thor");
}

const ThorchainSignTx* thorchain_getThorchainSignTx(void) { return &msg; }

bool thorchain_signTxInit(const HDNode* _node, const ThorchainSignTx* _msg) {
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
                          "\",\"denom\":\"rune\"}]",
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

bool thorchain_signTxUpdateMsgSend(const uint64_t amount,
                                   const char* to_address, const char* denom) {
  const char mainnetp[] = "thor";
  const char testnetp[] = "tthor";
  const char* pfix;
  char buffer[64 + 1];

  size_t decoded_len;
  char hrp[BECH32_MAX_HRP_LEN + 1];
  uint8_t decoded[BECH32_DECODED_MAX];
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

  // Default to "rune" for backward compatibility; validate all non-default
  // denoms
  const char* coin_denom = (denom && denom[0]) ? denom : "rune";
  if (!thorchain_isValidDenom(coin_denom)) {
    return false;
  }

  bool success = true;

  const char* const prelude = "{\"type\":\"thorchain/MsgSend\",\"value\":{";
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

bool thorchain_signTxUpdateMsgDeposit(const ThorchainMsgDeposit* depmsg) {
  char buffer[64 + 1];

  // Defended here too (not just by the FSM caller) so this signing path is
  // safe even if called directly or reused elsewhere later.
  if (!thorchain_isValidAsset(depmsg->asset) ||
      !thorchain_isValidSigner(depmsg->signer)) {
    return false;
  }

  bool success = true;

  const char* const prelude = "{\"type\":\"thorchain/MsgDeposit\",\"value\":{";
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

bool thorchain_signTxFinalize(uint8_t* public_key, uint8_t* signature) {
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

bool thorchain_signingIsInited(void) { return initialized; }

bool thorchain_signingIsFinished(void) { return msgs_remaining == 0; }

void thorchain_signAbort(void) {
  initialized = false;
  msgs_remaining = 0;
  memzero(&msg, sizeof(msg));
  memzero(&node, sizeof(node));
}

/* Page the COMPLETE raw memo so nothing is truncated behind confirm()'s body
 * budget. THORChain memos are ASCII; a non-printable byte gets a hex page so
 * even a malformed memo is fully disclosed rather than hidden. Shared with the
 * MAYA path (mayachain memos use the same grammar) and the native signing
 * handlers, which page this as the authoritative disclosure after any
 * best-effort structured summary. */
bool thorchain_confirm_full_memo(const char* title, const char* memo,
                                 size_t len) {
  return confirm_bytes(ButtonRequestType_ButtonRequest_ConfirmOutput, title,
                       (const uint8_t*)memo, len);
}

ThorchainMemoResult thorchain_parseConfirmMemo(const char* swapStr,
                                               size_t size) {
  /*
    Input: swapStr is candidate thorchain data
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

  /* Up to 9 fields for a DEX-aggregator swap
   * (SWAP:ASSET:DEST:LIM:AFFILIATE:FEE:AGGREGATOR:FINALTOKEN:MINOUT); the 10th
   * slot lets us detect (and reject) a memo with more fields than any known
   * grammar rather than silently merging the tail into a displayed field. */
  char* fields[10] = {NULL, NULL, NULL, NULL, NULL,
                      NULL, NULL, NULL, NULL, NULL};
  /* Memos are documented/accepted up to 256 bytes; memoBuf reserves one
   * extra byte so a full 256-byte memo still leaves a guaranteed NUL
   * terminator, instead of the copy silently dropping its last byte. */
  enum { MEMO_MAX = 256 };
  char memoBuf[MEMO_MAX + 1];
  size_t nfields, i;
  char *chain, *asset;

  // check if memo data is recognized

  if (size > MEMO_MAX) return THORCHAIN_MEMO_UNPARSED;
  memzero(memoBuf, sizeof(memoBuf));
  /* size is a byte count, not necessarily including a NUL: the BTC
   * OP_RETURN caller passes raw memo bytes with no terminator. strlcpy
   * would copy only size-1 bytes and silently drop the memo's last
   * character (turning an affiliate fee of "75" bps into "7"). Copy the
   * bytes exactly (size <= MEMO_MAX < sizeof(memoBuf), so this never
   * overflows and always leaves at least one zeroed terminator byte);
   * the zeroed buffer provides termination. */
  memcpy(memoBuf, swapStr, size);

  /* The field split below treats memoBuf as a C string, so it stops at the
     first NUL -- but `size` bytes were copied and ALL of them are covered by
     the signature. A memo such as "=:ETH.ETH:<dest>:0\0:affiliate:75" would
     parse and confirm as if it ended at the zero byte while the suffix stayed
     in the signed calldata. The EVM caller passes the true ABI length, so
     those bytes are real.

     Reject ANY NUL inside the declared length, including a trailing one. A
     length word that does not describe its own content is a non-canonical
     encoding, and is not made trustworthy by the bytes it misdescribes
     happening to be zero. The caller's UNPARSED path discloses the raw bytes
     with a length-aware writer, so nothing is lost by refusing to parse. */
  for (i = 0; i < size; i++) {
    if (memoBuf[i] == '\0') return THORCHAIN_MEMO_UNPARSED;
  }

  // Split on ':', keeping empty fields
  nfields = 0;
  fields[nfields++] = memoBuf;
  for (i = 0; memoBuf[i] != '\0' && nfields < 10; i++) {
    if (memoBuf[i] == ':') {
      memoBuf[i] = '\0';
      fields[nfields++] = &memoBuf[i + 1];
    }
  }

  if (nfields < 2) {
    // Must have at least transaction and chain.asset. If not, just confirm
    // data
    return THORCHAIN_MEMO_UNPARSED;
  }

  // Split chain.asset at the first '.'
  chain = fields[1];
  asset = strchr(chain, '.');
  if (asset == NULL) {
    // No chain.asset pair; not recognizable thorchain data, just confirm data
    return THORCHAIN_MEMO_UNPARSED;
  }
  *asset = '\0';
  asset++;

  // Check for swap
  if (strncmp(fields[0], "SWAP", 4) == 0 || *fields[0] == 's' ||
      *fields[0] == '=') {
    /* Aggregator outbound memo: field 8 is MinAmountOut|OUTBOUND_MEMO, and
     * everything after '|' is forwarded to the outbound contract. That suffix
     * can itself contain ':' which our ':'-split would scatter (or overflow
     * past field 9), so a single confirm could truncate it. When a '|' is
     * present, skip structured field display and page the COMPLETE raw memo so
     * every signed byte is shown. */
    if (memchr(swapStr, '|', size) != NULL) {
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                   "Thorchain swap", "Confirm swap asset %s\n on chain %s",
                   asset, chain)) {
        return THORCHAIN_MEMO_CANCELLED;
      }
      return thorchain_confirm_full_memo("Swap memo", swapStr, size)
                 ? THORCHAIN_MEMO_CONFIRMED
                 : THORCHAIN_MEMO_CANCELLED;
    }
    // This is a swap, set up destination and limit
    // The dest may be blank which means swap to self
    const char* dest =
        (nfields > 2 && fields[2][0] != '\0') ? fields[2] : "self";
    const char* limit =
        (nfields > 3 && fields[3][0] != '\0') ? fields[3] : "none";
    const char* affiliate =
        (nfields > 4 && fields[4][0] != '\0') ? fields[4] : NULL;
    const bool has_fee = (nfields > 5 && fields[5][0] != '\0');
    const char* fee_bps = has_fee ? fields[5] : "unspecified";
    /* DEX-aggregator swap-out fields — all router-executed, so all displayed.
     */
    const char* agg_addr =
        (nfields > 6 && fields[6][0] != '\0') ? fields[6] : NULL;
    const char* final_token =
        (nfields > 7 && fields[7][0] != '\0') ? fields[7] : NULL;
    const char* min_out =
        (nfields > 8 && fields[8][0] != '\0') ? fields[8] : NULL;

    /* Refuse only genuinely-unknown structure — more fields than any THORChain
     * swap grammar defines (>9), which we cannot label and must not hide. */
    if (nfields > 9) {
      return THORCHAIN_MEMO_UNPARSED;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Thorchain swap", "Confirm swap asset %s\n on chain %s", asset,
                 chain)) {
      return THORCHAIN_MEMO_CANCELLED;
    }
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Thorchain swap", "Confirm to %s", dest)) {
      return THORCHAIN_MEMO_CANCELLED;
    }
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Thorchain swap", "Confirm limit %s", limit)) {
      return THORCHAIN_MEMO_CANCELLED;
    }
    /* Never hide the affiliate fee skim. Gated on EITHER field being present,
     * not on the affiliate alone: a memo may carry a fee with an empty
     * affiliate slot ("=:ETH.ETH:0xdest:0::75"), and those bytes are inside
     * the signed length whether or not the slot naming their recipient is
     * filled in. Showing the fee against "(none given)" discloses what is
     * actually signed; skipping the screen discloses nothing. */
    if (affiliate != NULL || has_fee) {
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                   "Thorchain swap", "Affiliate fee %s bps to %s", fee_bps,
                   affiliate ? affiliate : "(none given)")) {
        return THORCHAIN_MEMO_CANCELLED;
      }
    }
    // DEX-aggregator routing: the router forwards the output through this
    // aggregator to a final token, so both must be visible.
    if (agg_addr != NULL &&
        !confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Thorchain swap", "DEX aggregator %s", agg_addr)) {
      return THORCHAIN_MEMO_CANCELLED;
    }
    if (final_token != NULL &&
        !confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Thorchain swap", "Final token %s", final_token)) {
      return THORCHAIN_MEMO_CANCELLED;
    }
    if (min_out != NULL &&
        !confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Thorchain swap", "Min output %s", min_out)) {
      return THORCHAIN_MEMO_CANCELLED;
    }
    return THORCHAIN_MEMO_CONFIRMED;
  }

  // Check for add liquidity
  else if (strncmp(fields[0], "ADD", 3) == 0 || *fields[0] == 'a' ||
           *fields[0] == '+') {
    // ADD:POOL:PAIREDADDR:AFFILIATE:FEE — paired address, affiliate and fee are
    // all optional but router-executed, so none may be hidden.
    const char* pool = (nfields > 2 && fields[2][0] != '\0') ? fields[2] : NULL;
    const char* affiliate =
        (nfields > 3 && fields[3][0] != '\0') ? fields[3] : NULL;
    const bool has_fee = (nfields > 4 && fields[4][0] != '\0');
    const char* fee_bps = has_fee ? fields[4] : "unspecified";

    /* ADD grammar defines at most 5 fields; more than that is structure we
     * cannot label and must not sign hidden, so refuse it. */
    if (nfields > 5) {
      return THORCHAIN_MEMO_UNPARSED;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Thorchain add liquidity",
                 "Confirm add asset %s\n on chain %s pool", asset, chain)) {
      return THORCHAIN_MEMO_CANCELLED;
    }
    if (pool != NULL) {
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                   "Thorchain add liquidity", "Confirm to %s", pool)) {
        return THORCHAIN_MEMO_CANCELLED;
      }
    }
    /* Same as the SWAP branch: a fee in an otherwise-unnamed affiliate slot
     * is still signed, so it is still shown. */
    if (affiliate != NULL || has_fee) {
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                   "Thorchain add liquidity", "Affiliate fee %s bps to %s",
                   fee_bps, affiliate ? affiliate : "(none given)")) {
        return THORCHAIN_MEMO_CANCELLED;
      }
    }
    return THORCHAIN_MEMO_CONFIRMED;
  }

  // Check for withdraw liquidity
  else if (strncmp(fields[0], "WITHDRAW", 8) == 0 ||
           strncmp(fields[0], "wd", 2) == 0 || *fields[0] == '-') {
    if (nfields < 3 || fields[2][0] == '\0') {
      return THORCHAIN_MEMO_UNPARSED;  // malformed memo
    }
    /* WD:POOL:BPS[:ASSET] — refuse only genuinely-unknown structure (>4
     * fields), mirroring the SWAP (>9) and ADD (>5) caps. */
    if (nfields > 4) {
      return THORCHAIN_MEMO_UNPARSED;
    }

    /* BPS rendered with integer math: snprintf is the integer-only sniprintf
     * on the device, so no float formats. Negative BPS is a malformed memo. */
    int bps = atoi(fields[2]);
    if (bps < 0) {
      return THORCHAIN_MEMO_UNPARSED;
    }
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Thorchain withdraw liquidity",
                 "Confirm withdraw %d.%02d%% of asset %s on chain %s",
                 bps / 100, bps % 100, asset, chain)) {
      return THORCHAIN_MEMO_CANCELLED;
    }
    /* Field 4 is the ASYMMETRIC-withdrawal asset selector: WD:POOL:BPS:ASSET
     * pays the whole withdrawal out single-sided in ASSET instead of the
     * symmetric split. It directs money, so it must never sign unseen —
     * otherwise the screens for the asymmetric form are identical to the
     * symmetric one. */
    if (nfields > 3 && fields[3][0] != '\0') {
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                   "Thorchain withdraw liquidity",
                   "Withdraw single-sided as %s", fields[3])) {
        return THORCHAIN_MEMO_CANCELLED;
      }
    }
    return THORCHAIN_MEMO_CONFIRMED;

  } else {
    // Just confirm whatever coin data if no thorchain intention data parsable
    return THORCHAIN_MEMO_UNPARSED;
  }
}
