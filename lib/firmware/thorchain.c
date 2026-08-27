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
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/firmware/tendermint.h"
#include "trezor/crypto/secp256k1.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/segwit_addr.h"

#include <stdbool.h>
#include <time.h>

static CONFIDENTIAL HDNode node;
static SHA256_CTX ctx;
static bool initialized;
static bool has_message;
static uint32_t msgs_remaining;
static ThorchainSignTx msg;
static bool testnet;

const ThorchainSignTx* thorchain_getThorchainSignTx(void) { return &msg; }

bool thorchain_formatAmount(uint64_t amount, const char* asset, char* out,
                            size_t out_len) {
  if (!tendermint_validateSafeText(asset) || !out || out_len == 0) return false;

  char suffix[THORCHAIN_ASSET_SUFFIX_LEN + 2];
  const int suffix_len = snprintf(suffix, sizeof(suffix), " %s", asset);
  if (suffix_len <= 0 || (size_t)suffix_len >= sizeof(suffix)) return false;

  return bn_format_uint64(amount, NULL, suffix, 8, 0, false, out, out_len) != 0;
}

bool thorchain_signTxInit(const HDNode* _node, const ThorchainSignTx* _msg) {
  thorchain_signAbort();
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

  if (!success) {
    thorchain_signAbort();
    return false;
  }
  initialized = true;
  return true;
}

bool thorchain_signTxUpdateMsgSend(const uint64_t amount,
                                   const char* to_address) {
  if (!initialized || msgs_remaining == 0) return false;

  const char mainnetp[] = "thor";
  const char testnetp[] = "tthor";
  const char* pfix;
  char buffer[64 + 1];

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

  if (has_message) {
    sha256_Update(&ctx, (uint8_t*)",", 1);
  }

  bool success = true;

  const char* const prelude = "{\"type\":\"thorchain/MsgSend\",\"value\":{";
  sha256_Update(&ctx, (uint8_t*)prelude, strlen(prelude));

  // 21 + ^20 + 19 = ^60
  success &= tendermint_snprintf(
      &ctx, buffer, sizeof(buffer),
      "\"amount\":[{\"amount\":\"%" PRIu64 "\",\"denom\":\"rune\"}]", amount);

  // 17 + 45 + 1 = 63
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 ",\"from_address\":\"%s\"", from_address);

  // 15 + 45 + 3 = 63
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 ",\"to_address\":\"%s\"}}", to_address);

  if (success) has_message = true;
  msgs_remaining--;
  return success;
}

bool thorchain_signTxUpdateMsgDeposit(const ThorchainMsgDeposit* depmsg) {
  if (!initialized || msgs_remaining == 0) return false;

  const char* const signer_prefix = testnet ? "tthor" : "thor";
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

  const char* const prelude = "{\"type\":\"thorchain/MsgDeposit\",\"value\":{";
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

  if (success) has_message = true;
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

/* The account this session's key signs as.
 *
 * MsgDeposit's `signer` is serialized verbatim as the message authority, so a
 * merely well-formed thor/maya address let the device sign a document for an
 * account it cannot represent -- and the confirmation labels that address as
 * though it were a destination. There is exactly one authority a session can
 * act as; require the host to name it. */
bool thorchain_addressIsSigner(const char* address) {
  if (!initialized || !address) return false;

  char expected[46] = {0};
  if (!tendermint_getAddress(&node, testnet ? "tthor" : "thor", expected))
    return false;
  return strcmp(address, expected) == 0;
}

bool thorchain_signingIsInited(void) { return initialized; }

bool thorchain_signingIsFinished(void) {
  return msgs_remaining == 0 && has_message;
}

void thorchain_signAbort(void) {
  initialized = false;
  has_message = false;
  msgs_remaining = 0;
  memzero(&msg, sizeof(msg));
  memzero(&node, sizeof(node));
}

/* strtok() discards empty delimiter-separated components. Empty memo fields
 * are positional and meaningful -- for example, an omitted swap limit before
 * an affiliate is encoded as `::`. Structured review cannot use a tokenizer
 * that turns that memo into the same token sequence as one with no empty
 * position, because it can label the affiliate as the limit or otherwise
 * shift every field that follows.
 *
 * Treat any empty `:` or `.` component as non-canonical for this legacy
 * parser. Callers either disclose the raw memo (UTXO) or refuse the structured
 * EVM path. This is deliberately fail-closed until the parser is replaced by
 * one that preserves and understands every position in the current grammar. */
static bool thorchain_memo_has_empty_component(const char* memo, size_t size) {
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

static bool thorchain_memo_has_canonical_separators(const char* memo,
                                                    size_t size) {
  /* The grammar is  OP:CHAIN.ASSET:DEST:LIMIT[:AFFILIATE:BPS]  -- ':' between
     fields, '.' only inside the chain/asset pair.

     The tokenizer below cannot tell the two apart. After splitting the
     operation on ':' it calls strtok(NULL, ":.") three times, so ':' and '.'
     are interchangeable for everything it reads. A memo that puts a colon
     where the dot belongs,

         SWAP:ETH:USDT:dest:limit

     therefore produces exactly the same three tokens as SWAP:ETH.USDT:... and
     is reviewed as "asset USDT on chain ETH", while THORChain/MAYAChain read
     that same memo with USDT as the DESTINATION -- every field after the
     operation shifts by one, including the address the funds go to. The screen
     and the protocol disagree about a memo the signature covers.

     Require the dot exactly once and only inside the second colon-delimited
     field. Anything else is not this grammar, so it goes to the raw-byte path
     rather than through a parser that would mislabel it. A destination that
     legitimately contains a dot is refused here too; disclosure of the exact
     bytes is the safe direction, and this parser is fail-closed by design. */
  if (!memo || size == 0) return false;

  size_t field = 0;
  size_t dots_total = 0;
  size_t dots_in_asset_field = 0;

  for (size_t i = 0; i < size; i++) {
    if (memo[i] == ':') {
      field++;
      continue;
    }
    if (memo[i] == '.') {
      dots_total++;
      if (field == 1) dots_in_asset_field++;
    }
  }

  return dots_total == 1 && dots_in_asset_field == 1;
}

static bool thorchain_memo_is_structured_text(const char* memo, size_t size) {
  if (!memo || size == 0) return false;

  for (size_t i = 0; i < size; i++) {
    const unsigned char c = (unsigned char)memo[i];
    if (c < 0x21 || c > 0x7e) return false;
  }
  return true;
}

static bool thorchain_parse_bps(const char* text, uint16_t* bps) {
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

ThorchainMemoResult thorchain_parseConfirmMemo(const char* swapStr,
                                               size_t size) {
  /*
    Input: swapStr is candidate thorchain data
           size is the size of swapStr (<= 256)
    Memos should be of the form:
    transaction:chain.ticker-id:destination:limit[:affiliate:fee_bps...]
                ^^^^^^^^^^^^^^----------asset

    So, swap USDT to dest address 0x41e55..., limit 420
    SWAP:ETH.USDT-0xdac17f958d2ee523a2206206994597c13d831ec7:0x41e5560054824ea6b0732e656e3ad64e20e94e45:420

    Swap transactions can be indicated by "SWAP" or "s" or "="

    Fields past the ones labelled below (affiliate, affiliate fee, aggregator
    routing) are executed by THORChain, so each branch pages whatever is left
    rather than signing it unseen.
  */

  // THORChain's memo maximum, and the largest `size` any caller can pass.
  enum { THORCHAIN_MEMO_MAX = 256 };

  char* parseTokPtrs[5] = {NULL, NULL, NULL, NULL,
                           NULL};  // we can parse up to 5 labelled tokens
  char* tok;
  // One byte past the maximum, so a full-length memo is still NUL terminated
  // by the memzero below.
  char memoBuf[THORCHAIN_MEMO_MAX + 1];
  uint16_t ctr;

  // check if memo data is recognized

  if (size > THORCHAIN_MEMO_MAX ||
      thorchain_memo_has_empty_component(swapStr, size) ||
      !thorchain_memo_is_structured_text(swapStr, size) ||
      !thorchain_memo_has_canonical_separators(swapStr, size)) {
    return THORCHAIN_MEMO_UNPARSED;
  }
  memzero(memoBuf, sizeof(memoBuf));
  /* `size` is a byte count and swapStr is NOT guaranteed to be NUL
     terminated - the BTC OP_RETURN caller hands us raw script bytes. strlcpy
     copies only size-1 of them, silently dropping the memo's last character
     (an affiliate fee of "75" bps renders as "7"), and then walks past the end
     of the source looking for a terminator. Copy exactly `size` bytes; the
     memzero'd tail terminates them. */
  memcpy(memoBuf, swapStr, size);

  /* strtok below treats memoBuf as a C string, so it stops at the first NUL --
     but `size` bytes were copied and ALL of them are covered by the signature.
     A memo such as "=:ETH.ETH:<dest>:0\0:affiliate:75" would parse and confirm
     as if it ended at the zero byte while the suffix stayed in the signed
     calldata. The EVM caller passes the true ABI length, so those bytes are
     real.

     Reject ANY NUL inside the declared length, including a trailing one.

     An earlier version of this check exempted trailing NULs on the grounds
     that nothing is hidden behind them. That was wrong twice over. It was
     adopted to make two test fixtures pass -- fixtures that declare 59 bytes
     for a 58-byte memo -- which is the one thing the release invariant forbids:
     tests adapt to disclosure, disclosure never weakens for a test. And it
     accepts a length word that does not describe its own content, which is the
     same non-canonical ABI encoding that the offset-word validation already
     refuses. A declaration the device cannot trust is not made trustworthy by
     the bytes it misdescribes happening to be zero.

     The caller's UNPARSED path discloses the raw bytes with a length-aware
     writer, so nothing is lost by refusing to parse. */
  for (uint16_t i = 0; i < size; i++) {
    if (memoBuf[i] == '\0') return THORCHAIN_MEMO_UNPARSED;
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
    return THORCHAIN_MEMO_UNPARSED;
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
                 "Thorchain swap", "Confirm swap asset %s\n on chain %s",
                 parseTokPtrs[2], parseTokPtrs[1])) {
      return THORCHAIN_MEMO_CANCELLED;
    }
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Thorchain swap", "Confirm to %s", parseTokPtrs[3])) {
      return THORCHAIN_MEMO_CANCELLED;
    }
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Thorchain swap", "Confirm limit %s", parseTokPtrs[4])) {
      return THORCHAIN_MEMO_CANCELLED;
    }
    /* Everything after the limit - affiliate, affiliate fee in basis points,
       DEX-aggregator routing - is executed by THORChain but was never shown.
       Page each remaining field rather than sign it unseen. */
    while ((tok = strtok(NULL, ":")) != NULL) {
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                   "Thorchain swap", "Additional memo field\n%s", tok)) {
        return THORCHAIN_MEMO_CANCELLED;
      }
    }
    return THORCHAIN_MEMO_CONFIRMED;
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
                 "Thorchain add liquidity",
                 "Confirm add asset %s\n on chain %s pool", parseTokPtrs[2],
                 parseTokPtrs[1])) {
      return THORCHAIN_MEMO_CANCELLED;
    }
    if (tok != NULL) {
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                   "Thorchain add liquidity", "Confirm to %s",
                   parseTokPtrs[3])) {
        return THORCHAIN_MEMO_CANCELLED;
      }
    }
    /* ADD:POOL:PAIREDADDR:AFFILIATE:FEE - the affiliate and its fee are
       optional but router-executed, so neither may be hidden. */
    while ((tok = strtok(NULL, ":")) != NULL) {
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                   "Thorchain add liquidity", "Additional memo field\n%s",
                   tok)) {
        return THORCHAIN_MEMO_CANCELLED;
      }
    }
    return THORCHAIN_MEMO_CONFIRMED;
  }

  // Check for withdraw liquidity
  else if (strcmp(parseTokPtrs[0], "WITHDRAW") == 0 ||
           strcmp(parseTokPtrs[0], "wd") == 0 ||
           strcmp(parseTokPtrs[0], "-") == 0) {
    if (tok != NULL) {
      // add liquidity pool address
      parseTokPtrs[3] = tok;
    } else {
      return THORCHAIN_MEMO_UNPARSED;  // malformed memo
    }

    uint16_t bps = 0;
    if (!thorchain_parse_bps(parseTokPtrs[3], &bps)) {
      return THORCHAIN_MEMO_UNPARSED;
    }
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Thorchain withdraw liquidity",
                 "Confirm withdraw %u.%02u%% of asset %s on chain %s",
                 (unsigned)(bps / 100u), (unsigned)(bps % 100u),
                 parseTokPtrs[2], parseTokPtrs[1])) {
      return THORCHAIN_MEMO_CANCELLED;
    }
    /* WD:POOL:BPS:ASSET - the optional 4th field pays the whole withdrawal
       out single-sided in ASSET instead of the symmetric split. It directs
       money and the screens are otherwise identical, so it must be shown. */
    while ((tok = strtok(NULL, ":")) != NULL) {
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                   "Thorchain withdraw liquidity", "Additional memo field\n%s",
                   tok)) {
        return THORCHAIN_MEMO_CANCELLED;
      }
    }
    return THORCHAIN_MEMO_CONFIRMED;

  } else {
    // Just confirm whatever coin data if no thorchain intention data parsable
    return THORCHAIN_MEMO_UNPARSED;
  }
}
