/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2018 KeepKey
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

#include "keepkey/firmware/eos.h"

#include "eos.h"

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/storage.h"
#include "hwcrypto/crypto/base58.h"
#include "hwcrypto/crypto/bip32.h"
#include "hwcrypto/crypto/hasher.h"
#include "hwcrypto/crypto/memzero.h"
#include "hwcrypto/crypto/secp256k1.h"

#include "messages-eos.pb.h"

#include <stdio.h>
#include <time.h>

CONFIDENTIAL Hasher hasher_preimage;
CONFIDENTIAL Hasher hasher_unknown;

static bool inited = false;
static CONFIDENTIAL HDNode node;
static CONFIDENTIAL HDNode root;
static uint32_t address_n[8];
static size_t address_n_count;
static EosTxHeader header;
static uint32_t actions_remaining = 0;
static uint32_t unknown_total = 0;
static uint32_t unknown_remaining = 0;

bool eos_formatAsset(const EosAsset *asset, char str[EOS_ASSET_STR_SIZE]) {
  memset(str, 0, EOS_ASSET_STR_SIZE);
  char *s = str;
  uint64_t v = (uint64_t)asset->amount;

  // Sign
  if (asset->amount < 0) {
    *s++ = '-';
    v = ~v + 1;
  }

  // Value. Precision stored in low 8 bits
  uint8_t p = asset->symbol & 0xff;
  if (v >= 10000000000000000000ULL || p >= 19) {
    *s++ = '0' + v / 10000000000000000000ULL % 10;
  }
  if (p == 19) {
    *s++ = '.';
  }
  if (v >= 1000000000000000000ULL || p >= 18) {
    *s++ = '0' + v / 1000000000000000000ULL % 10;
  }
  if (p == 18) {
    *s++ = '.';
  }
  if (v >= 100000000000000000ULL || p >= 17) {
    *s++ = '0' + v / 100000000000000000ULL % 10;
  }
  if (p == 17) {
    *s++ = '.';
  }
  if (v >= 10000000000000000ULL || p >= 16) {
    *s++ = '0' + v / 10000000000000000ULL % 10;
  }
  if (p == 16) {
    *s++ = '.';
  }
  if (v >= 1000000000000000ULL || p >= 15) {
    *s++ = '0' + v / 1000000000000000ULL % 10;
  }
  if (p == 15) {
    *s++ = '.';
  }
  if (v >= 100000000000000ULL || p >= 14) {
    *s++ = '0' + v / 100000000000000ULL % 10;
  }
  if (p == 14) {
    *s++ = '.';
  }
  if (v >= 10000000000000ULL || p >= 13) {
    *s++ = '0' + v / 10000000000000ULL % 10;
  }
  if (p == 13) {
    *s++ = '.';
  }
  if (v >= 1000000000000ULL || p >= 12) {
    *s++ = '0' + v / 1000000000000ULL % 10;
  }
  if (p == 12) {
    *s++ = '.';
  }
  if (v >= 100000000000ULL || p >= 11) {
    *s++ = '0' + v / 100000000000ULL % 10;
  }
  if (p == 11) {
    *s++ = '.';
  }
  if (v >= 10000000000ULL || p >= 10) {
    *s++ = '0' + v / 10000000000ULL % 10;
  }
  if (p == 10) {
    *s++ = '.';
  }
  if (v >= 1000000000ULL || p >= 9) {
    *s++ = '0' + v / 1000000000ULL % 10;
  }
  if (p == 9) {
    *s++ = '.';
  }
  if (v >= 100000000ULL || p >= 8) {
    *s++ = '0' + v / 100000000ULL % 10;
  }
  if (p == 8) {
    *s++ = '.';
  }
  if (v >= 10000000ULL || p >= 7) {
    *s++ = '0' + v / 10000000ULL % 10;
  }
  if (p == 7) {
    *s++ = '.';
  }
  if (v >= 1000000ULL || p >= 6) {
    *s++ = '0' + v / 1000000ULL % 10;
  }
  if (p == 6) {
    *s++ = '.';
  }
  if (v >= 100000ULL || p >= 5) {
    *s++ = '0' + v / 100000ULL % 10;
  }
  if (p == 5) {
    *s++ = '.';
  }
  if (v >= 10000ULL || p >= 4) {
    *s++ = '0' + v / 10000ULL % 10;
  }
  if (p == 4) {
    *s++ = '.';
  }
  if (v >= 1000ULL || p >= 3) {
    *s++ = '0' + v / 1000ULL % 10;
  }
  if (p == 3) {
    *s++ = '.';
  }
  if (v >= 100ULL || p >= 2) {
    *s++ = '0' + v / 100ULL % 10;
  }
  if (p == 2) {
    *s++ = '.';
  }
  if (v >= 10ULL || p >= 1) {
    *s++ = '0' + v / 10ULL % 10;
  }
  if (p == 1) {
    *s++ = '.';
  }
  *s++ = '0' + v % 10;
  *s++ = ' ';

  // Symbol
  for (int i = 0; i < 7; i++) {
    char c = (char)((asset->symbol >> (i + 1) * 8) & 0xff);
    if (!('A' <= c && c <= 'Z') && c != 0) {
      memset(str, 0, EOS_ASSET_STR_SIZE);
      return false;  // Invalid symbol
    }
    *s++ = c;
  }

  return true;
}

/// Ported from EOSIO libraries/chain/name.cpp
bool eos_formatName(uint64_t name, char str[EOS_NAME_STR_SIZE]) {
  memset(str, '.', EOS_NAME_STR_SIZE);
  static const char *charmap = ".12345abcdefghijklmnopqrstuvwxyz";

  uint64_t tmp = name;
  for (uint32_t i = 0; i <= 12; ++i) {
    char c = charmap[tmp & (i == 0 ? 0x0f : 0x1f)];
    str[12 - i] = c;
    tmp >>= (i == 0 ? 4 : 5);
  }

  for (int i = 1; i <= EOS_NAME_STR_SIZE; i++) {
    if (str[EOS_NAME_STR_SIZE - i] != '.') break;
    str[EOS_NAME_STR_SIZE - i] = '\0';
  }

  return true;
}

bool eos_derivePublicKey(const uint32_t *addr_n, size_t addr_n_count,
                         uint8_t *public_key, size_t len) {
  if (len < sizeof(node.public_key)) return false;

  if (!eos_signingIsInited()) return false;

  memcpy(&node, &root, sizeof(node));
  if (hdnode_private_ckd_cached(&node, addr_n, addr_n_count, NULL) == 0) {
    fsm_sendFailure(FailureType_Failure_Other, "Child key derivation failed");
    eos_signingAbort();
    return false;
  }

  hdnode_fill_public_key(&node);
  memcpy(public_key, node.public_key, sizeof(node.public_key));
  memzero(&node, sizeof(node));
  return true;
}

bool eos_getPublicKey(const HDNode *n, const curve_info *curve,
                      EosPublicKeyKind kind, char *pubkey, size_t len) {
  (void)curve;
  return eos_publicKeyToWif(n->public_key, kind, pubkey, len);
}

bool eos_publicKeyToWif(const uint8_t *public_key, EosPublicKeyKind kind,
                        char *pubkey, size_t len) {
  const char *prefix = "";
  switch (kind) {
    case EosPublicKeyKind_EOS:
      prefix = "EOS";
      break;
    case EosPublicKeyKind_EOS_K1:
      prefix = "EOS_K1_";
      break;
    case EosPublicKeyKind_EOS_R1:
      return false;
    default:
      return false;
  }

  const size_t prefix_len = strlen(prefix);
  strlcpy(pubkey, prefix, len);

  if (!base58_encode_check(public_key, 33, HASHER_RIPEMD, pubkey + prefix_len,
                           len - prefix_len)) {
    return false;
  }

  return true;
}

// https://github.com/EOSIO/fc/blob/30eb81c1d995f9cd9834701e03b83ec7e6468a0f/include/fc/io/raw.hpp#L214
size_t eos_hashUInt(Hasher *hasher, uint64_t val) {
  size_t count = 0;
  do {
    uint8_t b = ((uint8_t)val) & 0x7f;
    val >>= 7;
    b |= ((val > 0) << 7);
    count++;
    if (hasher) hasher_Update(hasher, &b, 1);
  } while (val);
  return count;
}

void eos_signingInit(const uint8_t *chain_id, uint32_t num_actions,
                     const EosTxHeader *_header, const HDNode *_root,
                     const uint32_t _address_n[8], size_t _address_n_count) {
  hasher_Init(&hasher_preimage, HASHER_SHA2);

  memcpy(&header, _header, sizeof(header));
  memzero(&node, sizeof(node));
  memcpy(&root, _root, sizeof(root));
  memcpy(address_n, _address_n, sizeof(address_n));
  address_n_count = _address_n_count;

  hasher_Update(&hasher_preimage, chain_id, 32);
  hasher_Update(&hasher_preimage, (const uint8_t *)&header.expiration, 4);
  hasher_Update(&hasher_preimage, (const uint8_t *)&header.ref_block_num, 2);
  hasher_Update(&hasher_preimage, (const uint8_t *)&header.ref_block_prefix, 4);
  eos_hashUInt(&hasher_preimage, header.max_net_usage_words);
  hasher_Update(&hasher_preimage, (const uint8_t *)&header.max_cpu_usage_ms, 1);
  eos_hashUInt(&hasher_preimage, header.delay_sec);

  // context_free_actions. count, followed by each action
  eos_hashUInt(&hasher_preimage, 0);

  // actions. count, followed by each action
  eos_hashUInt(&hasher_preimage, num_actions);

  unknown_remaining = 0;
  unknown_total = 0;
  hasher_Init(&hasher_unknown, HASHER_SHA2);

  actions_remaining = num_actions;
  inited = true;
}

bool eos_signingIsInited(void) { return inited; }

bool eos_signingIsFinished(void) {
  return inited && actions_remaining == 0 && unknown_remaining == 0;
}

uint32_t eos_actionsRemaining(void) { return actions_remaining; }

void eos_signingAbort(void) {
  inited = false;
  memzero(&hasher_preimage, sizeof(hasher_preimage));
  memzero(&hasher_unknown, sizeof(hasher_unknown));
  memzero(&header, sizeof(header));
  memzero(&node, sizeof(node));
  memzero(&root, sizeof(root));
  memzero(address_n, sizeof(address_n));
  address_n_count = 0;
  actions_remaining = 0;
  unknown_remaining = 0;
  unknown_total = 0;
}

bool eos_compileAsset(const EosAsset *asset) {
  if (!asset->has_amount) return false;

  if (!asset->has_symbol) return false;

  hasher_Update(&hasher_preimage, (const uint8_t *)&asset->amount, 8);
  hasher_Update(&hasher_preimage, (const uint8_t *)&asset->symbol, 8);
  return true;
}

bool eos_compileString(const char *str) {
  if (!str) return false;
  uint32_t len = strlen(str);
  eos_hashUInt(&hasher_preimage, len);
  if (len) hasher_Update(&hasher_preimage, (const uint8_t *)str, len);
  return true;
}

bool eos_compileActionCommon(const EosActionCommon *common) {
  if (!(actions_remaining--)) return false;

  if (!common->has_account) return false;

  if (!common->has_name) return false;

  if (!common->authorization_count) return false;

  hasher_Update(&hasher_preimage, (const uint8_t *)&common->account, 8);
  hasher_Update(&hasher_preimage, (const uint8_t *)&common->name, 8);

  eos_hashUInt(&hasher_preimage, common->authorization_count);
  for (size_t i = 0; i < common->authorization_count; i++) {
    if (!eos_compilePermissionLevel(&common->authorization[i])) return false;
  }

  return true;
}

bool eos_compilePermissionLevel(const EosPermissionLevel *auth) {
  if (!auth->has_actor) return false;

  if (!auth->has_permission) return false;

  hasher_Update(&hasher_preimage, (const uint8_t *)&auth->actor, 8);
  hasher_Update(&hasher_preimage, (const uint8_t *)&auth->permission, 8);

  return true;
}

bool eos_hasActionUnknownDataRemaining(void) { return 0 < unknown_remaining; }

static bool isSupportedAction(const EosActionCommon *common) {
  if (common->account == EOS_eosio || common->account == EOS_eosio_token) {
    switch (common->name) {
      case EOS_Transfer:
      case EOS_Owner:
      case EOS_Active:
      case EOS_DelegateBW:
      case EOS_UndelegateBW:
      case EOS_Refund:
      case EOS_BuyRam:
      case EOS_BuyRamBytes:
      case EOS_SellRam:
      case EOS_VoteProducer:
      case EOS_UpdateAuth:
      case EOS_DeleteAuth:
      case EOS_LinkAuth:
      case EOS_UnlinkAuth:
        return true;
    }
  }
  return false;
}

bool eos_compileActionUnknown(const EosActionCommon *common,
                              const EosActionUnknown *action) {
  if (isSupportedAction(common)) {
    fsm_sendFailure(
        FailureType_Failure_SyntaxError,
        "EosActionUnknown cannot be used with supported contract actions");
    eos_signingAbort();
    return false;
  }

  if (!storage_isPolicyEnabled("AdvancedMode")) {
    (void)review(ButtonRequestType_ButtonRequest_Other, "Warning",
                 "Signing of arbitrary EOS actions is recommended only for "
                 "experienced users. Enable 'AdvancedMode' policy to dismiss.");
  }

  if (unknown_remaining == 0) {
    CHECK_PARAM_RET(eos_compileActionCommon(common),
                    "Cannot compile ActionCommon", false);

    hasher_Init(&hasher_unknown, HASHER_SHA2);

    unknown_total = unknown_remaining = action->data_size;
    eos_hashUInt(&hasher_preimage, action->data_size);
  } else if (action->data_size != unknown_total) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    "EosActionUnknown unexpected change in total length");
    eos_signingAbort();
    layoutHome();
    return false;
  }

  if (unknown_remaining < action->data_chunk.size) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    "EosActionUnknown unexpected data chunk size");
    eos_signingAbort();
    layoutHome();
    return false;
  }

  hasher_Update(&hasher_unknown, (const uint8_t *)action->data_chunk.bytes,
                action->data_chunk.size);
  hasher_Update(&hasher_preimage, (const uint8_t *)action->data_chunk.bytes,
                action->data_chunk.size);
  unknown_remaining -= action->data_chunk.size;

  if (unknown_remaining == 0) {
    char name[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(common->name, name), "Invalid name", false);

    char account[EOS_NAME_STR_SIZE];
    CHECK_PARAM_RET(eos_formatName(common->account, account), "Invalid name",
                    false);

    char title[MEDIUM_STR_BUF];
    snprintf(title, sizeof(title), "%s:%s", account, name);

    static uint8_t hash[32];
    hasher_Final(&hasher_unknown, hash);

    char hex[2][16 * 2 + 1];
    data2hex(hash, 16, hex[0]);
    data2hex(hash + 16, 16, hex[1]);

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmEosAction, title,
                 "%" PRIu32 " bytes with fingerprint:\n%s\n%s", unknown_total,
                 hex[0], hex[1])) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, "Action Cancelled");
      eos_signingAbort();
      layoutHome();
      return false;
    }
  }

  return true;
}

static int eos_is_canonic(uint8_t v, uint8_t signature[64]) {
  (void)v;
  return !(signature[0] & 0x80) &&
         !(signature[0] == 0 && !(signature[1] & 0x80)) &&
         !(signature[32] & 0x80) &&
         !(signature[32] == 0 && !(signature[33] & 0x80));
}

bool eos_signTx(EosSignedTx *tx) {
  memzero(tx, sizeof(*tx));

  if (!eos_signingIsInited()) {
    fsm_sendFailure(FailureType_Failure_Other, "Must call EosSignTx first");
    eos_signingAbort();
    return false;
  }

  // transaction_extensions. count, followed by data
  eos_hashUInt(&hasher_preimage, 0);

  // context_free_data. if nonempty, the sha256 digest of it. otherwise:
  hasher_Update(&hasher_preimage, (const uint8_t*)
                  "\x00\x00\x00\x00\x00\x00\x00\x00"
                  "\x00\x00\x00\x00\x00\x00\x00\x00"
                  "\x00\x00\x00\x00\x00\x00\x00\x00"
                  "\x00\x00\x00\x00\x00\x00\x00\x00", 32);

  char ram_limit[8 + 5 + 14 + 1] = "Unlimited RAM";
  if (header.max_net_usage_words) {
    snprintf(ram_limit, sizeof(ram_limit), "At most %" PRIu16 " bytes RAM",
             (uint16_t)header.max_net_usage_words);
  }

  char cpu_limit[8 + 5 + 11 + 1] = "Unlimited CPU";
  if (header.max_cpu_usage_ms) {
    snprintf(cpu_limit, sizeof(cpu_limit), "At most %" PRIu8 " ms CPU",
             (uint8_t)header.max_cpu_usage_ms);
  }

  if (!confirm(ButtonRequestType_ButtonRequest_ConfirmEosBudget,
               "Confirm Budget", "You may be billed for up to:\n%s\n%s",
               ram_limit, cpu_limit)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, "Action Cancelled");
    eos_signingAbort();
    return false;
  }

  time_t expiry = header.expiration;
  char expiry_str[26];
  asctime_r(gmtime(&expiry), expiry_str);
  expiry_str[24] = 0;  // cut off the '\n'
  uint32_t delay = header.delay_sec;
  if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Sign Transaction",
               "Do you want to sign this EOS transaction?\n"
               "Expiry: %s UTC\n"
               "Delay: %" PRIu32 "h%02" PRIu32 "m%02" PRIu32 "s",
               expiry_str, delay / 3600, (delay / 60) % 60, (delay % 60))) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, "Action Cancelled");
    eos_signingAbort();
    return false;
  }

  tx->has_hash = true;
  tx->hash.size = 32;
  hasher_Final(&hasher_preimage, tx->hash.bytes);

  memcpy(&node, &root, sizeof(node));
  if (hdnode_private_ckd_cached(&node, address_n, address_n_count, NULL) == 0) {
    fsm_sendFailure(FailureType_Failure_Other, "Child key derivation failed");
    eos_signingAbort();
    return false;
  }

  uint8_t sig[64];
  uint8_t pby;
  if (ecdsa_sign_digest(&secp256k1, node.private_key, tx->hash.bytes, sig, &pby,
                        eos_is_canonic) != 0) {
    fsm_sendFailure(FailureType_Failure_Other, "Signing failed");
    eos_signingAbort();
    return false;
  }
  memzero(&node, sizeof(node));
  memzero(&root, sizeof(root));

  tx->has_signature_v = true;
  tx->signature_v = 27 + pby + /*compressed=*/4;

  tx->has_signature_r = true;
  tx->signature_r.size = 32;
  memcpy(tx->signature_r.bytes, sig, 32);

  tx->has_signature_s = true;
  tx->signature_s.size = 32;
  memcpy(tx->signature_s.bytes, sig + 32, 32);

  return true;
}
