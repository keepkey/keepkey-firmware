/*
 * This file is part of the TREZOR project.
 *
 * Copyright (C) 2022 markrypto <cryptoakorn@gmail.com>
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
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

#include "keepkey/board/layout.h"
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/crypto.h"
#include "hwcrypto/crypto/address.h"
#include "hwcrypto/crypto/aes/aes.h"
#include "hwcrypto/crypto/base58.h"
#include "hwcrypto/crypto/bip32.h"
#include "hwcrypto/crypto/cash_addr.h"
#include "hwcrypto/crypto/curves.h"
#include "hwcrypto/crypto/hmac.h"
#include "hwcrypto/crypto/memzero.h"
#include "hwcrypto/crypto/pbkdf2.h"
#include "hwcrypto/crypto/secp256k1.h"
#include "hwcrypto/crypto/segwit_addr.h"
#include "hwcrypto/crypto/sha2.h"

#include <string.h>

uint32_t ser_length(uint32_t len, uint8_t *out) {
  if (len < 253) {
    out[0] = len & 0xFF;
    return 1;
  }
  if (len < 0x10000) {
    out[0] = 253;
    out[1] = len & 0xFF;
    out[2] = (len >> 8) & 0xFF;
    return 3;
  }
  out[0] = 254;
  out[1] = len & 0xFF;
  out[2] = (len >> 8) & 0xFF;
  out[3] = (len >> 16) & 0xFF;
  out[4] = (len >> 24) & 0xFF;
  return 5;
}

uint32_t ser_length_hash(Hasher *hasher, uint32_t len) {
  if (len < 253) {
    hasher_Update(hasher, (const uint8_t *)&len, 1);
    return 1;
  }
  if (len < 0x10000) {
    uint8_t d = 253;
    hasher_Update(hasher, &d, 1);
    hasher_Update(hasher, (const uint8_t *)&len, 2);
    return 3;
  }
  uint8_t d = 254;
  hasher_Update(hasher, &d, 1);
  hasher_Update(hasher, (const uint8_t *)&len, 4);
  return 5;
}

uint32_t deser_length(const uint8_t *in, uint32_t *out) {
  if (in[0] < 253) {
    *out = in[0];
    return 1;
  }
  if (in[0] == 253) {
    *out = in[1] + (in[2] << 8);
    return 1 + 2;
  }
  if (in[0] == 254) {
    *out = in[1] + (in[2] << 8) + (in[3] << 16) + ((uint32_t)in[4] << 24);
    return 1 + 4;
  }
  *out = 0;  // ignore 64 bit
  return 1 + 8;
}

int sshMessageSign(HDNode *node, const uint8_t *message, size_t message_len,
                   uint8_t *signature) {
  signature[0] = 0;  // prefix: pad with zero, so all signatures are 65 bytes
  return hdnode_sign(node, message, message_len, HASHER_SHA2, signature + 1,
                     NULL, NULL);
}

int gpgMessageSign(HDNode *node, const uint8_t *message, size_t message_len,
                   uint8_t *signature) {
  signature[0] = 0;  // prefix: pad with zero, so all signatures are 65 bytes
  const curve_info *ed25519_curve_info = get_curve_by_name(ED25519_NAME);
  if (ed25519_curve_info && node->curve == ed25519_curve_info) {
    // GPG supports variable size digest for Ed25519 signatures
    return hdnode_sign(node, message, message_len, 0, signature + 1, NULL,
                       NULL);
  } else {
    // Ensure 256-bit digest before proceeding
    if (message_len != 32) {
      return 1;
    }
    return hdnode_sign_digest(node, message, signature + 1, NULL, NULL);
  }
}

int cryptoGetECDHSessionKey(const HDNode *node, const uint8_t *peer_public_key,
                            uint8_t *session_key) {
  curve_point point;
  const ecdsa_curve *curve = node->curve->params;
  if (!ecdsa_read_pubkey(curve, peer_public_key, &point)) {
    return 1;
  }
  bignum256 k;
  bn_read_be(node->private_key, &k);
  point_multiply(curve, &k, &point, &point);
  memzero(&k, sizeof(k));

  session_key[0] = 0x04;
  bn_write_be(&point.x, session_key + 1);
  bn_write_be(&point.y, session_key + 33);
  memzero(&point, sizeof(point));
  return 0;
}

_Static_assert(sizeof(((CoinType *)0)->signed_message_header) < 256,
               "Message header too long");

static void cryptoMessageHash(const CoinType *coin, const curve_info *curve,
                              const uint8_t *message, size_t message_len,
                              uint8_t hash[HASHER_DIGEST_LENGTH]) {
  Hasher hasher;
  hasher_Init(&hasher, curve->hasher_sign);
  uint8_t header_len = strlen(coin->signed_message_header);
  hasher_Update(&hasher, &header_len, 1);
  hasher_Update(&hasher, (const uint8_t *)coin->signed_message_header,
                strlen(coin->signed_message_header));
  uint8_t varint[5];
  uint32_t l = ser_length(message_len, varint);
  hasher_Update(&hasher, varint, l);
  hasher_Update(&hasher, message, message_len);
  hasher_Final(&hasher, hash);
}

int cryptoMessageSign(const CoinType *coin, HDNode *node,
                      InputScriptType script_type, const uint8_t *message,
                      size_t message_len, uint8_t *signature) {
  const curve_info *curve = get_curve_by_name(coin->curve_name);
  if (!curve) return 1;

  if (!coin->has_signed_message_header) return 1;

  uint8_t hash[HASHER_DIGEST_LENGTH];
  cryptoMessageHash(coin, curve, message, message_len, hash);

  uint8_t pby;
  int result = hdnode_sign_digest(node, hash, signature + 1, &pby, NULL);
  if (result == 0) {
    switch (script_type) {
      case InputScriptType_SPENDP2SHWITNESS:
        // segwit-in-p2sh
        signature[0] = 35 + pby;
        break;
      case InputScriptType_SPENDWITNESS:
        // segwit
        signature[0] = 39 + pby;
        break;
      default:
        // p2pkh
        signature[0] = 31 + pby;
        break;
    }
  }
  return result;
}

int cryptoMessageVerify(const CoinType *coin, const uint8_t *message,
                        size_t message_len, const char *address,
                        const uint8_t *signature) {
  // check for invalid signature prefix
  if (signature[0] < 27 || signature[0] > 43) {
    return 1;
  }

  const curve_info *curve = get_curve_by_name(coin->curve_name);
  if (!curve) return 1;

  if (!coin->has_signed_message_header) return 1;

  uint8_t hash[HASHER_DIGEST_LENGTH];
  cryptoMessageHash(coin, curve, message, message_len, hash);

  uint8_t recid = (signature[0] - 27) % 4;
  bool compressed = signature[0] >= 31;

  // check if signature verifies the digest and recover the public key
  uint8_t pubkey[65];
  if (!curve->params ||
      ecdsa_recover_pub_from_sig(curve->params, pubkey, signature + 1, hash,
                                 recid) != 0) {
    return 3;
  }
  // convert public key to compressed pubkey if necessary
  if (compressed) {
    pubkey[0] = 0x02 | (pubkey[64] & 1);
  }

  // check if the address is correct
  uint8_t addr_raw[MAX_ADDR_RAW_SIZE];
  uint8_t recovered_raw[MAX_ADDR_RAW_SIZE];

  // p2pkh
  if (signature[0] >= 27 && signature[0] <= 34) {
    size_t len;
    if (coin->has_cashaddr_prefix) {
      if (!cash_addr_decode(addr_raw, &len, coin->cashaddr_prefix, address)) {
        return 2;
      }
    } else {
      len = base58_decode_check(address, curve->hasher_base58, addr_raw,
                                MAX_ADDR_RAW_SIZE);
    }
    ecdsa_get_address_raw(pubkey, coin->address_type, curve->hasher_pubkey,
                          recovered_raw);
    if (memcmp(recovered_raw, addr_raw, len) != 0 ||
        len != address_prefix_bytes_len(coin->address_type) + 20) {
      return 2;
    }
  } else
      // segwit-in-p2sh
      if (signature[0] >= 35 && signature[0] <= 38) {
    size_t len = base58_decode_check(address, curve->hasher_base58, addr_raw,
                                     MAX_ADDR_RAW_SIZE);
    ecdsa_get_address_segwit_p2sh_raw(pubkey, coin->address_type_p2sh,
                                      curve->hasher_pubkey, recovered_raw);
    if (memcmp(recovered_raw, addr_raw, len) != 0 ||
        len != address_prefix_bytes_len(coin->address_type_p2sh) + 20) {
      return 2;
    }
  } else
      // segwit
      if (signature[0] >= 39 && signature[0] <= 42) {
    int witver;
    size_t len;
    if (!coin->has_bech32_prefix ||
        !segwit_addr_decode(&witver, recovered_raw, &len, coin->bech32_prefix,
                            address)) {
      return 4;
    }
    ecdsa_get_pubkeyhash(pubkey, curve->hasher_pubkey, addr_raw);
    if (memcmp(recovered_raw, addr_raw, len) != 0 || witver != 0 || len != 20) {
      return 2;
    }
  } else {
    return 4;
  }

  return 0;
}

uint8_t *cryptoHDNodePathToPubkey(const CoinType *coin,
                                  const HDNodePathType *hdnodepath) {
  if (!hdnodepath ||
      !hdnodepath->node.has_public_key ||
      hdnodepath->node.public_key.size != 33) {
    return 0;
  }

  static HDNode node;
  if (hdnode_from_xpub(hdnodepath->node.depth, hdnodepath->node.child_num,
                       hdnodepath->node.chain_code.bytes,
                       hdnodepath->node.public_key.bytes, coin->curve_name,
                       &node) == 0) {
    return 0;
  }
  animating_progress_handler("Deriving pubkey...", 0);
  for (uint32_t i = 0; i < hdnodepath->address_n_count; i++) {
    if (hdnode_public_ckd(&node, hdnodepath->address_n[i]) == 0) {
      return 0;
    }
    animating_progress_handler("Deriving pubkey...",
                               (i * 1000) / hdnodepath->address_n_count);
  }
  return node.public_key;
}

int cryptoMultisigPubkeyIndex(const CoinType *coin,
                              const MultisigRedeemScriptType *multisig,
                              const uint8_t *pubkey) {
  for (size_t i = 0; i < multisig->pubkeys_count; i++) {
    const uint8_t *node_pubkey =
        cryptoHDNodePathToPubkey(coin, &(multisig->pubkeys[i]));
    if (node_pubkey && memcmp(node_pubkey, pubkey, 33) == 0) {
      return i;
    }
  }
  return -1;
}

int cryptoMultisigFingerprint(const MultisigRedeemScriptType *multisig,
                              uint8_t *hash) {
  static const HDNodePathType *ptr[15], *swap;
  const uint32_t n = multisig->pubkeys_count;
  if (n < 1 || n > 15) {
    return 0;
  }
  // check sanity
  if (!multisig->has_m || multisig->m < 1 || multisig->m > 15) return 0;
  for (uint32_t i = 0; i < n; i++) {
    ptr[i] = &(multisig->pubkeys[i]);
    if (!ptr[i]->node.has_public_key || ptr[i]->node.public_key.size != 33)
      return 0;
    if (ptr[i]->node.chain_code.size != 32) return 0;
  }
  animating_progress_handler("Calculating multisig fingerprint...", 0);
  // minsort according to pubkey
  for (uint32_t i = 0; i < n - 1; i++) {
    for (uint32_t j = n - 1; j > i; j--) {
      if (memcmp(ptr[i]->node.public_key.bytes, ptr[j]->node.public_key.bytes,
                 33) > 0) {
        swap = ptr[i];
        ptr[i] = ptr[j];
        ptr[j] = swap;
      }
    }
  }
  // hash sorted nodes
  SHA256_CTX ctx;
  sha256_Init(&ctx);
  sha256_Update(&ctx, (const uint8_t *)&(multisig->m), sizeof(uint32_t));
  for (uint32_t i = 0; i < n; i++) {
    animating_progress_handler("Calculating multisig fingerprint...",
                               (i * 1000) / n);
    sha256_Update(&ctx, (const uint8_t *)&(ptr[i]->node.depth),
                  sizeof(uint32_t));
    sha256_Update(&ctx, (const uint8_t *)&(ptr[i]->node.fingerprint),
                  sizeof(uint32_t));
    sha256_Update(&ctx, (const uint8_t *)&(ptr[i]->node.child_num),
                  sizeof(uint32_t));
    sha256_Update(&ctx, ptr[i]->node.chain_code.bytes, 32);
    sha256_Update(&ctx, ptr[i]->node.public_key.bytes, 33);
  }
  sha256_Update(&ctx, (const uint8_t *)&n, sizeof(uint32_t));
  sha256_Final(&ctx, hash);
  animating_progress_handler("Calculating multisig fingerprint...", 100 * 1000);
  return 1;
}

int cryptoIdentityFingerprint(const IdentityType *identity, uint8_t *hash) {
  SHA256_CTX ctx;
  sha256_Init(&ctx);
  sha256_Update(&ctx, (const uint8_t *)&(identity->index), sizeof(uint32_t));
  if (identity->has_proto && identity->proto[0]) {
    sha256_Update(&ctx, (const uint8_t *)(identity->proto),
                  strlen(identity->proto));
    sha256_Update(&ctx, (const uint8_t *)"://", 3);
  }
  if (identity->has_user && identity->user[0]) {
    sha256_Update(&ctx, (const uint8_t *)(identity->user),
                  strlen(identity->user));
    sha256_Update(&ctx, (const uint8_t *)"@", 1);
  }
  if (identity->has_host && identity->host[0]) {
    sha256_Update(&ctx, (const uint8_t *)(identity->host),
                  strlen(identity->host));
  }
  if (identity->has_port && identity->port[0]) {
    sha256_Update(&ctx, (const uint8_t *)":", 1);
    sha256_Update(&ctx, (const uint8_t *)(identity->port),
                  strlen(identity->port));
  }
  if (identity->has_path && identity->path[0]) {
    sha256_Update(&ctx, (const uint8_t *)(identity->path),
                  strlen(identity->path));
  }
  sha256_Final(&ctx, hash);
  return 1;
}
