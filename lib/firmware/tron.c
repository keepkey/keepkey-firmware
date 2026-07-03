/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2024 KeepKey
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

#include "keepkey/firmware/tron.h"

#include "keepkey/crypto/curves.h"
#include "trezor/crypto/base58.h"
#include "trezor/crypto/bignum.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/secp256k1.h"
#include "trezor/crypto/sha3.h"

#include <stdint.h>
#include <string.h>

#define TRON_ADDRESS_PREFIX 0x41  // Mainnet addresses start with 'T'

/**
 * Generate TRON address from secp256k1 public key
 * TRON uses Keccak256(uncompressed_pubkey) and takes last 20 bytes,
 * then prepends 0x41 and Base58Check encodes it
 */
bool tron_getAddress(const uint8_t public_key[33], char* address,
                     size_t address_len) {
  if (address_len < TRON_ADDRESS_MAX_LEN) {
    return false;
  }

  uint8_t uncompressed_pubkey[65];
  uint8_t hash[32];
  uint8_t addr_bytes[21];

  // Uncompress the public key
  if (!ecdsa_uncompress_pubkey(&secp256k1, public_key, uncompressed_pubkey)) {
    return false;
  }

  // Keccak256 hash of uncompressed public key (skip first 0x04 byte)
  keccak_256(uncompressed_pubkey + 1, 64, hash);

  // Take last 20 bytes of hash and prepend TRON prefix byte
  addr_bytes[0] = TRON_ADDRESS_PREFIX;
  memcpy(addr_bytes + 1, hash + 12, 20);

  // Base58Check encode with double SHA256
  if (!base58_encode_check(addr_bytes, 21, HASHER_SHA2D, address,
                           address_len)) {
    return false;
  }

  // Clean up sensitive data
  memzero(uncompressed_pubkey, sizeof(uncompressed_pubkey));
  memzero(hash, sizeof(hash));

  return true;
}

/**
 * Format TRON amount (SUN) for display
 * 1 TRX = 1,000,000 SUN
 */
void tron_formatAmount(char* buf, size_t len, uint64_t amount) {
  bignum256 val;
  bn_read_uint64(amount, &val);
  bn_format(&val, NULL, " TRX", TRON_DECIMALS, 0, false, buf, len);
}

bool tron_addressFromBytes(const uint8_t addr[TRON_RAW_ADDRESS_SIZE],
                           char* out, size_t out_len) {
  return base58_encode_check(addr, TRON_RAW_ADDRESS_SIZE, HASHER_SHA2D, out,
                             out_len);
}

bool tron_formatTrc20Amount(const uint8_t amount_be[32], char* buf,
                            size_t len) {
  bignum256 val;
  bn_read_be(amount_be, &val);
  return bn_format(&val, NULL, NULL, 0, 0, false, buf, len);
}

/* ------------------------------------------------------------------ */
/*  raw_data protobuf parser                                           */
/*                                                                     */
/*  The device signs sha256(raw_data), so display decisions are made   */
/*  from these exact bytes. Minimal protobuf wire-format reader —      */
/*  fail-closed: anything not fully understood ends TRON_TX_UNVERIFIED */
/* ------------------------------------------------------------------ */

/* TRON protocol.Transaction.raw field numbers */
#define TRON_RAW_REF_BLOCK_BYTES 1
#define TRON_RAW_REF_BLOCK_NUM 3
#define TRON_RAW_REF_BLOCK_HASH 4
#define TRON_RAW_EXPIRATION 8
#define TRON_RAW_DATA 10 /* memo */
#define TRON_RAW_CONTRACT 11
#define TRON_RAW_TIMESTAMP 14
#define TRON_RAW_FEE_LIMIT 18

/* protocol.Transaction.Contract */
#define TRON_CONTRACT_TYPE 1
#define TRON_CONTRACT_PARAMETER 2

/* google.protobuf.Any */
#define TRON_ANY_TYPE_URL 1
#define TRON_ANY_VALUE 2

/* protocol.Transaction.Contract.ContractType enum values */
#define TRON_CT_TRANSFER_CONTRACT 1
#define TRON_CT_TRIGGER_SMART_CONTRACT 31

/* TRC-20 transfer(address,uint256) selector */
static const uint8_t TRC20_TRANSFER_SELECTOR[4] = {0xa9, 0x05, 0x9c, 0xbb};

static bool pb_read_varint(const uint8_t* buf, size_t len, size_t* pos,
                           uint64_t* out) {
  uint64_t val = 0;
  for (unsigned shift = 0; shift < 64; shift += 7) {
    if (*pos >= len) return false;
    uint8_t b = buf[(*pos)++];
    uint8_t payload = b & 0x7f;
    if (shift == 63 && payload > 1) {
      /* The 10th byte can only contribute bit 63 to a 64-bit value
       * (63 + 7 > 64); any payload bit above bit 0 here claims more
       * precision than 64 bits hold. The shift below would silently
       * drop those bits rather than reject them, letting a malformed
       * key/length/amount/fee varint parse as if it were well-formed
       * — reject instead of truncating. */
      return false;
    }
    val |= (uint64_t)payload << shift;
    if (!(b & 0x80)) {
      *out = val;
      return true;
    }
  }
  return false; /* varint too long / overflows 64 bits */
}

static bool pb_read_key(const uint8_t* buf, size_t len, size_t* pos,
                        uint32_t* field, uint8_t* wire) {
  uint64_t key;
  if (!pb_read_varint(buf, len, pos, &key)) return false;
  *wire = (uint8_t)(key & 0x7);
  if ((key >> 3) > UINT32_MAX) return false;
  *field = (uint32_t)(key >> 3);
  return *field != 0;
}

static bool pb_read_bytes(const uint8_t* buf, size_t len, size_t* pos,
                          const uint8_t** out, size_t* out_len) {
  uint64_t blen;
  if (!pb_read_varint(buf, len, pos, &blen)) return false;
  if (blen > len - *pos) return false;
  *out = buf + *pos;
  *out_len = (size_t)blen;
  *pos += (size_t)blen;
  return true;
}

static bool pb_skip(const uint8_t* buf, size_t len, size_t* pos,
                    uint8_t wire) {
  uint64_t dummy;
  const uint8_t* bp;
  size_t bl;
  switch (wire) {
    case 0: /* varint */
      return pb_read_varint(buf, len, pos, &dummy);
    case 1: /* fixed64 */
      if (len - *pos < 8) return false;
      *pos += 8;
      return true;
    case 2: /* length-delimited */
      return pb_read_bytes(buf, len, pos, &bp, &bl);
    case 5: /* fixed32 */
      if (len - *pos < 4) return false;
      *pos += 4;
      return true;
    default:
      return false;
  }
}

static bool tron_isRawAddress(const uint8_t* p, size_t len) {
  return len == TRON_RAW_ADDRESS_SIZE && p[0] == TRON_ADDRESS_PREFIX;
}

/* Parse protocol.TransferContract { owner_address=1, to_address=2, amount=3 } */
static bool tron_parseTransferContract(const uint8_t* buf, size_t len,
                                       TronParsedTx* out) {
  size_t pos = 0;
  bool has_owner = false, has_to = false, has_amount = false;
  while (pos < len) {
    uint32_t field;
    uint8_t wire;
    if (!pb_read_key(buf, len, &pos, &field, &wire)) return false;
    const uint8_t* bp;
    size_t bl;
    uint64_t v;
    if (field == 1 && wire == 2) {
      if (!pb_read_bytes(buf, len, &pos, &bp, &bl)) return false;
      if (!tron_isRawAddress(bp, bl) || has_owner) return false;
      memcpy(out->owner, bp, TRON_RAW_ADDRESS_SIZE);
      has_owner = true;
    } else if (field == 2 && wire == 2) {
      if (!pb_read_bytes(buf, len, &pos, &bp, &bl)) return false;
      if (!tron_isRawAddress(bp, bl) || has_to) return false;
      memcpy(out->to, bp, TRON_RAW_ADDRESS_SIZE);
      has_to = true;
    } else if (field == 3 && wire == 0) {
      if (!pb_read_varint(buf, len, &pos, &v) || has_amount) return false;
      if (v > INT64_MAX) return false;
      out->amount = v;
      has_amount = true;
    } else {
      /* Unknown field in a value-moving payload: refuse to summarize. */
      return false;
    }
  }
  return has_owner && has_to && has_amount;
}

/* Parse protocol.TriggerSmartContract:
 *   owner_address=1, contract_address=2, call_value=3, data=4,
 *   call_token_value=5, token_id=6
 * Only a plain TRC-20 transfer(address,uint256) with zero call_value and
 * no TRC-10 tokens attached is considered verified. */
static bool tron_parseTriggerSmartContract(const uint8_t* buf, size_t len,
                                           TronParsedTx* out) {
  size_t pos = 0;
  bool has_owner = false, has_contract = false, has_data = false;
  const uint8_t* data = NULL;
  size_t data_len = 0;
  while (pos < len) {
    uint32_t field;
    uint8_t wire;
    if (!pb_read_key(buf, len, &pos, &field, &wire)) return false;
    const uint8_t* bp;
    size_t bl;
    uint64_t v;
    if (field == 1 && wire == 2) {
      if (!pb_read_bytes(buf, len, &pos, &bp, &bl)) return false;
      if (!tron_isRawAddress(bp, bl) || has_owner) return false;
      memcpy(out->owner, bp, TRON_RAW_ADDRESS_SIZE);
      has_owner = true;
    } else if (field == 2 && wire == 2) {
      if (!pb_read_bytes(buf, len, &pos, &bp, &bl)) return false;
      if (!tron_isRawAddress(bp, bl) || has_contract) return false;
      memcpy(out->contract, bp, TRON_RAW_ADDRESS_SIZE);
      has_contract = true;
    } else if (field == 3 && wire == 0) {
      /* call_value: transfer(address,uint256) is non-payable — any TRX
       * attached to the call is something we can't explain to the user. */
      if (!pb_read_varint(buf, len, &pos, &v)) return false;
      if (v != 0) return false;
    } else if (field == 4 && wire == 2) {
      if (!pb_read_bytes(buf, len, &pos, &data, &data_len) || has_data)
        return false;
      has_data = true;
    } else {
      /* token_id / call_token_value / anything else: refuse. */
      return false;
    }
  }
  if (!has_owner || !has_contract || !has_data) return false;

  /* data must be exactly selector + address word + amount word */
  if (data_len != 4 + 32 + 32) return false;
  if (memcmp(data, TRC20_TRANSFER_SELECTOR, 4) != 0) return false;

  /* Address word: 12 zero bytes then the 20-byte address. TRON tooling
   * sometimes writes the 0x41 network prefix at byte 11; the TVM decodes
   * only the low 160 bits, so accept 0x41 there and nothing else. */
  const uint8_t* word = data + 4;
  for (int i = 0; i < 11; i++) {
    if (word[i] != 0) return false;
  }
  if (word[11] != 0 && word[11] != TRON_ADDRESS_PREFIX) return false;

  out->to[0] = TRON_ADDRESS_PREFIX;
  memcpy(out->to + 1, word + 12, 20);
  memcpy(out->trc20_amount, data + 4 + 32, 32);
  return true;
}

/* Parse Contract { type=1, parameter=2 (Any) }; enum type and the Any
 * type_url must agree, otherwise refuse. */
static TronTxType tron_parseContract(const uint8_t* buf, size_t len,
                                     TronParsedTx* out) {
  size_t pos = 0;
  uint64_t ctype = 0;
  bool has_type = false;
  const uint8_t* value = NULL;
  size_t value_len = 0;
  const uint8_t* type_url = NULL;
  size_t type_url_len = 0;

  while (pos < len) {
    uint32_t field;
    uint8_t wire;
    if (!pb_read_key(buf, len, &pos, &field, &wire))
      return TRON_TX_UNVERIFIED;
    if (field == TRON_CONTRACT_TYPE && wire == 0) {
      if (!pb_read_varint(buf, len, &pos, &ctype) || has_type)
        return TRON_TX_UNVERIFIED;
      has_type = true;
    } else if (field == TRON_CONTRACT_PARAMETER && wire == 2) {
      const uint8_t* any;
      size_t any_len;
      if (!pb_read_bytes(buf, len, &pos, &any, &any_len) || value)
        return TRON_TX_UNVERIFIED;
      size_t apos = 0;
      while (apos < any_len) {
        uint32_t afield;
        uint8_t awire;
        if (!pb_read_key(any, any_len, &apos, &afield, &awire))
          return TRON_TX_UNVERIFIED;
        if (afield == TRON_ANY_TYPE_URL && awire == 2) {
          if (type_url ||
              !pb_read_bytes(any, any_len, &apos, &type_url, &type_url_len))
            return TRON_TX_UNVERIFIED;
        } else if (afield == TRON_ANY_VALUE && awire == 2) {
          if (value ||
              !pb_read_bytes(any, any_len, &apos, &value, &value_len))
            return TRON_TX_UNVERIFIED;
        } else {
          return TRON_TX_UNVERIFIED;
        }
      }
      if (!value) return TRON_TX_UNVERIFIED;
    } else {
      /* Permission_id (multisig), provider, ContractName, unknown: refuse. */
      return TRON_TX_UNVERIFIED;
    }
  }
  if (!has_type || !value || !type_url) return TRON_TX_UNVERIFIED;

  /* type_url ends with "/protocol.<Name>"; require agreement with enum */
  const char* expect_suffix;
  if (ctype == TRON_CT_TRANSFER_CONTRACT) {
    expect_suffix = "/protocol.TransferContract";
  } else if (ctype == TRON_CT_TRIGGER_SMART_CONTRACT) {
    expect_suffix = "/protocol.TriggerSmartContract";
  } else {
    return TRON_TX_UNVERIFIED;
  }
  size_t suffix_len = strlen(expect_suffix);
  if (type_url_len < suffix_len ||
      memcmp(type_url + type_url_len - suffix_len, expect_suffix,
             suffix_len) != 0) {
    return TRON_TX_UNVERIFIED;
  }

  if (ctype == TRON_CT_TRANSFER_CONTRACT) {
    return tron_parseTransferContract(value, value_len, out)
               ? TRON_TX_TRANSFER
               : TRON_TX_UNVERIFIED;
  }
  return tron_parseTriggerSmartContract(value, value_len, out)
             ? TRON_TX_TRC20_TRANSFER
             : TRON_TX_UNVERIFIED;
}

TronTxType tron_parseRawTx(const uint8_t* raw, size_t len, TronParsedTx* out) {
  memset(out, 0, sizeof(*out));
  if (!raw || len == 0) return TRON_TX_UNVERIFIED;

  size_t pos = 0;
  const uint8_t* contract = NULL;
  size_t contract_len = 0;

  while (pos < len) {
    uint32_t field;
    uint8_t wire;
    if (!pb_read_key(raw, len, &pos, &field, &wire)) goto unverified;
    switch (field) {
      case TRON_RAW_REF_BLOCK_BYTES:
      case TRON_RAW_REF_BLOCK_HASH:
        if (wire != 2 || !pb_skip(raw, len, &pos, wire)) goto unverified;
        break;
      case TRON_RAW_REF_BLOCK_NUM:
      case TRON_RAW_EXPIRATION:
      case TRON_RAW_TIMESTAMP:
        if (wire != 0 || !pb_skip(raw, len, &pos, wire)) goto unverified;
        break;
      case TRON_RAW_DATA: {
        const uint8_t* bp;
        size_t bl;
        if (wire != 2 || out->memo ||
            !pb_read_bytes(raw, len, &pos, &bp, &bl) || bl > UINT16_MAX)
          goto unverified;
        out->memo = bp;
        out->memo_len = (uint16_t)bl;
        break;
      }
      case TRON_RAW_CONTRACT:
        /* exactly one contract may be displayed truthfully */
        if (wire != 2 || contract ||
            !pb_read_bytes(raw, len, &pos, &contract, &contract_len))
          goto unverified;
        break;
      case TRON_RAW_FEE_LIMIT: {
        uint64_t v;
        if (wire != 0 || out->has_fee_limit ||
            !pb_read_varint(raw, len, &pos, &v) || v > INT64_MAX)
          goto unverified;
        out->fee_limit = v;
        out->has_fee_limit = true;
        break;
      }
      default:
        /* auths, scripts, future fields: can change meaning — refuse. */
        goto unverified;
    }
  }

  if (!contract) goto unverified;
  out->type = tron_parseContract(contract, contract_len, out);
  if (out->type == TRON_TX_UNVERIFIED) goto unverified;
  return out->type;

unverified:
  /* Preserve nothing from a failed parse except the classification. */
  memset(out, 0, sizeof(*out));
  out->type = TRON_TX_UNVERIFIED;
  return TRON_TX_UNVERIFIED;
}

/**
 * Sign a TRON transaction with secp256k1
 */
bool tron_signTx(const HDNode* node, const TronSignTx* msg,
                 TronSignedTx* resp) {
  if (!node || !msg || !resp) {
    return false;
  }

  // Verify we have raw transaction data
  if (!msg->has_raw_data || msg->raw_data.size == 0) {
    return false;
  }

  // Get the curve for secp256k1
  const curve_info* curve = get_curve_by_name(SECP256K1_NAME);
  if (!curve) {
    return false;
  }

  // Hash the transaction with SHA256
  uint8_t hash[32];
  sha256_Raw(msg->raw_data.bytes, msg->raw_data.size, hash);

  // Sign with secp256k1 (recoverable signature: 65 bytes including recovery
  // ID)
  uint8_t sig[65];
  uint8_t pby;

  if (ecdsa_sign_digest(&secp256k1, node->private_key, hash, sig, &pby, NULL) !=
      0) {
    memzero(hash, sizeof(hash));
    return false;
  }

  // Convert to recoverable signature format (r + s + recovery_id)
  // The recovery ID allows recovering the public key from the signature
  sig[64] = pby;

  // Copy signature to response (65 bytes)
  resp->has_signature = true;
  resp->signature.size = 65;
  memcpy(resp->signature.bytes, sig, 65);

  // Clean up sensitive data
  memzero(hash, sizeof(hash));
  memzero(sig, sizeof(sig));

  return true;
}

static int tron_is_canonic(uint8_t v, uint8_t signature[64]) {
  // Match ethereum_is_canonic: accept only recovery IDs 0 and 1 (reject
  // 2 and 3). Mirrors verifier expectations across the TRON/EVM ecosystem.
  // Returning non-zero means "canonical, accept"; ecdsa_sign_digest retries
  // when this returns 0, so a permanent 0 here causes signing to fail.
  (void)signature;
  return (v & 2) == 0;
}

/**
 * Compute the TIP-191 personal_sign hash:
 *   keccak256("\x19TRON Signed Message:\n" || ASCII(len) || message)
 *
 * Mirrors ethereum_message_hash() — only the prefix differs.
 */
static void tron_message_hash(const uint8_t* message, size_t message_len,
                              uint8_t hash[32]) {
  struct SHA3_CTX ctx;
  uint8_t c;

  sha3_256_Init(&ctx);
  sha3_Update(&ctx, (const uint8_t*)"\x19" "TRON Signed Message:\n", 22);
  if (message_len >= 1000000000) {
    c = '0' + message_len / 1000000000 % 10;
    sha3_Update(&ctx, &c, 1);
  }
  if (message_len >= 100000000) {
    c = '0' + message_len / 100000000 % 10;
    sha3_Update(&ctx, &c, 1);
  }
  if (message_len >= 10000000) {
    c = '0' + message_len / 10000000 % 10;
    sha3_Update(&ctx, &c, 1);
  }
  if (message_len >= 1000000) {
    c = '0' + message_len / 1000000 % 10;
    sha3_Update(&ctx, &c, 1);
  }
  if (message_len >= 100000) {
    c = '0' + message_len / 100000 % 10;
    sha3_Update(&ctx, &c, 1);
  }
  if (message_len >= 10000) {
    c = '0' + message_len / 10000 % 10;
    sha3_Update(&ctx, &c, 1);
  }
  if (message_len >= 1000) {
    c = '0' + message_len / 1000 % 10;
    sha3_Update(&ctx, &c, 1);
  }
  if (message_len >= 100) {
    c = '0' + message_len / 100 % 10;
    sha3_Update(&ctx, &c, 1);
  }
  if (message_len >= 10) {
    c = '0' + message_len / 10 % 10;
    sha3_Update(&ctx, &c, 1);
  }
  c = '0' + message_len % 10;
  sha3_Update(&ctx, &c, 1);
  sha3_Update(&ctx, message, message_len);
  keccak_Final(&ctx, hash);
}

/**
 * Sign an arbitrary message under TIP-191 personal_sign.
 * Output signature is 65 bytes (r || s || v) where v = 27 + recovery_id.
 */
bool tron_message_sign(const HDNode* node, const TronSignMessage* msg,
                       TronMessageSignature* resp) {
  if (!node || !msg || !resp) {
    return false;
  }

  // Caller must have populated node->public_key (hdnode_fill_public_key).
  char address[TRON_ADDRESS_MAX_LEN];
  if (!tron_getAddress(node->public_key, address, sizeof(address))) {
    return false;
  }

  uint8_t hash[32];
  tron_message_hash(msg->message.bytes, msg->message.size, hash);

  uint8_t v;
  if (ecdsa_sign_digest(&secp256k1, node->private_key, hash,
                        resp->signature.bytes, &v, tron_is_canonic) != 0) {
    memzero(hash, sizeof(hash));
    return false;
  }

  resp->signature.bytes[64] = 27 + v;
  resp->signature.size = 65;
  resp->has_signature = true;

  strlcpy(resp->address, address, sizeof(resp->address));
  resp->has_address = true;

  memzero(hash, sizeof(hash));
  return true;
}

/**
 * Verify a TIP-191 signature against the claimed Base58Check TRON address.
 * Returns 0 on success, non-zero on malformed input or signature mismatch.
 */
int tron_message_verify(const TronVerifyMessage* msg) {
  if (!msg || msg->signature.size != 65) {
    return 1;
  }

  uint8_t pubkey[65];
  uint8_t hash[32];

  tron_message_hash(msg->message.bytes, msg->message.size, hash);

  uint8_t v = msg->signature.bytes[64];
  if (v >= 27) {
    v -= 27;
  }
  if (v >= 2 || ecdsa_recover_pub_from_sig(
                    &secp256k1, pubkey, msg->signature.bytes, hash, v) != 0) {
    memzero(hash, sizeof(hash));
    return 2;
  }

  uint8_t addr_hash[32];
  keccak_256(pubkey + 1, 64, addr_hash);

  uint8_t addr_bytes[21];
  addr_bytes[0] = TRON_ADDRESS_PREFIX;
  memcpy(addr_bytes + 1, addr_hash + 12, 20);

  char recovered_addr[TRON_ADDRESS_MAX_LEN];
  if (!base58_encode_check(addr_bytes, 21, HASHER_SHA2D, recovered_addr,
                           sizeof(recovered_addr))) {
    memzero(hash, sizeof(hash));
    memzero(addr_hash, sizeof(addr_hash));
    return 2;
  }

  int rv = (strcmp(recovered_addr, msg->address) != 0) ? 2 : 0;

  memzero(hash, sizeof(hash));
  memzero(addr_hash, sizeof(addr_hash));
  return rv;
}

/**
 * Compute the TIP-712 typed-data digest:
 *   keccak256("\x19\x01" || domain_separator_hash || message_hash)
 *
 * If the typed-data primaryType is the EIP712Domain itself, message_hash
 * is empty/absent and the digest folds in only the domain separator.
 *
 * Mirrors ethereum_typed_hash() — TIP-712 uses the same '\x19\x01' prefix
 * as EIP-712.
 */
static void tron_typed_hash(const uint8_t domain_separator_hash[32],
                            const uint8_t message_hash[32],
                            bool has_message_hash, uint8_t hash[32]) {
  struct SHA3_CTX ctx = {0};
  sha3_256_Init(&ctx);
  sha3_Update(&ctx, (const uint8_t*)"\x19\x01", 2);
  sha3_Update(&ctx, domain_separator_hash, 32);
  if (has_message_hash) {
    sha3_Update(&ctx, message_hash, 32);
  }
  keccak_Final(&ctx, hash);
}

/**
 * Sign a TIP-712 typed-data digest. Host pre-computes the domain
 * separator hash and message hash per the TIP-712 spec; the device just
 * signs the assembled digest with secp256k1 + recovery id.
 *
 * Reuses tron_is_canonic from the TIP-191 path — both impose the same
 * v-in-{0,1} canonicality required by EVM-style verifiers.
 *
 * Caller must have populated node->public_key (hdnode_fill_public_key).
 */
bool tron_typed_hash_sign(const HDNode* node, const TronSignTypedHash* msg,
                          TronTypedDataSignature* resp) {
  if (!node || !msg || !resp) {
    return false;
  }
  if (msg->domain_separator_hash.size != 32 ||
      (msg->has_message_hash && msg->message_hash.size != 32)) {
    return false;
  }

  char address[TRON_ADDRESS_MAX_LEN];
  if (!tron_getAddress(node->public_key, address, sizeof(address))) {
    return false;
  }

  uint8_t hash[32] = {0};
  tron_typed_hash(msg->domain_separator_hash.bytes, msg->message_hash.bytes,
                  msg->has_message_hash, hash);

  uint8_t v = 0;
  if (ecdsa_sign_digest(&secp256k1, node->private_key, hash,
                        resp->signature.bytes, &v, tron_is_canonic) != 0) {
    memzero(hash, sizeof(hash));
    return false;
  }

  resp->signature.bytes[64] = 27 + v;
  resp->signature.size = 65;
  strlcpy(resp->address, address, sizeof(resp->address));

  memzero(hash, sizeof(hash));
  return true;
}
