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
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/secp256k1.h"
#include "trezor/crypto/sha2.h"
#include "trezor/crypto/sha3.h"

#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/*  Bounded protobuf encoding helpers                                  */
/* ------------------------------------------------------------------ */

/* How many bytes a varint takes. */
static size_t pb_varint_size(uint64_t v) {
  size_t n = 1;
  while (v >= 0x80) { v >>= 7; n++; }
  return n;
}

/* Encode a varint, checking remaining capacity. */
static bool pb_encode_varint_safe(uint8_t *buf, size_t *pos, size_t cap,
                                  uint64_t v) {
  size_t need = pb_varint_size(v);
  if (*pos + need > cap) return false;
  while (v >= 0x80) {
    buf[(*pos)++] = (uint8_t)(v & 0x7F) | 0x80;
    v >>= 7;
  }
  buf[(*pos)++] = (uint8_t)v;
  return true;
}

/* Write a protobuf tag (field_num << 3 | wire_type). */
static bool pb_write_tag_safe(uint8_t *buf, size_t *pos, size_t cap,
                              unsigned field, unsigned wire) {
  return pb_encode_varint_safe(buf, pos, cap,
                               ((uint64_t)field << 3) | wire);
}

/* Write a length-delimited field (wire type 2). */
static bool pb_write_bytes_safe(uint8_t *buf, size_t *pos, size_t cap,
                                unsigned field,
                                const uint8_t *data, size_t data_len) {
  if (!pb_write_tag_safe(buf, pos, cap, field, 2)) return false;
  if (!pb_encode_varint_safe(buf, pos, cap, data_len)) return false;
  if (*pos + data_len > cap) return false;
  memcpy(buf + *pos, data, data_len);
  *pos += data_len;
  return true;
}

/* Write a varint field (wire type 0). */
static bool pb_write_varint_field_safe(uint8_t *buf, size_t *pos, size_t cap,
                                       unsigned field, uint64_t val) {
  if (!pb_write_tag_safe(buf, pos, cap, field, 0)) return false;
  return pb_encode_varint_safe(buf, pos, cap, val);
}

/* ------------------------------------------------------------------ */
/*  Address functions                                                  */
/* ------------------------------------------------------------------ */

bool tron_getAddress(const uint8_t public_key[33], char *address,
                     size_t address_len) {
  if (address_len < TRON_ADDRESS_MAX_LEN) {
    return false;
  }

  uint8_t uncompressed_pubkey[65];
  uint8_t hash[32];
  uint8_t addr_bytes[21];

  if (!ecdsa_uncompress_pubkey(&secp256k1, public_key, uncompressed_pubkey)) {
    return false;
  }

  keccak_256(uncompressed_pubkey + 1, 64, hash);

  addr_bytes[0] = TRON_MAINNET_PREFIX;
  memcpy(addr_bytes + 1, hash + 12, 20);

  if (!base58_encode_check(addr_bytes, 21, HASHER_SHA2D, address,
                           address_len)) {
    memzero(uncompressed_pubkey, sizeof(uncompressed_pubkey));
    memzero(hash, sizeof(hash));
    return false;
  }

  memzero(uncompressed_pubkey, sizeof(uncompressed_pubkey));
  memzero(hash, sizeof(hash));
  return true;
}

bool tron_decodeAddress(const char *address,
                        uint8_t raw_address[TRON_ADDRESS_SIZE]) {
  if (!address || strlen(address) < 25 || strlen(address) > 36) {
    return false;
  }
  uint8_t decoded[25];  /* 21-byte payload + 4-byte checksum */
  int len = base58_decode_check(address, HASHER_SHA2D, decoded,
                                sizeof(decoded));
  if (len != 21) return false;
  if (decoded[0] != TRON_MAINNET_PREFIX) return false;
  memcpy(raw_address, decoded, 21);
  return true;
}

bool tron_validateAddress(const char *address) {
  uint8_t raw[TRON_ADDRESS_SIZE];
  return tron_decodeAddress(address, raw);
}

/* ------------------------------------------------------------------ */
/*  Formatting                                                         */
/* ------------------------------------------------------------------ */

void tron_formatAmount(char *buf, size_t len, uint64_t amount) {
  bignum256 val;
  bn_read_uint64(amount, &val);
  bn_format(&val, NULL, " TRX", TRON_DECIMALS, 0, false, buf, len);
}

void tron_formatTokenAmount(char *buf, size_t buf_len,
                            const uint8_t amount_be[32],
                            uint8_t decimals, const char *symbol) {
  /* Check if amount fits in uint64 (first 24 bytes must be zero). */
  bool fits_u64 = true;
  for (int i = 0; i < 24; i++) {
    if (amount_be[i] != 0) { fits_u64 = false; break; }
  }

  if (fits_u64) {
    uint64_t val64 = 0;
    for (int i = 24; i < 32; i++) {
      val64 = (val64 << 8) | amount_be[i];
    }
    bignum256 bn;
    bn_read_uint64(val64, &bn);
    char suffix[20];
    snprintf(suffix, sizeof(suffix), " %s", symbol);
    bn_format(&bn, NULL, suffix, decimals, 0, false, buf, buf_len);
  } else {
    snprintf(buf, buf_len, "(raw) %s", symbol);
  }
}

/* ------------------------------------------------------------------ */
/*  TRC-20 ABI decoding                                                */
/* ------------------------------------------------------------------ */

bool tron_decodeTRC20Transfer(const uint8_t *data, size_t data_len,
                              uint8_t to_raw[TRON_ADDRESS_SIZE],
                              uint8_t amount_bytes[32]) {
  if (data_len < 68) return false;

  /* Check 4-byte function selector: transfer(address,uint256) = 0xa9059cbb */
  if (data[0] != 0xa9 || data[1] != 0x05 ||
      data[2] != 0x9c || data[3] != 0xbb) {
    return false;
  }

  /* Bytes 4..35: ABI-encoded address (12 zero bytes + 20-byte EVM address).
   * TRON ABI uses standard Solidity encoding — no 0x41 prefix in the ABI.
   * We verify the 12 leading bytes are zero, then prepend 0x41 ourselves. */
  for (int i = 4; i < 16; i++) {
    if (data[i] != 0) return false;
  }
  to_raw[0] = TRON_MAINNET_PREFIX;
  memcpy(to_raw + 1, data + 16, 20);

  /* Bytes 36..67: uint256 amount (big-endian) */
  memcpy(amount_bytes, data + 36, 32);
  return true;
}

/* ------------------------------------------------------------------ */
/*  Protobuf serialization (reconstruct-then-sign)                     */
/* ------------------------------------------------------------------ */

/* Serialize a TransferContract into a contract entry (field 11 of raw). */
static bool tron_serializeTransferContract(uint8_t *buf, size_t *pos,
                                           size_t cap,
                                           const TronTransferContract *tc,
                                           const uint8_t *owner_raw) {
  /* Build inner TransferContract protobuf:
   *   field 1 (bytes): owner_address (21 bytes)
   *   field 2 (bytes): to_address    (21 bytes)
   *   field 3 (varint): amount
   */
  uint8_t inner[128];
  size_t ip = 0;

  /* owner_address */
  if (!pb_write_bytes_safe(inner, &ip, sizeof(inner), 1, owner_raw, 21))
    return false;

  /* to_address — decode from Base58 */
  uint8_t to_raw[TRON_ADDRESS_SIZE];
  if (!tron_decodeAddress(tc->to_address, to_raw)) return false;
  if (!pb_write_bytes_safe(inner, &ip, sizeof(inner), 2, to_raw, 21))
    return false;

  /* amount */
  if (!pb_write_varint_field_safe(inner, &ip, sizeof(inner), 3, tc->amount))
    return false;

  /* Build contract wrapper:
   *   field 1 (varint): type = 1 (TransferContract)
   *   field 2 (bytes): google.protobuf.Any {
   *     field 1 (bytes): type_url
   *     field 2 (bytes): value = inner
   *   }
   */
  static const char type_url[] =
      "type.googleapis.com/protocol.TransferContract";
  uint8_t any[256];
  size_t ap = 0;
  if (!pb_write_bytes_safe(any, &ap, sizeof(any), 1,
                           (const uint8_t *)type_url, strlen(type_url)))
    return false;
  if (!pb_write_bytes_safe(any, &ap, sizeof(any), 2, inner, ip))
    return false;

  uint8_t contract[300];
  size_t cp = 0;
  if (!pb_write_varint_field_safe(contract, &cp, sizeof(contract), 1, 1))
    return false;
  if (!pb_write_bytes_safe(contract, &cp, sizeof(contract), 2, any, ap))
    return false;

  /* Write as field 11 of the outer transaction.raw */
  return pb_write_bytes_safe(buf, pos, cap, 11, contract, cp);
}

/* Serialize a TriggerSmartContract into a contract entry. */
static bool tron_serializeTriggerSmartContract(
    uint8_t *buf, size_t *pos, size_t cap,
    const TronTriggerSmartContract *tsc, const uint8_t *owner_raw) {
  /* Inner TriggerSmartContract:
   *   field 1 (bytes): owner_address (21)
   *   field 2 (bytes): contract_address (21)
   *   field 3 (bytes): data (ABI call data)
   *   field 4 (varint): call_value
   */
  uint8_t inner[700];
  size_t ip = 0;

  if (!pb_write_bytes_safe(inner, &ip, sizeof(inner), 1, owner_raw, 21))
    return false;

  uint8_t contract_raw[TRON_ADDRESS_SIZE];
  if (!tron_decodeAddress(tsc->contract_address, contract_raw)) return false;
  if (!pb_write_bytes_safe(inner, &ip, sizeof(inner), 2, contract_raw, 21))
    return false;

  if (tsc->has_data && tsc->data.size > 0) {
    if (!pb_write_bytes_safe(inner, &ip, sizeof(inner), 3,
                             tsc->data.bytes, tsc->data.size))
      return false;
  }

  if (tsc->has_call_value && tsc->call_value > 0) {
    if (!pb_write_varint_field_safe(inner, &ip, sizeof(inner), 4,
                                    tsc->call_value))
      return false;
  }

  /* Wrap in Any with type_url for TriggerSmartContract */
  static const char type_url[] =
      "type.googleapis.com/protocol.TriggerSmartContract";
  uint8_t any[768];
  size_t ap = 0;
  if (!pb_write_bytes_safe(any, &ap, sizeof(any), 1,
                           (const uint8_t *)type_url, strlen(type_url)))
    return false;
  if (!pb_write_bytes_safe(any, &ap, sizeof(any), 2, inner, ip))
    return false;

  /* contract type = 31 for TriggerSmartContract */
  uint8_t contract[900];
  size_t cpp = 0;
  if (!pb_write_varint_field_safe(contract, &cpp, sizeof(contract), 1, 31))
    return false;
  if (!pb_write_bytes_safe(contract, &cpp, sizeof(contract), 2, any, ap))
    return false;

  return pb_write_bytes_safe(buf, pos, cap, 11, contract, cpp);
}

bool tron_serializeRawTransaction(const TronSignTx *msg,
                                  const uint8_t *owner_raw,
                                  uint8_t *out, size_t *out_len,
                                  size_t max_len) {
  size_t pos = 0;

  /* Field 1: ref_block_bytes (2 bytes required) */
  if (!msg->has_ref_block_bytes || msg->ref_block_bytes.size != 2)
    return false;
  if (!pb_write_bytes_safe(out, &pos, max_len, 1,
                           msg->ref_block_bytes.bytes, 2))
    return false;

  /* Field 4: ref_block_hash (8 bytes required) */
  if (!msg->has_ref_block_hash || msg->ref_block_hash.size != 8)
    return false;
  if (!pb_write_bytes_safe(out, &pos, max_len, 4,
                           msg->ref_block_hash.bytes, 8))
    return false;

  /* Field 8: expiration */
  if (!msg->has_expiration) return false;
  if (!pb_write_varint_field_safe(out, &pos, max_len, 8, msg->expiration))
    return false;

  /* Field 10: data/memo (optional, max 256 bytes) */
  if (msg->has_data && msg->data.size > 0) {
    if (msg->data.size > 256) return false;
    if (!pb_write_bytes_safe(out, &pos, max_len, 10,
                             msg->data.bytes, msg->data.size))
      return false;
  }

  /* Field 11: contract (exactly one) */
  if (msg->has_transfer) {
    if (!tron_serializeTransferContract(out, &pos, max_len,
                                        &msg->transfer, owner_raw))
      return false;
  } else if (msg->has_trigger_smart) {
    if (!tron_serializeTriggerSmartContract(out, &pos, max_len,
                                            &msg->trigger_smart, owner_raw))
      return false;
  } else {
    return false;  /* Must have exactly one contract */
  }

  /* Field 14: timestamp (optional) */
  if (msg->has_timestamp) {
    if (!pb_write_varint_field_safe(out, &pos, max_len, 14, msg->timestamp))
      return false;
  }

  /* Field 18: fee_limit (optional) */
  if (msg->has_fee_limit && msg->fee_limit > 0) {
    if (!pb_write_varint_field_safe(out, &pos, max_len, 18, msg->fee_limit))
      return false;
  }

  *out_len = pos;
  return true;
}

/* ------------------------------------------------------------------ */
/*  Transaction signing                                                */
/* ------------------------------------------------------------------ */

bool tron_signTx(const HDNode *node, const TronSignTx *msg,
                 TronSignedTx *resp) {
  if (!node || !msg || !resp) return false;

  const curve_info *curve = get_curve_by_name(SECP256K1_NAME);
  if (!curve) return false;

  uint8_t hash[32];
  bool is_structured = msg->has_transfer || msg->has_trigger_smart;

  if (is_structured) {
    /* Derive owner address from public key */
    uint8_t owner_raw[TRON_ADDRESS_SIZE];
    {
      uint8_t uncompressed[65];
      uint8_t keccak[32];
      if (!ecdsa_uncompress_pubkey(&secp256k1, node->public_key, uncompressed))
        return false;
      keccak_256(uncompressed + 1, 64, keccak);
      owner_raw[0] = TRON_MAINNET_PREFIX;
      memcpy(owner_raw + 1, keccak + 12, 20);
      memzero(uncompressed, sizeof(uncompressed));
      memzero(keccak, sizeof(keccak));
    }

    /* Reconstruct the raw transaction */
    uint8_t raw_buf[1024];
    size_t raw_len = sizeof(raw_buf);
    if (!tron_serializeRawTransaction(msg, owner_raw, raw_buf, &raw_len,
                                      sizeof(raw_buf))) {
      memzero(owner_raw, sizeof(owner_raw));
      return false;
    }
    memzero(owner_raw, sizeof(owner_raw));

    /* Return the serialized bytes for host verification */
    resp->has_serialized_tx = true;
    resp->serialized_tx.size = raw_len;
    memcpy(resp->serialized_tx.bytes, raw_buf, raw_len);

    sha256_Raw(raw_buf, raw_len, hash);
    memzero(raw_buf, sizeof(raw_buf));
  } else if (msg->has_raw_data && msg->raw_data.size > 0) {
    /* Legacy: hash the client-provided raw_data */
    sha256_Raw(msg->raw_data.bytes, msg->raw_data.size, hash);
  } else {
    return false;
  }

  /* Sign with secp256k1 */
  uint8_t sig[65];
  uint8_t pby;
  if (ecdsa_sign_digest(&secp256k1, node->private_key, hash, sig, &pby,
                        NULL) != 0) {
    memzero(hash, sizeof(hash));
    return false;
  }
  sig[64] = pby;

  resp->has_signature = true;
  resp->signature.size = 65;
  memcpy(resp->signature.bytes, sig, 65);

  memzero(hash, sizeof(hash));
  memzero(sig, sizeof(sig));
  return true;
}
