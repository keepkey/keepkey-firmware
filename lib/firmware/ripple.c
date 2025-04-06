/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2019 ShapeShift
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

#include "keepkey/firmware/ripple.h"

#include "keepkey/firmware/ripple_base58.h"
#include "hwcrypto/crypto/base58.h"
#include "hwcrypto/crypto/secp256k1.h"

#include <assert.h>

const RippleFieldMapping RFM_account = {.type = RFT_ACCOUNT, .key = 1};
const RippleFieldMapping RFM_amount = {.type = RFT_AMOUNT, .key = 1};
const RippleFieldMapping RFM_destination = {.type = RFT_ACCOUNT, .key = 3};
const RippleFieldMapping RFM_fee = {.type = RFT_AMOUNT, .key = 8};
const RippleFieldMapping RFM_sequence = {.type = RFT_INT32, .key = 4};
const RippleFieldMapping RFM_type = {.type = RFT_INT16, .key = 2};
const RippleFieldMapping RFM_signingPubKey = {.type = RFT_VL, .key = 3};
const RippleFieldMapping RFM_flags = {.type = RFT_INT32, .key = 2};
const RippleFieldMapping RFM_txnSignature = {.type = RFT_VL, .key = 4};
const RippleFieldMapping RFM_lastLedgerSequence = {.type = RFT_INT32,
                                                   .key = 27};
const RippleFieldMapping RFM_destinationTag = {.type = RFT_INT32, .key = 14};

bool ripple_getAddress(const uint8_t public_key[33],
                       char address[MAX_RIPPLE_ADDR_SIZE]) {
  uint8_t buff[64];
  memset(buff, 0, sizeof(buff));

  Hasher hasher;
  hasher_Init(&hasher, HASHER_SHA2_RIPEMD);
  hasher_Update(&hasher, public_key, 33);
  hasher_Final(&hasher, buff + 1);

  if (!ripple_encode_check(buff, 21, HASHER_SHA2D, address, MAX_RIPPLE_ADDR_SIZE)) {
    assert(false && "can't encode address");
    return false;
  }

  return true;
}

void ripple_formatAmount(char *buf, size_t len, uint64_t amount) {
  bignum256 val;
  bn_read_uint64(amount, &val);
  bn_format(&val, NULL, " XRP", RIPPLE_DECIMALS, 0, false, buf, len);
}

static void append_u8(bool *ok, uint8_t **buf, const uint8_t *end,
                      uint8_t val) {
  if (!*ok) {
    return;
  }

  if (*buf + 1 > end) {
    *ok = false;
    return;
  }

  **buf = val;
  *buf += 1;
}

void ripple_serializeType(bool *ok, uint8_t **buf, const uint8_t *end,
                          const RippleFieldMapping *m) {
  if (m->key <= 0xf) {
    append_u8(ok, buf, end, m->type << 4 | m->key);
    return;
  }

  append_u8(ok, buf, end, m->type << 4);
  append_u8(ok, buf, end, m->key);
}

void ripple_serializeInt16(bool *ok, uint8_t **buf, const uint8_t *end,
                           const RippleFieldMapping *m, int16_t val) {
  assert(m->type == RFT_INT16 && "wrong type?");

  ripple_serializeType(ok, buf, end, m);
  append_u8(ok, buf, end, (val >> 8) & 0xff);
  append_u8(ok, buf, end, val & 0xff);
}

void ripple_serializeInt32(bool *ok, uint8_t **buf, const uint8_t *end,
                           const RippleFieldMapping *m, int32_t val) {
  assert(m->type == RFT_INT32 && "wrong type?");

  ripple_serializeType(ok, buf, end, m);
  append_u8(ok, buf, end, (val >> 24) & 0xff);
  append_u8(ok, buf, end, (val >> 16) & 0xff);
  append_u8(ok, buf, end, (val >> 8) & 0xff);
  append_u8(ok, buf, end, val & 0xff);
}

void ripple_serializeAmount(bool *ok, uint8_t **buf, const uint8_t *end,
                            const RippleFieldMapping *m, int64_t amount) {
  ripple_serializeType(ok, buf, end, m);

  assert(amount >= 0 && "amounts cannot be negative");
  assert(amount <= 100000000000 && "larger amounts not supported");
  uint8_t msb = (amount >> (7 * 8)) & 0xff;
  msb &= 0x7f;  // Clear first bit, indicating XRP
  msb |= 0x40;  // Clear second bit, indicating value is positive

  append_u8(ok, buf, end, msb);
  append_u8(ok, buf, end, (amount >> (6 * 8)) & 0xff);
  append_u8(ok, buf, end, (amount >> (5 * 8)) & 0xff);
  append_u8(ok, buf, end, (amount >> (4 * 8)) & 0xff);
  append_u8(ok, buf, end, (amount >> (3 * 8)) & 0xff);
  append_u8(ok, buf, end, (amount >> (2 * 8)) & 0xff);
  append_u8(ok, buf, end, (amount >> (1 * 8)) & 0xff);
  append_u8(ok, buf, end, amount & 0xff);
}

void ripple_serializeVarint(bool *ok, uint8_t **buf, const uint8_t *end,
                            int val) {
  if (val < 0) {
    assert(false && "can't serialize 0-valued varint");
    *ok = false;
    return;
  }

  if (val < 192) {
    append_u8(ok, buf, end, val);
    return;
  }

  if (val <= 12480) {
    val -= 193;
    append_u8(ok, buf, end, 193 + (val >> 8));
    append_u8(ok, buf, end, val & 0xff);
    return;
  }

  if (val < 918744) {
    assert(*buf + 3 < end && "buffer not long enough");
    val -= 12481;
    append_u8(ok, buf, end, 241 + (val >> 16));
    append_u8(ok, buf, end, (val >> 8) & 0xff);
    append_u8(ok, buf, end, val & 0xff);
    return;
  }

  assert(false && "value too large");
  *ok = false;
}

void ripple_serializeBytes(bool *ok, uint8_t **buf, const uint8_t *end,
                           const uint8_t *bytes, size_t count) {
  ripple_serializeVarint(ok, buf, end, count);

  if (!*ok || *buf + count > end) {
    *ok = false;
    assert(false && "buffer not long enough");
    return;
  }

  memcpy(*buf, bytes, count);
  *buf += count;
}

void ripple_serializeAddress(bool *ok, uint8_t **buf, const uint8_t *end,
                             const RippleFieldMapping *m, const char *address) {
  ripple_serializeType(ok, buf, end, m);

  uint8_t addr_raw[MAX_ADDR_RAW_SIZE];
  uint32_t addr_raw_len =
      ripple_decode_check(address, HASHER_SHA2D, addr_raw, MAX_ADDR_RAW_SIZE);
  if (addr_raw_len != 21) {
    assert(false && "address has wrong length?");
    *ok = false;
    return;
  }

  ripple_serializeBytes(ok, buf, end, addr_raw + 1, addr_raw_len - 1);
}

void ripple_serializeVL(bool *ok, uint8_t **buf, const uint8_t *end,
                        const RippleFieldMapping *m, const uint8_t *bytes,
                        size_t count) {
  ripple_serializeType(ok, buf, end, m);
  ripple_serializeBytes(ok, buf, end, bytes, count);
}

bool ripple_serialize(uint8_t **buf, const uint8_t *end, const RippleSignTx *tx,
                      const char *source_address, const uint8_t *pubkey,
                      const uint8_t *sig, size_t sig_len) {
  bool ok = true;
  ripple_serializeInt16(&ok, buf, end, &RFM_type, /*Payment*/ 0);
  if (tx->has_flags)
    ripple_serializeInt32(&ok, buf, end, &RFM_flags, tx->flags);
  if (tx->has_sequence)
    ripple_serializeInt32(&ok, buf, end, &RFM_sequence, tx->sequence);
  if (tx->payment.has_destination_tag)
    ripple_serializeInt32(&ok, buf, end, &RFM_destinationTag,
                          tx->payment.destination_tag);
  if (tx->has_last_ledger_sequence)
    ripple_serializeInt32(&ok, buf, end, &RFM_lastLedgerSequence,
                          tx->last_ledger_sequence);
  if (tx->payment.has_amount)
    ripple_serializeAmount(&ok, buf, end, &RFM_amount, tx->payment.amount);
  if (tx->has_fee) ripple_serializeAmount(&ok, buf, end, &RFM_fee, tx->fee);
  if (pubkey) ripple_serializeVL(&ok, buf, end, &RFM_signingPubKey, pubkey, 33);
  if (sig) ripple_serializeVL(&ok, buf, end, &RFM_txnSignature, sig, sig_len);
  if (source_address)
    ripple_serializeAddress(&ok, buf, end, &RFM_account, source_address);
  if (tx->payment.has_destination)
    ripple_serializeAddress(&ok, buf, end, &RFM_destination,
                            tx->payment.destination);
  return ok;
}

void ripple_signTx(const HDNode *node, RippleSignTx *tx, RippleSignedTx *resp) {
  const curve_info *curve = get_curve_by_name("secp256k1");
  if (!curve) return;

  // Set canonical flag, since trezor-crypto ECDSA implementation returns
  // fully-canonical signatures, thereby enforcing it in the transaction
  // using the designated flag.
  // See:
  // https://github.com/trezor/trezor-crypto/blob/3e8974ff8871263a70b7fbb9a27a1da5b0d810f7/ecdsa.c#L791
  if (!tx->has_flags) {
    tx->flags = 0;
    tx->has_flags = true;
  }
  tx->flags |= RIPPLE_FLAG_FULLY_CANONICAL;

  memset(resp->serialized_tx.bytes, 0, sizeof(resp->serialized_tx.bytes));

  // 'STX'
  memcpy(resp->serialized_tx.bytes, "\x53\x54\x58\x00", 4);

  char source_address[MAX_ADDR_SIZE];
  if (!ripple_getAddress(node->public_key, source_address)) return;

  uint8_t *buf = resp->serialized_tx.bytes + 4;
  size_t len = sizeof(resp->serialized_tx.bytes) - 4;
  if (!ripple_serialize(&buf, buf + len, tx, source_address, node->public_key,
                        NULL, 0))
    return;

  // Ripple uses the first half of SHA512
  uint8_t hash[64];
  sha512_Raw(resp->serialized_tx.bytes, buf - resp->serialized_tx.bytes, hash);

  uint8_t sig[64];
  if (ecdsa_sign_digest(&secp256k1, node->private_key, hash, sig, NULL, NULL) !=
      0) {
    // Failure
    return;
  }

  resp->signature.size = ecdsa_sig_to_der(sig, resp->signature.bytes);
  resp->has_signature = true;

  memset(resp->serialized_tx.bytes, 0, sizeof(resp->serialized_tx.bytes));

  buf = resp->serialized_tx.bytes;
  len = sizeof(resp->serialized_tx);
  if (!ripple_serialize(&buf, buf + len, tx, source_address, node->public_key,
                        resp->signature.bytes, resp->signature.size))
    return;

  resp->has_serialized_tx = true;
  resp->serialized_tx.size = buf - resp->serialized_tx.bytes;
}
