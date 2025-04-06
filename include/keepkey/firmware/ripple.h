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

#ifndef KEEPKEY_FIRMWARE_RIPPLE_H
#define KEEPKEY_FIRMWARE_RIPPLE_H

#include "hwcrypto/crypto/bip32.h"

#include "messages-ripple.pb.h"

#define RIPPLE_MIN_FEE 10
#define RIPPLE_MAX_FEE 1000000

#define RIPPLE_DECIMALS 6

#define RIPPLE_FLAG_FULLY_CANONICAL 0x80000000

#define MAX_RIPPLE_ADDR_SIZE 36

typedef enum {
  RFT_INT16 = 1,
  RFT_INT32 = 2,
  RFT_AMOUNT = 6,
  RFT_VL = 7,
  RFT_ACCOUNT = 8,
} RippleFieldType;

typedef struct _RippleFieldMapping {
  RippleFieldType type;
  int key;
} RippleFieldMapping;

extern const RippleFieldMapping RFM_account;
extern const RippleFieldMapping RFM_amount;
extern const RippleFieldMapping RFM_destination;
extern const RippleFieldMapping RFM_fee;
extern const RippleFieldMapping RFM_sequence;
extern const RippleFieldMapping RFM_type;
extern const RippleFieldMapping RFM_signingPubKey;
extern const RippleFieldMapping RFM_flags;
extern const RippleFieldMapping RFM_txnSignature;
extern const RippleFieldMapping RFM_lastLedgerSequence;
extern const RippleFieldMapping RFM_destinationTag;

bool ripple_getAddress(const uint8_t public_key[33],
                       char address[MAX_RIPPLE_ADDR_SIZE]);

void ripple_formatAmount(char *buf, size_t len, uint64_t amount);

void ripple_serializeType(bool *ok, uint8_t **buf, const uint8_t *end,
                          const RippleFieldMapping *m);

void ripple_serializeInt16(bool *ok, uint8_t **buf, const uint8_t *end,
                           const RippleFieldMapping *m, int16_t val);

void ripple_serializeInt32(bool *ok, uint8_t **buf, const uint8_t *end,
                           const RippleFieldMapping *m, int32_t val);

void ripple_serializeAmount(bool *ok, uint8_t **buf, const uint8_t *end,
                            const RippleFieldMapping *m, int64_t amount);

void ripple_serializeVarint(bool *ok, uint8_t **buf, const uint8_t *end,
                            int val);

void ripple_serializeBytes(bool *ok, uint8_t **buf, const uint8_t *end,
                           const uint8_t *bytes, size_t count);

void ripple_serializeAddress(bool *ok, uint8_t **buf, const uint8_t *end,
                             const RippleFieldMapping *m, const char *address);

void ripple_serializeVL(bool *ok, uint8_t **buf, const uint8_t *end,
                        const RippleFieldMapping *m, const uint8_t *bytes,
                        size_t count);

bool ripple_serialize(uint8_t **buf, const uint8_t *end, const RippleSignTx *tx,
                      const char *source_address, const uint8_t *pubkey,
                      const uint8_t *sig, size_t sig_len);

void ripple_signTx(const HDNode *node, RippleSignTx *tx, RippleSignedTx *resp);

#endif
