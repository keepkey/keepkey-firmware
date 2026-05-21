#ifndef KEEPKEY_FIRMWARE_HIVE_H
#define KEEPKEY_FIRMWARE_HIVE_H

#include "trezor/crypto/bip32.h"

#include "messages-hive.pb.h"

// Hive mainnet chain ID
#define HIVE_CHAIN_ID                                \
  "\xbe\xea\xb0\xde\x00\x00\x00\x00\x00\x00\x00\x00" \
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
  "\x00\x00\x00\x00\x00\x00\x00\x00"

#define HIVE_CHAIN_ID_LEN 32

// STM public key prefix (Hive inherited from Steem)
#define HIVE_PUBKEY_PREFIX "STM"

// Max account name length on Hive
#define HIVE_MAX_ACCOUNT_LEN 17

// BIP44 coin type for HIVE
#define HIVE_SLIP44 1275

// Decimals for HIVE and HBD
#define HIVE_DECIMALS 3

// Transfer operation type ID in Graphene
#define HIVE_OP_TRANSFER 2

bool hive_getPublicKey(const uint8_t public_key[33], char* out, size_t out_len);

void hive_signTx(const HDNode* node, const HiveSignTx* msg, HiveSignedTx* resp);

#endif
