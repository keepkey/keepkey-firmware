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

#define HIVE_PUBKEY_PREFIX "STM"

// SLIP-0048, all hardened: m/48'/13'/role'/account_index'/0'
#define HIVE_SLIP48_PURPOSE (0x80000030u)  // 48'
#define HIVE_SLIP48_NETWORK (0x8000000Du)  // 13' — Hive SLIP-0048 network ID
#define HIVE_ROLE_OWNER \
  (0x80000000u)  // 0'  — account recovery, authority changes
#define HIVE_ROLE_ACTIVE (0x80000001u)   // 1'  — transfers, staking
#define HIVE_ROLE_MEMO (0x80000003u)     // 3'  — memo field encryption
#define HIVE_ROLE_POSTING (0x80000004u)  // 4'  — votes, posts, follows

#define HIVE_OP_TRANSFER 2
#define HIVE_OP_ACCOUNT_CREATE 9
#define HIVE_OP_ACCOUNT_UPDATE 10

#define HIVE_MAX_ACCOUNT_LEN 16  // max Hive username length
// Worst-case transfer with this memo is 505 bytes, inside the 512-byte tx_buf.
#define HIVE_MAX_MEMO_LEN 440
#define HIVE_DECIMALS 3  // HIVE and HBD both use 3 decimal places
#define HIVE_WIRE_SYMBOL_HIVE "STEEM"
#define HIVE_WIRE_SYMBOL_HBD "SBD"

/** STM-prefixed base58 with RIPEMD checksum (Graphene, not SHA256d). */
bool hive_getPublicKey(const uint8_t public_key[33], char* out, size_t out_len);

/** One SLIP-0048 role key (HIVE_ROLE_*) as 33 raw bytes; both indices
 * hardened. */
bool hive_deriveRawKey(const HDNode* root, uint32_t role_hardened,
                       uint32_t account_index_hardened, uint8_t out[33]);

/** All four role keys as STM strings (buffers >= 64 bytes). Rejects
 * account_index > 0x7fffffff (bit 31 would alias a lower account). */
bool hive_getPublicKeys(const HDNode* root, uint32_t account_index,
                        char* owner_out, size_t owner_len, char* active_out,
                        size_t active_len, char* memo_out, size_t memo_len,
                        char* posting_out, size_t posting_len);

/** Validate the public fields before consent and again before serialization. */
bool hive_validateTransfer(const HiveSignTx* msg);
bool hive_validateAccountCreate(const HiveSignAccountCreate* msg);
bool hive_validateAccountUpdate(const HiveSignAccountUpdate* msg);

/** Resolve a transferable Hive asset to its signed and displayed spellings. */
bool hive_transferAsset(const HiveSignTx* msg, const char** wire,
                        const char** display, uint8_t* precision);

/** Transfer (op 2); rejects memos over HIVE_MAX_MEMO_LEN. */
void hive_signTx(const HDNode* node, const HiveSignTx* msg, HiveSignedTx* resp);

/** account_create (op 9). *_raw must be device-derived; msg key strings are
 * ignored. */
void hive_signAccountCreate(const HDNode* signing_node,
                            const HiveSignAccountCreate* msg,
                            const uint8_t owner_raw[33],
                            const uint8_t active_raw[33],
                            const uint8_t posting_raw[33],
                            const uint8_t memo_raw[33],
                            HiveSignedAccountCreate* resp);

/** account_update (op 10). *_raw must be device-derived; msg new_*_key
 * strings are ignored. */
void hive_signAccountUpdate(const HDNode* signing_node,
                            const HiveSignAccountUpdate* msg,
                            const uint8_t owner_raw[33],
                            const uint8_t active_raw[33],
                            const uint8_t posting_raw[33],
                            const uint8_t memo_raw[33],
                            HiveSignedAccountUpdate* resp);

#endif  // KEEPKEY_FIRMWARE_HIVE_H
