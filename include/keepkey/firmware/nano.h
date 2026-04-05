#ifndef KEEPKEY_FIRMWARE_NANO_H
#define KEEPKEY_FIRMWARE_NANO_H

#include "keepkey/transport/interface.h"
#include "trezor/crypto/bip32.h"
#include "trezor/crypto/nano.h"

#include <stdint.h>
#include <stdbool.h>

#define MAX_NANO_ADDR_SIZE 100

bool nano_path_mismatched(const CoinType* _coin, const uint32_t* address_n,
                          const uint32_t address_n_count);

bool nano_bip32_to_string(char* node_str, size_t len, const CoinType* _coin,
                          const uint32_t* address_n,
                          const size_t address_n_count);

void nano_hash_block_data(const uint8_t _account_pk[32],
                          const uint8_t _parent_hash[32],
                          const uint8_t _link[32],
                          const uint8_t _representative_pk[32],
                          const uint8_t _balance[16], uint8_t _out_hash[32]);

const char* nano_getKnownRepName(const char* addr);
void nano_truncateAddress(const CoinType* _coin, char* str);

void nano_signingAbort(void);
bool nano_signingInit(const NanoSignTx* msg, const HDNode* node,
                      const CoinType* _coin);
bool nano_parentHash(const NanoSignTx* msg);
bool nano_currentHash(const NanoSignTx* msg, const HDNode* recip);
bool nano_sanityCheck(const NanoSignTx* msg);
bool nano_signTx(const NanoSignTx* msg, HDNode* node, NanoSignedTx* resp);

#endif
