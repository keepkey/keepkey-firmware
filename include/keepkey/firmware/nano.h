#ifndef __FIRMWARE_NANO_H__
#define __FIRMWARE_NANO_H__

#include <stdint.h>
#include <stdbool.h>
#include "trezor/crypto/nano.h"
#include "keepkey/transport/interface.h"

#define MAX_NANO_ADDR_SIZE 100

bool nano_path_mismatched(const CoinType *coin,
                          const uint32_t *address_n,
                          const uint32_t address_n_count);

bool nano_bip32_to_string(char *node_str, size_t len,
                          const CoinType *coin,
                          const uint32_t *address_n,
                          const size_t address_n_count);

void nano_hash_block_data(const uint8_t account_pk[32],
                          const uint8_t parent_hash[32],
                          const uint8_t link[32],
                          const uint8_t representative_pk[32],
                          const uint8_t balance[16],
                          uint8_t out_hash[32]);

void nano_truncate_address(const CoinType *coin, char *str);

#endif // __FIRMWARE_NANO_H__
