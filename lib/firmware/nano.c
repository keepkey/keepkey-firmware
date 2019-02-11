#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include "keepkey/firmware/nano.h"
#include "trezor/crypto/blake2b.h"

static uint8_t const NANO_BLOCK_HASH_PREAMBLE[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
};

bool nano_path_mismatched(const CoinType *coin,
                          const uint32_t *address_n,
                          const uint32_t address_n_count)
{
    // m/44' : BIP44-like path
    // m / purpose' / bip44_account_path' / account'
    bool mismatch = false;
    mismatch |= address_n_count != 3;
    mismatch |= address_n_count > 0 && (address_n[0] != (0x80000000 + 44));
    mismatch |= address_n_count > 1 && (address_n[1] != coin->bip44_account_path);
    mismatch |= address_n_count > 2 && (address_n[2] & 0x80000000) == 0;
    return mismatch;
}

bool nano_bip32_to_string(char *node_str, size_t len,
                          const CoinType *coin,
                          const uint32_t *address_n,
                          const size_t address_n_count)
{
    if (address_n_count != 3)
        return false;

    if (nano_path_mismatched(coin, address_n, address_n_count))
        return false;

    snprintf(node_str, len, "%s Account #%" PRIu32, coin->coin_name,
             address_n[2] & 0x7ffffff);
    return true;
}

void nano_hash_block_data(const uint8_t account_pk[32],
                          const uint8_t parent_hash[32],
                          const uint8_t link[32],
                          const uint8_t representative_pk[32],
                          const uint8_t balance[16],
                          uint8_t out_hash[32])
{
    blake2b_state ctx;
    blake2b_Init(&ctx, 32);

    blake2b_Update(&ctx, NANO_BLOCK_HASH_PREAMBLE, sizeof(NANO_BLOCK_HASH_PREAMBLE));
    blake2b_Update(&ctx, account_pk, 32);
    blake2b_Update(&ctx, parent_hash, 32);
    blake2b_Update(&ctx, representative_pk, 32);
    blake2b_Update(&ctx, balance, 16);
    blake2b_Update(&ctx, link, 32);

    blake2b_Final(&ctx, out_hash, 32);
}

void nano_truncate_address(const CoinType *coin, char *str) {
    const size_t prefix_len = strlen(coin->nanoaddr_prefix);
    const size_t str_len = strlen(str);

    if (str_len < prefix_len + 12)
        return;

    memset(&str[prefix_len + 5], '.', 2);
    memmove(&str[prefix_len + 7], &str[str_len - 5], 5);
    str[prefix_len+12] = '\0';
}
