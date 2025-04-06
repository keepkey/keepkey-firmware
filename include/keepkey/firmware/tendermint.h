#ifndef KEEPKEY_FIRMWARE_TENDERMINT_H
#define KEEPKEY_FIRMWARE_TENDERMINT_H

#include "hwcrypto/crypto/bip32.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct _CoinType CoinType;
typedef struct _SHA256_CTX SHA256_CTX;

/**
 * \returns false iff the provided bip32 derivation path matches the given coin.
 */
bool tendermint_pathMismatched(const CoinType *coin, const uint32_t *address_n,
                               const uint32_t address_n_count);

/**
 * Gets the address
 *
 * \param node    HDNode from which the address is to be derived
 * \param prefix  bech32 prefix
 * \param address Output buffer
 *
 * \returns true if successful
 */
bool tendermint_getAddress(const HDNode *node, const char *prefix,
                           char *address);

void tendermint_sha256UpdateEscaped(SHA256_CTX *ctx, const char *s, size_t len);

bool tendermint_snprintf(SHA256_CTX *ctx, char *temp, size_t len,
                         const char *format, ...)
    __attribute__((format(printf, 4, 5)));

#endif
