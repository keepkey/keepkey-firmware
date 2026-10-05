#ifndef KEEPKEY_FIRMWARE_TENDERMINT_H
#define KEEPKEY_FIRMWARE_TENDERMINT_H

#include "trezor/crypto/bip32.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct _CoinType CoinType;
typedef struct _SHA256_CTX SHA256_CTX;

/**
 * \returns false iff the provided bip32 derivation path matches the given coin.
 */
bool tendermint_pathMismatched(const CoinType* coin, const uint32_t* address_n,
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
bool tendermint_getAddress(const HDNode* node, const char* prefix,
                           char* address);

/**
 * Validate non-empty host text before it is reused in both Amino JSON and a
 * printf-based confirmation. This deliberately accepts visible ASCII except
 * JSON string delimiters; spaces and controls are refused so the display has
 * no hidden layout semantics.
 */
bool tendermint_validateSafeText(const char* value);

/** Validate a Bech32 address and bind it to the expected human-readable part.
 */
/// Well-formed bech32 (charset, length, checksum) with ANY human-readable
/// part. Use only where an arbitrary HRP is intended -- an IBC receiver on a
/// counterparty chain. Where the network is known, use
/// tendermint_validateBech32Address(), which also pins the prefix and the
/// 20-byte account length.
bool tendermint_bech32IsWellFormed(const char* address);

/// A validator operator address: a 20-byte account payload under the
/// "<chain_prefix>valoper" HRP. Use for every validator_address,
/// validator_src_address and validator_dst_address before it is serialized.
bool tendermint_validateValidatorAddress(const char* address,
                                         const char* chain_prefix);

bool tendermint_validateBech32Address(const char* address,
                                      const char* expected_prefix);

void tendermint_sha256UpdateEscaped(SHA256_CTX* ctx, const char* s, size_t len);

bool tendermint_snprintf(SHA256_CTX* ctx, char* temp, size_t len,
                         const char* format, ...)
    __attribute__((format(printf, 4, 5)));

#endif
