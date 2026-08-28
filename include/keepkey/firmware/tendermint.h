#ifndef KEEPKEY_FIRMWARE_TENDERMINT_H
#define KEEPKEY_FIRMWARE_TENDERMINT_H

#include "trezor/crypto/bip32.h"
#include "trezor/crypto/segwit_addr.h"

/* Output size for the data half of a bech32_decode().
 *
 * segwit_addr.h documents the contract as: hrp needs BECH32_MAX_HRP_LEN + 1
 * bytes, and data needs strlen(input) - 8. The Tendermint-family callers all
 * used char hrp[45] / uint8_t decoded[38] against address fields whose proto
 * max_size is 53, so a long address wrote past both -- and bech32_decode
 * fills these buffers BEFORE it validates the checksum, so the usual
 * `if (!bech32_decode(...)) return false;` guard does not prevent it.
 *
 * 64 covers any input up to 72 characters, comfortably above every address
 * cap on these paths. */
#define BECH32_DECODED_MAX 64

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

/** Reject empty or display-ambiguous host-provided JSON text. */
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

bool tendermint_isValidDenom(const char* denom);

bool tendermint_isValidAsset(const char* asset);

bool tendermint_isValidSigner(const char* signer, const char* hrp);

void tendermint_sha256UpdateEscaped(SHA256_CTX* ctx, const char* s, size_t len);

bool tendermint_snprintf(SHA256_CTX* ctx, char* temp, size_t len,
                         const char* format, ...)
    __attribute__((format(printf, 4, 5)));

#endif
