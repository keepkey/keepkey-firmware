#ifndef BIP85_H
#define BIP85_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * Derive a child BIP-39 mnemonic via BIP-85.
 *
 * Path: m/83696968'/39'/0'/<word_count>'/<index>'
 *
 * @param word_count  Number of words: 12, 18, or 24.
 * @param index       Child index (0-based).
 * @param mnemonic    Output buffer (must be at least 241 bytes).
 * @param mnemonic_len Size of the output buffer.
 * @return true on success, false on error.
 */
bool bip85_derive_mnemonic(uint32_t word_count, uint32_t index,
                           char *mnemonic, size_t mnemonic_len);

#endif
