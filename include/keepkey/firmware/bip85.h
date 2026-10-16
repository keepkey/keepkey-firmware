#ifndef BIP85_H
#define BIP85_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#if DEBUG_LINK
#include "trezor/crypto/bip32.h"
#endif

/* BIP-85 child mnemonic at m/83696968'/39'/0'/<word_count>'/<index>'.
 * word_count: 12, 18 or 24; mnemonic buffer >= 241 bytes. */
bool bip85_derive_mnemonic(uint32_t word_count, uint32_t index, char *mnemonic,
                           size_t mnemonic_len);

/* A child mnemonic is private for the entire on-device display ceremony. */
bool bip85_debug_is_private(void);
void bip85_set_private_display(bool active);

#if DEBUG_LINK
/* Native fixture entry: production uses storage_getRootNode for this input. */
bool bip85_derive_from_root_for_test(const HDNode *root, uint32_t word_count,
                                     uint32_t index, char *mnemonic,
                                     size_t mnemonic_len);
#endif

#endif
