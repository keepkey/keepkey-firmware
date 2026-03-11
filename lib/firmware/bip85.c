#include "keepkey/firmware/bip85.h"
#include "keepkey/firmware/storage.h"
#include "trezor/crypto/bip32.h"
#include "trezor/crypto/bip39.h"
#include "trezor/crypto/curves.h"
#include "trezor/crypto/hmac.h"
#include "trezor/crypto/memzero.h"

#include <string.h>

/*
 * BIP-85: Deterministic Entropy From BIP32 Keychains
 *
 * For BIP-39 mnemonic derivation:
 *   path = m / 83696968' / 39' / 0' / <word_count>' / <index>'
 *   k    = derived_node.private_key  (32 bytes)
 *   hmac = HMAC-SHA512(key="bip-entropy-from-k", msg=k)
 *   entropy = hmac[0 : entropy_bytes]
 *     12 words -> 16 bytes, 18 words -> 24 bytes, 24 words -> 32 bytes
 *   mnemonic = bip39_from_entropy(entropy)
 */

/* BIP-85 application number for deriving entropy from a key */
static const uint8_t BIP85_HMAC_KEY[] = "bip-entropy-from-k";
#define BIP85_HMAC_KEY_LEN 18

bool bip85_derive_mnemonic(uint32_t word_count, uint32_t index,
                           char *mnemonic, size_t mnemonic_len) {
  /* Validate word count and compute entropy length */
  int entropy_bytes;
  switch (word_count) {
    case 12: entropy_bytes = 16; break;
    case 18: entropy_bytes = 24; break;
    case 24: entropy_bytes = 32; break;
    default: return false;
  }

  /* BIP-85 derivation path: m/83696968'/39'/0'/<word_count>'/<index>' */
  uint32_t address_n[5];
  address_n[0] = 0x80000000 | 83696968;  /* purpose (hardened) */
  address_n[1] = 0x80000000 | 39;        /* BIP-39 app (hardened) */
  address_n[2] = 0x80000000 | 0;         /* English language (hardened) */
  address_n[3] = 0x80000000 | word_count; /* word count (hardened) */
  address_n[4] = 0x80000000 | index;     /* child index (hardened) */

  /* Get the master node from storage (respects passphrase) */
  static CONFIDENTIAL HDNode node;
  if (!storage_getRootNode(SECP256K1_NAME, true, &node)) {
    memzero(&node, sizeof(node));
    return false;
  }

  /* Derive to the BIP-85 path */
  for (int i = 0; i < 5; i++) {
    if (hdnode_private_ckd(&node, address_n[i]) == 0) {
      memzero(&node, sizeof(node));
      return false;
    }
  }

  /* HMAC-SHA512(key="bip-entropy-from-k", msg=private_key) */
  static CONFIDENTIAL uint8_t hmac_out[64];
  hmac_sha512(BIP85_HMAC_KEY, BIP85_HMAC_KEY_LEN,
              node.private_key, 32, hmac_out);

  /* We no longer need the derived node */
  memzero(&node, sizeof(node));

  /* Truncate HMAC output to the required entropy length */
  static CONFIDENTIAL uint8_t entropy[32];
  memcpy(entropy, hmac_out, entropy_bytes);
  memzero(hmac_out, sizeof(hmac_out));

  /* Convert entropy to BIP-39 mnemonic */
  const char *words = mnemonic_from_data(entropy, entropy_bytes);
  memzero(entropy, sizeof(entropy));

  if (!words) {
    return false;
  }

  /* Copy to output buffer */
  size_t words_len = strlen(words);
  if (words_len >= mnemonic_len) {
    mnemonic_clear();
    return false;
  }

  memcpy(mnemonic, words, words_len + 1);
  mnemonic_clear();

  return true;
}
