#include "keepkey/firmware/bip85.h"
#include "keepkey/firmware/storage.h"
#include "trezor/crypto/bip32.h"
#include "trezor/crypto/bip39.h"
#include "trezor/crypto/curves.h"
#include "trezor/crypto/hmac.h"
#include "trezor/crypto/memzero.h"

#include <string.h>

/* BIP-85: k = key at m/83696968'/39'/0'/<words>'/<index>',
 * entropy = HMAC-SHA512("bip-entropy-from-k", k)[0 : 16|24|32]. */

static const uint8_t BIP85_HMAC_KEY[] = "bip-entropy-from-k";
#define BIP85_HMAC_KEY_LEN 18

static bool private_display;

bool bip85_debug_is_private(void) { return private_display; }

void bip85_set_private_display(bool active) { private_display = active; }

static int bip85_entropy_bytes(uint32_t word_count, uint32_t index) {
  /* Reject index >= 0x80000000 to avoid hardened-bit collision */
  if (index & 0x80000000) return 0;

  switch (word_count) {
    case 12:
      return 16;
    case 18:
      return 24;
    case 24:
      return 32;
    default:
      return 0;
  }
}

static bool bip85_derive_from_root(HDNode *node, int entropy_bytes,
                                   uint32_t word_count, uint32_t index,
                                   char *mnemonic, size_t mnemonic_len) {
  uint32_t address_n[5];
  address_n[0] = 0x80000000 | 83696968;   /* purpose (hardened) */
  address_n[1] = 0x80000000 | 39;         /* BIP-39 app (hardened) */
  address_n[2] = 0x80000000;              /* English language 0 (hardened) */
  address_n[3] = 0x80000000 | word_count; /* word count (hardened) */
  address_n[4] = 0x80000000 | index;      /* child index (hardened) */

  for (int i = 0; i < 5; i++) {
    if (hdnode_private_ckd(node, address_n[i]) == 0) {
      memzero(node, sizeof(*node));
      return false;
    }
  }

  static CONFIDENTIAL uint8_t hmac_out[64];
  hmac_sha512(BIP85_HMAC_KEY, BIP85_HMAC_KEY_LEN, node->private_key, 32,
              hmac_out);

  memzero(node, sizeof(*node));

  static CONFIDENTIAL uint8_t entropy[32];
  memcpy(entropy, hmac_out, entropy_bytes);
  memzero(hmac_out, sizeof(hmac_out));

  const char *words = mnemonic_from_data(entropy, entropy_bytes);
  memzero(entropy, sizeof(entropy));

  if (!words) {
    return false;
  }

  size_t words_len = strlen(words);
  if (words_len >= mnemonic_len) {
    mnemonic_clear();
    return false;
  }

  memcpy(mnemonic, words, words_len + 1);
  mnemonic_clear();

  return true;
}

bool bip85_derive_mnemonic(uint32_t word_count, uint32_t index, char *mnemonic,
                           size_t mnemonic_len) {
  const int entropy_bytes = bip85_entropy_bytes(word_count, index);
  if (!entropy_bytes) return false;

  /* Get the master node from storage (respects passphrase). */
  static CONFIDENTIAL HDNode node;
  if (!storage_getRootNode(SECP256K1_NAME, true, &node)) {
    memzero(&node, sizeof(node));
    return false;
  }
  return bip85_derive_from_root(&node, entropy_bytes, word_count, index,
                                mnemonic, mnemonic_len);
}

#if DEBUG_LINK
bool bip85_derive_from_root_for_test(const HDNode *root, uint32_t word_count,
                                     uint32_t index, char *mnemonic,
                                     size_t mnemonic_len) {
  const int entropy_bytes = bip85_entropy_bytes(word_count, index);
  if (!root || !entropy_bytes) return false;
  HDNode node = *root;
  return bip85_derive_from_root(&node, entropy_bytes, word_count, index,
                                mnemonic, mnemonic_len);
}
#endif
