/*
 *
 * Copyright (C) 2023 markrypto <cryptoakorn@gmail.com>
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "storage.h"

#include "keepkey/firmware/storage.h"

#include "variant.h"

#ifndef EMULATOR
#include <libopencm3/stm32/flash.h>
#include <libopencm3/stm32/desig.h>
#endif

#include "aes_sca/aes128_cbc.h"

#include "keepkey/board/confirm_sm.h"
#include "keepkey/firmware/home_sm.h"


#include "keepkey/board/common.h"
#include "keepkey/board/supervise.h"
#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/keepkey_flash.h"
#include "keepkey/board/memcmp_s.h"
#include "keepkey/board/memory.h"
#include "keepkey/board/util.h"
#include "keepkey/board/variant.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/passphrase_sm.h"
#include "keepkey/firmware/policy.h"
#include "keepkey/firmware/u2f.h"
#include "keepkey/rand/rng.h"
#include "keepkey/transport/interface.h"
#include "hwcrypto/crypto/aes/aes.h"
#include "hwcrypto/crypto/bip32.h"
#include "hwcrypto/crypto/bip39.h"
#include "hwcrypto/crypto/curves.h"
#include "hwcrypto/crypto/memzero.h"
#include "hwcrypto/crypto/pbkdf2.h"
#include "hwcrypto/crypto/rand.h"

#include <string.h>
#include <stdint.h>
#include <assert.h>

/* 
The PIN_ITER defines below changed between storage version 15 and 16 to eliminate
the unacceptable multi-second wait while the pin was being stretched for a dubious
claim to better security. The defines help during upgrades from v15 to v16
*/

#if defined(EMULATOR) || defined(DEBUG_ON)
#define PIN_ITER_COUNT_v15 1000
#define PIN_ITER_CHUNK_v15 10
#define PIN_ITER_COUNT_v16 10
#define PIN_ITER_CHUNK_v16 1
#else
#define PIN_ITER_COUNT_v15 100000
#define PIN_ITER_CHUNK_v15 1000
#define PIN_ITER_COUNT_v16 10
#define PIN_ITER_CHUNK_v16 1
#endif

#define U2F_KEY_PATH 0x80553246
#define _(X) (X)

static SessionState CONFIDENTIAL session;

static Allocation storage_location = FLASH_INVALID;

/* Shadow memory for configuration data in storage partition */
_Static_assert(sizeof(ConfigFlash) <= FLASH_STORAGE_LEN,
               "ConfigFlash struct is too large for storage partition");
static ConfigFlash CONFIDENTIAL shadow_config;

#if DEBUG_LINK
// These won't survive resets like the stuff in flash would, but thats a
// reasonable compromise given how testing works.
char debuglink_pin[10];
char debuglink_wipe_code[10];
char debuglink_mnemonic[241];
HDNode debuglink_node;
#endif

static void get_u2froot_callback(uint32_t iter, uint32_t total) {
  layoutProgress(_("Updating"), 1000 * iter / total);
}

static void storage_compute_u2froot(SessionState *ss, const char *mnemonic,
                                    HDNodeType *u2froot) {
  static CONFIDENTIAL HDNode node;
  mnemonic_to_seed(mnemonic, "", ss->seed, get_u2froot_callback);  // BIP-0039
  hdnode_from_seed(ss->seed, 64, NIST256P1_NAME, &node);
  hdnode_private_ckd(&node, U2F_KEY_PATH);
  u2froot->depth = node.depth;
  u2froot->child_num = U2F_KEY_PATH;
  u2froot->chain_code.size = sizeof(node.chain_code);
  memcpy(u2froot->chain_code.bytes, node.chain_code, sizeof(node.chain_code));
  u2froot->has_private_key = true;
  u2froot->private_key.size = sizeof(node.private_key);
  memcpy(u2froot->private_key.bytes, node.private_key,
         sizeof(node.private_key));
  memzero(&node, sizeof(node));
}

bool storage_getU2FRoot(HDNode *node) {
  return shadow_config.storage.pub.has_u2froot &&
         hdnode_from_xprv(shadow_config.storage.pub.u2froot.depth,
                          shadow_config.storage.pub.u2froot.child_num,
                          shadow_config.storage.pub.u2froot.chain_code.bytes,
                          shadow_config.storage.pub.u2froot.private_key.bytes,
                          NIST256P1_NAME, node);
}

uint32_t storage_nextU2FCounter(void) {
  shadow_config.storage.pub.u2f_counter++;
  storage_commit();
  return shadow_config.storage.pub.u2f_counter;
}

void storage_setU2FCounter(uint32_t u2f_counter) {
  shadow_config.storage.pub.u2f_counter = u2f_counter;
  storage_commit();
}

static bool storage_isActiveSector(const char *flash) {
  return memcmp(((const Metadata *)flash)->magic, STORAGE_MAGIC_STR,
                STORAGE_MAGIC_LEN) == 0;
}

void storage_upgradePolicies(Storage *storage) {
  for (int i = storage->pub.policies_count; i < (int)(POLICY_COUNT); ++i) {
    memcpy(&storage->pub.policies[i], &policies[i],
           sizeof(storage->pub.policies[i]));
  }
  storage->pub.policies_count = POLICY_COUNT;
}

void storage_resetPolicies(Storage *storage) {
  storage->pub.policies_count = 0;
  storage_upgradePolicies(storage);
}

void storage_resetCache(Cache *cache) { memset(cache, 0, sizeof(*cache)); }

static uint8_t read_u8(const char *ptr) { return *ptr; }

static void write_u8(char *ptr, uint8_t val) { *ptr = val; }

static uint32_t read_u32_le(const char *ptr) {
  return ((uint32_t)ptr[0]) | ((uint32_t)ptr[1]) << 8 |
         ((uint32_t)ptr[2]) << 16 | ((uint32_t)ptr[3]) << 24;
}

static void write_u32_le(char *ptr, uint32_t val) {
  ptr[0] = val & 0xff;
  ptr[1] = (val >> 8) & 0xff;
  ptr[2] = (val >> 16) & 0xff;
  ptr[3] = (val >> 24) & 0xff;
}

static bool read_bool(const char *ptr) { return *ptr; }

static void write_bool(char *ptr, bool val) { *ptr = val ? 1 : 0; }

enum StorageVersion {
  StorageVersion_NONE,
#define STORAGE_VERSION_ENTRY(VAL) StorageVersion_##VAL,
#include "storage_versions.inc"
};

static enum StorageVersion version_from_int(int version) {
#define STORAGE_VERSION_LAST(VAL)                          \
  _Static_assert(VAL == STORAGE_VERSION, "need to update " \
                                         "storage_versions.inc");
#include "storage_versions.inc"

  switch (version) {
#define STORAGE_VERSION_ENTRY(VAL) \
  case VAL:                        \
    return StorageVersion_##VAL;
#include "storage_versions.inc"
    default:
      return StorageVersion_NONE;
  }
}

void storage_readMeta(Metadata *meta, const char *ptr, size_t len) {
  if (len < 16 + STORAGE_UUID_STR_LEN) return;
  memcpy(meta->magic, ptr, STORAGE_MAGIC_LEN);
  memcpy(meta->uuid, ptr + 4, STORAGE_UUID_LEN);
  memcpy(meta->uuid_str, ptr + 16, STORAGE_UUID_STR_LEN);
}

void storage_writeMeta(char *ptr, size_t len, const Metadata *meta) {
  if (len < 16 + STORAGE_UUID_STR_LEN) return;
  memcpy(ptr, meta->magic, STORAGE_MAGIC_LEN);
  memcpy(ptr + 4, meta->uuid, STORAGE_UUID_LEN);
  memcpy(ptr + 16, meta->uuid_str, STORAGE_UUID_STR_LEN);
}

void storage_readPolicyV1(PolicyType *policy, const char *ptr, size_t len) {
  if (len < 17) return;
  policy->has_policy_name = read_bool(ptr);
  memset(policy->policy_name, 0, sizeof(policy->policy_name));
  memcpy(policy->policy_name, ptr + 1, 15);
  policy->has_enabled = read_bool(ptr + 16);
  policy->enabled = read_bool(ptr + 17);
}

void storage_readPolicyV2(PolicyType *policy, const char *policy_name,
                          bool enabled) {
  policy->has_policy_name = true;
  memset(policy->policy_name, 0, sizeof(policy->policy_name));
  strlcpy(policy->policy_name, policy_name, sizeof(policy->policy_name));
  policy->has_enabled = true;
  policy->enabled = enabled;
}

void storage_writePolicyV1(char *ptr, size_t len, const PolicyType *policy) {
  if (len < 17) return;
  write_bool(ptr, policy->has_policy_name);
  memcpy(ptr + 1, policy->policy_name, 15);
  write_bool(ptr + 16, policy->has_enabled);
  write_bool(ptr + 17, policy->enabled);
}

void storage_readHDNode(HDNodeType *node, const char *ptr, size_t len) {
  if (len < 96 + 33) return;
  node->depth = read_u32_le(ptr);
  node->fingerprint = read_u32_le(ptr + 4);
  node->child_num = read_u32_le(ptr + 8);
  node->chain_code.size = 32;
  memcpy(node->chain_code.bytes, ptr + 16, 32);
  node->has_private_key = read_bool(ptr + 48);
  node->private_key.size = 32;
  memcpy(node->private_key.bytes, ptr + 56, 32);
  node->has_public_key = read_bool(ptr + 88);
  node->public_key.size = 33;
  memcpy(node->public_key.bytes, ptr + 96, 33);
}

void storage_writeHDNode(char *ptr, size_t len, const HDNodeType *node) {
  if (len < 96 + 33) return;
  write_u32_le(ptr, node->depth);
  write_u32_le(ptr + 4, node->fingerprint);
  write_u32_le(ptr + 8, node->child_num);
  write_u32_le(ptr + 12, 32);
  memcpy(ptr + 16, node->chain_code.bytes, 32);
  write_bool(ptr + 48, node->has_private_key);
  ptr[49] = 0;  // reserved
  ptr[50] = 0;  // reserved
  ptr[51] = 0;  // reserved
  write_u32_le(ptr + 52, 32);
  memcpy(ptr + 56, node->private_key.bytes, 32);
  write_bool(ptr + 88, node->has_public_key);
  ptr[89] = 0;  // reserved
  ptr[90] = 0;  // reserved
  ptr[91] = 0;  // reserved
  write_u32_le(ptr + 92, 33);
  memcpy(ptr + 96, node->public_key.bytes, 33);
}

void storage_deriveWrappingKey(const char *pin, uint8_t wrapping_key[64],
                               bool sca_hardened,
                               bool v15_16_trans,
                               uint8_t random_salt[RANDOM_SALT_LEN],
                               const char *message) {
  size_t pin_len = strlen(pin);
  if (sca_hardened && pin_len > 0) {
    uint8_t salt[HW_ENTROPY_LEN + RANDOM_SALT_LEN];
    int iterCount, iterChunk;

    if (v15_16_trans) { // can use new counts
      iterCount = PIN_ITER_COUNT_v16;
      iterChunk = PIN_ITER_CHUNK_v16;
    } else { // need to use storage version 15 counts to derive wrap key 
      iterCount = PIN_ITER_COUNT_v15;
      iterChunk = PIN_ITER_CHUNK_v15;
    }

    memset(salt, 0, sizeof(salt));
    flash_readHWEntropy(salt, sizeof(salt));
    memcpy(salt + HW_ENTROPY_LEN, random_salt, RANDOM_SALT_LEN);

    PBKDF2_HMAC_SHA256_CTX ctx = {0};
    pbkdf2_hmac_sha256_Init(&ctx, (const uint8_t *)pin, pin_len, salt,
                            sizeof(salt), 1);

    for (int i = 0; i < iterCount; i += iterChunk) {
      layoutProgress(message, 1000 * i / (iterCount * 2));
      pbkdf2_hmac_sha256_Update(&ctx, iterChunk);
    }
    pbkdf2_hmac_sha256_Final(&ctx, wrapping_key);
    memzero(&ctx, sizeof(ctx));

    pbkdf2_hmac_sha256_Init(&ctx, (const uint8_t *)pin, pin_len, salt,
                            sizeof(salt), 2);
    for (int i = 0; i < iterCount; i += iterChunk) {
      layoutProgress(message,
                     1000 * (i + iterCount) / (iterCount * 2));
      pbkdf2_hmac_sha256_Update(&ctx, iterChunk);
    }
    layoutProgress(message, 1000);
    pbkdf2_hmac_sha256_Final(&ctx, wrapping_key + 32);
    memzero(&ctx, sizeof(ctx));

    memzero(salt, sizeof(salt));
  } else {
    sha512_Raw((const uint8_t *)pin, pin_len, wrapping_key);
  }
}

void storage_wrapStorageKey(const uint8_t wrapping_key[64],
                            const uint8_t key[64], uint8_t wrapped_key[64]) {
  uint8_t iv[64];
  memcpy(iv, wrapping_key, sizeof(iv));
  aes128_cbc_sca_encrypt(wrapping_key, key, wrapped_key, 64, iv + 32);
  memzero(iv, sizeof(iv));
}

void storage_unwrapStorageKey(const uint8_t wrapping_key[64],
                              const uint8_t wrapped_key[64], uint8_t key[64]) {
  uint8_t iv[64];
  memcpy(iv, wrapping_key, sizeof(iv));
  aes128_cbc_sca_decrypt(wrapping_key, wrapped_key, key, 64, iv + 32);
  memzero(iv, sizeof(iv));
}

void storage_unwrapStorageKey256(const uint8_t wrapping_key[64],
                                 const uint8_t wrapped_key[64],
                                 uint8_t key[64]) {
  uint8_t iv[64];
  memcpy(iv, wrapping_key, sizeof(iv));
  aes_decrypt_ctx ctx;
  aes_decrypt_key256(wrapping_key, &ctx);
  aes_cbc_decrypt(wrapped_key, key, 64, iv + 32, &ctx);
  memzero(&ctx, sizeof(ctx));
  memzero(iv, sizeof(iv));
}

void storage_keyFingerprint(const uint8_t key[64], uint8_t fingerprint[32]) {
  sha256_Raw(key, 64, fingerprint);
}

pintest_t storage_isPinCorrect_impl(const char *pin, uint8_t wrapped_key[64],
                                    const uint8_t fingerprint[32],
                                    bool *sca_hardened, 
                                    bool *v15_16_trans, 
                                    uint8_t key[64],
                                    uint8_t random_salt[RANDOM_SALT_LEN]) {
  /*
      This function tests whether the PIN is correct. It will return
          PIN_WRONG     - PIN is incorrect
          PIN_GOOD      - PIN is correct
          PIN_REWRAP -> PIN is correct, storage key was rewrapped, CALLING
     FUNCTION SHOULD storage_commit() If the pin is correct, the storage key may
     have been rewrapped and returned in the wrapped_key parameter. Since the
     *_impl functions are assumed to not touch the stored config state, the
      rewrapped storage key will not have been saved to flash on exit from this
     function. Thus, if the return is PIN_REWRAP, then the calling function is
     required to update the flash with a storage_commit().
  */
  uint8_t wrapping_key[64];
  storage_deriveWrappingKey(pin, wrapping_key, *sca_hardened, *v15_16_trans, random_salt,
                            _("Verifying PIN"));

  // unwrap the storage key for fingerprint test
  if (*sca_hardened) {
    // key was wrapped using the sca-hardened method
    storage_unwrapStorageKey(wrapping_key, wrapped_key, key);
  } else {
    // key was wrapped using deprecated method, unwrap for test
    storage_unwrapStorageKey256(wrapping_key, wrapped_key, key);
  }

  uint8_t fp[32];
  storage_keyFingerprint(key, fp);

  pintest_t ret = PIN_WRONG;
  if (memcmp_s(fp, fingerprint, 32) == 0) ret = PIN_GOOD;

  if (ret == PIN_GOOD) {
    if (!*sca_hardened || (*sca_hardened && !*v15_16_trans)) {
      // PIN is correct but:
      //   1. wrapping key needs to be regenerated using stretched key
      //   2. storage key needs a rewrap with new wrapping key and algorithm
      storage_deriveWrappingKey(pin, wrapping_key, 
                                true /* sca_hardened */,
                                true /* v15_16_trans */,
                                random_salt, _("Verifying PIN"));
      storage_wrapStorageKey(wrapping_key, key, wrapped_key);
      *sca_hardened = true;
      *v15_16_trans = true;
      ret = PIN_REWRAP;
      }
    }

  if (!ret) memzero(key, 64);
  memzero(wrapping_key, 64);
  memzero(fp, 32);
  return ret;
}

pintest_t storage_isWipeCodeCorrect_impl(const char *wipe_code,
                                         uint8_t wrapped_key[64],
                                         const uint8_t fingerprint[32],
                                         uint8_t key[64],
                                         uint8_t random_salt[RANDOM_SALT_LEN]) {
  uint8_t wrapping_key[64];
  storage_deriveWrappingKey(wipe_code, wrapping_key, true, true, random_salt,
                            _("Verifying PIN"));

  // unwrap the storage key for fingerprint test
  storage_unwrapStorageKey(wrapping_key, wrapped_key, key);

  uint8_t fp[32];
  storage_keyFingerprint(key, fp);

  pintest_t ret = PIN_WRONG;
  if (memcmp_s(fp, fingerprint, 32) == 0) {
    ret = PIN_GOOD;
  }

  if (!ret) {
    memzero(key, 64);
  }
  memzero(wrapping_key, 64);
  memzero(fp, 32);
  return ret;
}

void storage_secMigrate(SessionState *ss, Storage *storage, bool encrypt) {
  static CONFIDENTIAL char scratch[V17_ENCSEC_SIZE];
  _Static_assert(sizeof(scratch) == sizeof(storage->encrypted_sec),
                 "Be extermely careful when changing the size of scratch.");
  memzero(scratch, sizeof(scratch));

  if (encrypt) {
    if (!storage->has_sec) return;

    memzero(storage->encrypted_sec, sizeof(storage->encrypted_sec));

    // Serialize to scratch.
    storage_writeHDNode(&scratch[0], 129, &storage->sec.node);
    memcpy(&scratch[0] + 129, storage->sec.mnemonic, 241);
    storage_writeCacheV1(&scratch[0] + 370, 75, &storage->sec.cache);
    memcpy(&scratch[0] + 512, &storage->sec.authBlock, sizeof(storage->sec.authBlock));
    // 129 reserved bytes

    // Take a fingerprint of the secrets so we can tell whether they've
    // been correctly decrypted later.
    storage->has_sec_fingerprint = true;
    sha256_Raw((const uint8_t *)scratch, sizeof(scratch),
               storage->sec_fingerprint);

    // Encrypt with the storage key.
    uint8_t iv[64];
    memcpy(iv, ss->storageKey, sizeof(iv));
    aes_encrypt_ctx ctx;
    aes_encrypt_key256(ss->storageKey, &ctx);
    aes_cbc_encrypt((const uint8_t *)scratch, storage->encrypted_sec,
                    sizeof(scratch), iv + 32, &ctx);
    memzero(&ctx, sizeof(ctx));
    storage->encrypted_sec_version = STORAGE_VERSION;
  } else {
    memzero(&storage->sec, sizeof(storage->sec));
    storage->has_sec = false;

    // Decrypt with the storage key.
    uint8_t iv[64];
    memcpy(iv, ss->storageKey, sizeof(iv));
    aes_decrypt_ctx ctx;
    aes_decrypt_key256(ss->storageKey, &ctx);
    if (storage->encrypted_sec_version <= StorageVersion_16) {
      aes_cbc_decrypt((const uint8_t *)storage->encrypted_sec,
                      (uint8_t *)&scratch[0], V16_ENCSEC_SIZE, iv + 32, &ctx);
    } else {
      aes_cbc_decrypt((const uint8_t *)storage->encrypted_sec,
                      (uint8_t *)&scratch[0], sizeof(scratch), iv + 32, &ctx);
    }
    memzero(iv, sizeof(iv));

    // De-serialize from scratch.
    storage_readHDNode(&storage->sec.node, &scratch[0], 129);
    memcpy(storage->sec.mnemonic, &scratch[0] + 129, 241);
    storage_readCacheV1(&storage->sec.cache, &scratch[0] + 370, 75);

    // 129 reserved bytes

    // Check whether the secrets were correctly decrypted
    uint8_t sec_fingerprint[32];
    if (storage->encrypted_sec_version <= StorageVersion_16) {
      sha256_Raw((const uint8_t *)scratch, V16_ENCSEC_SIZE, sec_fingerprint);
    } else {
      sha256_Raw((const uint8_t *)scratch, sizeof(scratch), sec_fingerprint);
    }
    if (storage->has_sec_fingerprint) {
      if (memcmp_s(storage->sec_fingerprint, sec_fingerprint,
                   sizeof(sec_fingerprint)) != 0) {
        assert(false && "storage decrypt failure");
        memzero(scratch, sizeof(scratch));
        storage_wipe();
        layout_warning_static("Storage decrypt failure. Reboot device!");
        shutdown();
      }
    }

    storage->has_sec_fingerprint = true;
    memcpy(storage->sec_fingerprint, sec_fingerprint, sizeof(sec_fingerprint));

    // Derive the u2froot, if we haven't already.
    if (storage->pub.has_mnemonic && !storage->pub.has_u2froot) {
      storage_compute_u2froot(ss, storage->sec.mnemonic, &storage->pub.u2froot);
      storage->pub.has_u2froot = true;
    }

    // authblock migration
    if (storage->encrypted_sec_version <= StorageVersion_16) {
      // initialie authblock to zero and initialize the fingerprint
      memzero(&scratch[512], sizeof(storage->sec.authBlock));
      sha256_Raw((const uint8_t *)&scratch[512], sizeof(storage->sec.authBlock), storage->pub.authdata_fingerprint);
      storage->pub.authdata_initialized = true;
    } else {
      memcpy((void *)&storage->sec.authBlock, &scratch[512], sizeof(storage->sec.authBlock));
    }

#if DEBUG_LINK
    memcpy(debuglink_mnemonic, storage->sec.mnemonic,
           sizeof(debuglink_mnemonic));
    storage_loadNode(&debuglink_node, &storage->sec.node);
#endif

    storage->has_sec = true;
  }

  memzero(scratch, sizeof(scratch));
}

#define AUTHDATA_BLOCKSIZE  512

void storage_deriveAuthdataKey(const char *passphrase, uint8_t authdataKey[64]) {
  storage_deriveWrappingKey(passphrase, authdataKey,
                               /*sca_hardened*/ true,
                               /*v15_16_trans*/ true,
                               shadow_config.storage.pub.random_salt,
                               "deriving authdata key");
  return;
}


static void storage_cipherBlock(bool encrypt, uint8_t *key, 
                uint8_t *plaintextBlock, uint8_t *ciphertextBlock, size_t blockSize) {
  uint8_t iv[64];
  if (encrypt) {
    memcpy(iv, key, sizeof(iv));
    aes_encrypt_ctx ctx;
    aes_encrypt_key256(key, &ctx);
    aes_cbc_encrypt((const uint8_t *)plaintextBlock, ciphertextBlock,
                    blockSize, iv + 32, &ctx);
    memzero(&ctx, sizeof(ctx));
  } else {
    // decrypt
    memcpy(iv, key, sizeof(iv));
    aes_decrypt_ctx ctx;
    aes_decrypt_key256(key, &ctx);
    aes_cbc_decrypt((const uint8_t *)ciphertextBlock,
                      plaintextBlock, blockSize, iv + 32, &ctx);
    memzero(iv, sizeof(iv));
  }
    
  return;
}

void storage_wipeAuthData() {
  authBlockType plaintextAuthBlock = {0};

  memzero((void *)&plaintextAuthBlock, sizeof(plaintextAuthBlock.authData));

  // randomize remaining zeros in reserved area
  random_buffer(plaintextAuthBlock.reserved, sizeof(plaintextAuthBlock.reserved));

  // fingerprint authdata
  sha256_Raw((const uint8_t *)&plaintextAuthBlock, sizeof(plaintextAuthBlock), shadow_config.storage.pub.authdata_fingerprint);

  shadow_config.storage.pub.authdata_encrypted = false;
  memcpy((void *)&shadow_config.storage.sec.authBlock, (const void *)&plaintextAuthBlock, sizeof(shadow_config.storage.sec.authBlock));

  storage_commit();

  memzero((void *)&plaintextAuthBlock, sizeof(plaintextAuthBlock));
  return;
}

bool storage_getAuthData(authType *returnData) {
  uint8_t authdataKey[64] = {0};
  uint8_t testFp[32] = {0};
  authBlockType plaintextAuthBlock = {0};

  if (shadow_config.storage.pub.passphrase_protection && 
        session.passphraseCached && 
        0 != strlen(session.passphrase) &&
        !shadow_config.storage.pub.authdata_encrypted) {
      // This is the case where we have a non-null passphrase but the stored authblock is in plaintext.
      // This happens in the special case where a passphrase is first entered or an upgrade to firmware that supports
      // the authenticator feature (upgrade from storage version <= 16). Read-encrypt-write the authblock.
    memcpy((uint8_t *)&plaintextAuthBlock, (unsigned char *)&shadow_config.storage.sec.authBlock, 
            sizeof(shadow_config.storage.sec.authBlock));
    storage_deriveAuthdataKey(session.passphrase, authdataKey);
    storage_cipherBlock(true /*encrypt*/, authdataKey, (unsigned char *)&plaintextAuthBlock, 
                        (unsigned char *)&shadow_config.storage.sec.authBlock, sizeof(shadow_config.storage.sec.authBlock));
    shadow_config.storage.pub.authdata_encrypted = true;
    storage_commit();
  }

  // copy the auth block to candidate plaintext block and determine if it is encrypted
  memcpy((uint8_t *)&plaintextAuthBlock, (unsigned char *)&shadow_config.storage.sec.authBlock, 
            sizeof(shadow_config.storage.sec.authBlock));

  if (shadow_config.storage.pub.authdata_encrypted) {
    if (shadow_config.storage.pub.passphrase_protection && session.passphraseCached && 0 != strlen(session.passphrase)) {
      // encrypted, candidate passphrase available
      storage_deriveAuthdataKey(session.passphrase, authdataKey);
      storage_cipherBlock(false /*encrypt*/, authdataKey, (unsigned char *)&plaintextAuthBlock, 
                        (unsigned char *)&shadow_config.storage.sec.authBlock, sizeof(shadow_config.storage.sec.authBlock));
    } else {
      // encrypted, passphrase not available
      return false;
    }
  } else {
    // not encrypted. If a passphrase is available, encrypt the
  }

  // fingerprint authdata
  sha256_Raw((const uint8_t *)&plaintextAuthBlock, sizeof(plaintextAuthBlock), testFp);

  // if fingerprints don't match, passphrase, or lack thereof, is not valid for authdata
  if (0 != memcmp(shadow_config.storage.pub.authdata_fingerprint, testFp, sizeof(shadow_config.storage.pub.authdata_fingerprint))) {
    return false;
  }

  memcpy(returnData, plaintextAuthBlock.authData, sizeof(plaintextAuthBlock.authData));
  return true;

}

void storage_setAuthData(authType *setData) {
  authBlockType plaintextAuthBlock = {0};
  uint8_t authdataKey[64] = {0};

  memcpy((void *)&plaintextAuthBlock, (void *)setData, sizeof(plaintextAuthBlock.authData));

  // randomize remaining zeros in reserved area
  random_buffer(plaintextAuthBlock.reserved, sizeof(plaintextAuthBlock.reserved));

  // fingerprint authdata
  sha256_Raw((const uint8_t *)&plaintextAuthBlock, sizeof(plaintextAuthBlock), shadow_config.storage.pub.authdata_fingerprint);
  // encrypt if passphrase available
  if (shadow_config.storage.pub.passphrase_protection && session.passphraseCached && 0 != strlen(session.passphrase)) {
    storage_deriveAuthdataKey(session.passphrase, authdataKey);
    storage_cipherBlock(true /*encrypt*/, authdataKey, (uint8_t *)&plaintextAuthBlock, (uint8_t *)&shadow_config.storage.sec.authBlock, 
                        sizeof(shadow_config.storage.sec.authBlock));
    shadow_config.storage.pub.authdata_encrypted = true;
  } else {
    // not encrypted
    memcpy((void *)&shadow_config.storage.sec.authBlock, (const void *)&plaintextAuthBlock, sizeof(shadow_config.storage.sec.authBlock));
  }

  storage_commit();

  memzero((void *)&plaintextAuthBlock, sizeof(plaintextAuthBlock));
  return;
}

void storage_readStorageV1(SessionState *ss, Storage *storage, const char *ptr,
                           size_t len) {
  if (len < 464 + 17) return;
  storage->version = read_u32_le(ptr);
  storage->pub.has_node = read_bool(ptr + 4);
  storage_readHDNode(&storage->sec.node, ptr + 8, 140);
  storage->pub.has_mnemonic = read_bool(ptr + 140);
  memcpy(storage->sec.mnemonic, ptr + 141, 241);
  storage->pub.passphrase_protection = read_bool(ptr + 383);
  storage->pub.pin_failed_attempts = read_u32_le(ptr + 388);
  storage->pub.has_pin = read_bool(ptr + 392);
  memset(storage->sec.pin, 0, sizeof(storage->sec.pin));
  memcpy(storage->sec.pin, ptr + 393, 10);
  storage->pub.has_language = read_bool(ptr + 403);
  memset(storage->pub.language, 0, sizeof(storage->pub.language));
  memcpy(storage->pub.language, ptr + 404, 17);
  storage->pub.has_label = read_bool(ptr + 421);
  memset(storage->pub.label, 0, sizeof(storage->pub.label));
  memcpy(storage->pub.label, ptr + 422, 33);
  storage->pub.no_backup = false;
  storage->pub.imported = read_bool(ptr + 456);
  if (storage->version == 1) {
    storage->pub.policies_count = 0;
  } else {
    storage->pub.policies_count = 1;
    storage_readPolicyV1(&storage->pub.policies[0], ptr + 464, 17);
  }
  storage->pub.has_auto_lock_delay_ms = true;
  storage->pub.auto_lock_delay_ms = STORAGE_DEFAULT_SCREENSAVER_TIMEOUT;

  // Can't do derivation here, since the pin hasn't been entered.
  storage->pub.has_u2froot = false;
  memzero(&storage->pub.u2froot, sizeof(storage->pub.u2froot));
  storage->pub.u2f_counter = 0;

  if (storage->version == 1) {
    storage_resetPolicies(storage);
    storage_resetCache(&storage->sec.cache);
  } else {
    storage_readCacheV1(&storage->sec.cache, ptr + 484, 75);
  }

  _Static_assert(sizeof(storage->pub.wrapped_storage_key) == 64,
                 "(un)wrapped key must be 64 bytes");

  _Static_assert(sizeof(storage->pub.storage_key_fingerprint) == 32,
                 "key fingerprint must be 32 bytes");

  random_buffer(storage->pub.random_salt, 32);

  storage->has_sec = true;

  storage_setPin_impl(ss, storage,
                      storage->pub.has_pin ? storage->sec.pin : "");

  storage->has_sec_fingerprint = false;

#if DEBUG_LINK
  strlcpy(debuglink_pin, storage->sec.pin, sizeof(debuglink_pin));
  memcpy(debuglink_mnemonic, storage->sec.mnemonic, sizeof(debuglink_mnemonic));
  storage_loadNode(&debuglink_node, &storage->sec.node);
#endif

  if (storage->pub.has_pin) {
    session_clear_impl(ss, storage, /*clear_pin=*/true);
    // No need to storage_commit() here, it will get done
  }
}

void storage_writeStorageV11(char *ptr, size_t len, const Storage *storage) {
  if (len < 852) return;
  write_u32_le(ptr, storage->version);

  uint32_t flags = (storage->pub.has_pin ? (1u << 0) : 0) |
                   (storage->pub.has_language ? (1u << 1) : 0) |
                   (storage->pub.has_label ? (1u << 2) : 0) |
                   (storage->pub.has_auto_lock_delay_ms ? (1u << 3) : 0) |
                   (storage->pub.imported ? (1u << 4) : 0) |
                   (storage->pub.passphrase_protection ? (1u << 5) : 0) |
                   (/* ShapeShift policy, enabled always */ (1u << 6)) |
                   (/* Pin Caching policy, enabled always */ (1u << 7)) |
                   (storage->pub.has_node ? (1u << 8) : 0) |
                   (storage->pub.has_mnemonic ? (1u << 9) : 0) |
                   (storage->pub.has_u2froot ? (1u << 10) : 0) |
                   (storage_isPolicyEnabled("Experimental") ? (1u << 11) : 0) |
                   (storage_isPolicyEnabled("AdvancedMode") ? (1u << 12) : 0) |
                   (storage->pub.no_backup ? (1u << 13) : 0) |
                   (storage->has_sec_fingerprint ? (1u << 14) : 0) |
                   (storage->pub.sca_hardened ? (1u << 15) : 0) |
                   /* reserved 31:16 */ 0;
  write_u32_le(ptr + 4, flags);

  write_u32_le(ptr + 8, storage->pub.pin_failed_attempts);
  write_u32_le(ptr + 12, storage->pub.auto_lock_delay_ms);

  memcpy(ptr + 16, storage->pub.language, 16);
  memcpy(ptr + 32, storage->pub.label, 48);

  memcpy(ptr + 80, storage->pub.wrapped_storage_key, 64);
  memcpy(ptr + 144, storage->pub.storage_key_fingerprint, 32);

  storage_writeHDNode(ptr + 176, 129, &storage->pub.u2froot);
  write_u32_le(ptr + 305, storage->pub.u2f_counter);

  if (storage->has_sec_fingerprint) {
    memcpy(ptr + 309, storage->sec_fingerprint, 32);
  }

  memcpy(ptr + 341, storage->pub.random_salt, 32);

  // 1028 reserved bytes

  // Ignore whatever was in storage->sec. Only encrypted_sec can be committed.
  // Yes, this is a potential footgun. No, there's nothing we can do about it
  // here.

  // Note: the encrypted_sec_version is not necessarily STORAGE_VERSION. If
  // storage is committed without pin entry on storage upgrade, the plaintext
  // and ciphertext storage sections will have different versions.
  write_u32_le(ptr + 464, storage->encrypted_sec_version);

  memcpy(ptr + 468, storage->encrypted_sec, sizeof(storage->encrypted_sec));
}

void storage_readStorageV11(Storage *storage, const char *ptr, size_t len) {
  if (len < 852) return;

  storage->version = read_u32_le(ptr);

  uint32_t flags = read_u32_le(ptr + 4);
  storage->pub.has_pin = flags & (1u << 0);
  storage->pub.has_language = flags & (1u << 1);
  storage->pub.has_label = flags & (1u << 2);
  storage->pub.has_auto_lock_delay_ms = flags & (1u << 3);
  storage->pub.imported = flags & (1u << 4);
  storage->pub.passphrase_protection = flags & (1u << 5);
  storage_readPolicyV2(&storage->pub.policies[0], "ShapeShift", false);
  storage_readPolicyV2(&storage->pub.policies[1], "Pin Caching", true);
  storage->pub.has_node = flags & (1u << 8);
  storage->pub.has_mnemonic = flags & (1u << 9);
  storage->pub.has_u2froot = flags & (1u << 10);
  storage_readPolicyV2(&storage->pub.policies[2], "Experimental",
                       flags & (1u << 11));
  storage_readPolicyV2(&storage->pub.policies[3], "AdvancedMode",
                       flags & (1u << 12));
  storage->pub.no_backup = flags & (1u << 13);
  storage->has_sec_fingerprint = flags & (1u << 14);
  storage->pub.sca_hardened = flags & (1u << 15);
  storage->pub.v15_16_trans = false;

  storage->pub.policies_count = POLICY_COUNT;

  storage->pub.pin_failed_attempts = read_u32_le(ptr + 8);
  storage->pub.auto_lock_delay_ms =
      MAX(read_u32_le(ptr + 12), STORAGE_MIN_SCREENSAVER_TIMEOUT);

  memset(storage->pub.language, 0, sizeof(storage->pub.language));
  memcpy(storage->pub.language, ptr + 16, 16);

  memset(storage->pub.label, 0, sizeof(storage->pub.label));
  memcpy(storage->pub.label, ptr + 32, 48);

  memcpy(storage->pub.wrapped_storage_key, ptr + 80, 64);
  memcpy(storage->pub.storage_key_fingerprint, ptr + 144, 32);

  storage_readHDNode(&storage->pub.u2froot, ptr + 176, 129);
  storage->pub.u2f_counter = read_u32_le(ptr + 305);

  if (storage->has_sec_fingerprint) {
    memcpy(storage->sec_fingerprint, ptr + 309, 32);
  } else {
    memset(storage->sec_fingerprint, 0, sizeof(storage->sec_fingerprint));
  }

  memcpy(storage->pub.random_salt, ptr + 341, 32);

  // 1028 reserved bytes

  storage->has_sec = false;
  memzero(&storage->sec, sizeof(storage->sec));
  storage->encrypted_sec_version = read_u32_le(ptr + 464);
  memcpy(storage->encrypted_sec, ptr + 468, sizeof(storage->encrypted_sec));
}

void storage_writeStorageV16Plaintext(char *ptr, size_t len, const Storage *storage) {
  if (len < 852) return;
  write_u32_le(ptr, storage->version);

  uint32_t flags = (storage->pub.has_pin ? (1u << 0) : 0) |
                   (storage->pub.has_language ? (1u << 1) : 0) |
                   (storage->pub.has_label ? (1u << 2) : 0) |
                   (storage->pub.has_auto_lock_delay_ms ? (1u << 3) : 0) |
                   (storage->pub.imported ? (1u << 4) : 0) |
                   (storage->pub.passphrase_protection ? (1u << 5) : 0) |
                   (/* ShapeShift policy, enabled always */ (1u << 6)) |
                   (/* Pin Caching policy, enabled always */ (1u << 7)) |
                   (storage->pub.has_node ? (1u << 8) : 0) |
                   (storage->pub.has_mnemonic ? (1u << 9) : 0) |
                   (storage->pub.has_u2froot ? (1u << 10) : 0) |
                   (storage_isPolicyEnabled("Experimental") ? (1u << 11) : 0) |
                   (storage_isPolicyEnabled("AdvancedMode") ? (1u << 12) : 0) |
                   (storage->pub.no_backup ? (1u << 13) : 0) |
                   (storage->has_sec_fingerprint ? (1u << 14) : 0) |
                   (storage->pub.sca_hardened ? (1u << 15) : 0) |
                   (storage->pub.has_wipe_code ? (1u << 16) : 0) |
                   (storage->pub.v15_16_trans ? (1u << 17) : 0) |
                   /* reserved 31:18 */ 0;
  write_u32_le(ptr + 4, flags);

  write_u32_le(ptr + 8, storage->pub.pin_failed_attempts);
  write_u32_le(ptr + 12, storage->pub.auto_lock_delay_ms);

  memcpy(ptr + 16, storage->pub.language, 16);
  memcpy(ptr + 32, storage->pub.label, 48);

  memcpy(ptr + 80, storage->pub.wrapped_storage_key, 64);
  memcpy(ptr + 144, storage->pub.storage_key_fingerprint, 32);
  memcpy(ptr + 176, storage->pub.wrapped_wipe_code_key, 64);
  memcpy(ptr + 240, storage->pub.wipe_code_key_fingerprint, 32);

  storage_writeHDNode(ptr + 272, 129, &storage->pub.u2froot);
  write_u32_le(ptr + 401, storage->pub.u2f_counter);

  if (storage->has_sec_fingerprint) {
    memcpy(ptr + 405, storage->sec_fingerprint, 32);
  }

  memcpy(ptr + 437, storage->pub.random_salt, 32);
  return;
}

void storage_writeStorageV16(char *ptr, size_t len, const Storage *storage) {
  // V16 shares the same non-secret storage format as V17

  storage_writeStorageV16Plaintext(ptr, len, storage);
  // 1028 reserved bytes

  // Ignore whatever was in storage->sec. Only encrypted_sec can be committed.
  // Yes, this is a potential footgun. No, there's nothing we can do about it
  // here.

  // Note: the encrypted_sec_version is not necessarily STORAGE_VERSION. If
  // storage is committed without pin entry on storage upgrade, the plaintext
  // and ciphertext storage sections will have different versions.
  write_u32_le(ptr + 1497, storage->encrypted_sec_version);

  memcpy(ptr + 1501, storage->encrypted_sec, sizeof(storage->encrypted_sec));
}


void storage_readStorageV16Plaintext(Storage *storage, const char *ptr, size_t len) {
  if (len < 852) return;

  storage->version = read_u32_le(ptr);

  uint32_t flags = read_u32_le(ptr + 4);
  storage->pub.has_pin = flags & (1u << 0);
  storage->pub.has_language = flags & (1u << 1);
  storage->pub.has_label = flags & (1u << 2);
  storage->pub.has_auto_lock_delay_ms = flags & (1u << 3);
  storage->pub.imported = flags & (1u << 4);
  storage->pub.passphrase_protection = flags & (1u << 5);
  storage_readPolicyV2(&storage->pub.policies[0], "ShapeShift", false);
  storage_readPolicyV2(&storage->pub.policies[1], "Pin Caching", true);
  storage->pub.has_node = flags & (1u << 8);
  storage->pub.has_mnemonic = flags & (1u << 9);
  storage->pub.has_u2froot = flags & (1u << 10);
  storage_readPolicyV2(&storage->pub.policies[2], "Experimental",
                       flags & (1u << 11));
  storage_readPolicyV2(&storage->pub.policies[3], "AdvancedMode",
                       flags & (1u << 12));
  storage->pub.no_backup = flags & (1u << 13);
  storage->has_sec_fingerprint = flags & (1u << 14);
  storage->pub.sca_hardened = flags & (1u << 15);
  storage->pub.has_wipe_code = flags & (1u << 16);
  storage->pub.v15_16_trans = flags & (1u << 17);

  storage->pub.policies_count = POLICY_COUNT;

  storage->pub.pin_failed_attempts = read_u32_le(ptr + 8);
  storage->pub.auto_lock_delay_ms =
      MAX(read_u32_le(ptr + 12), STORAGE_MIN_SCREENSAVER_TIMEOUT);

  memset(storage->pub.language, 0, sizeof(storage->pub.language));
  memcpy(storage->pub.language, ptr + 16, 16);

  memset(storage->pub.label, 0, sizeof(storage->pub.label));
  memcpy(storage->pub.label, ptr + 32, 48);

  memcpy(storage->pub.wrapped_storage_key, ptr + 80, 64);
  memcpy(storage->pub.storage_key_fingerprint, ptr + 144, 32);

  memcpy(storage->pub.wrapped_wipe_code_key, ptr + 176, 64);
  memcpy(storage->pub.wipe_code_key_fingerprint, ptr + 240, 32);

  storage_readHDNode(&storage->pub.u2froot, ptr + 272, 129);
  storage->pub.u2f_counter = read_u32_le(ptr + 401);

  if (storage->has_sec_fingerprint) {
    memcpy(storage->sec_fingerprint, ptr + 405, 32);
  } else {
    memset(storage->sec_fingerprint, 0, sizeof(storage->sec_fingerprint));
  }

  memcpy(storage->pub.random_salt, ptr + 437, 32);
  return;
}

void storage_readStorageV16(Storage *storage, const char *ptr, size_t len) {

  // V16 shares the same non-secret storage format as V17
  storage_readStorageV16Plaintext(storage, ptr, len);

  // 1028 reserved bytes

  storage->has_sec = false;
  memzero(&storage->sec, sizeof(storage->sec));
  storage->encrypted_sec_version = read_u32_le(ptr + 1497);
  memcpy(storage->encrypted_sec, ptr + 1501, V16_ENCSEC_SIZE);
}

void storage_writeStorageV17(char *ptr, size_t len, const Storage *storage) {
  // V16 shares most of the same non-secret storage format as V17
  storage_writeStorageV16Plaintext(ptr, len, storage);

  // V17 additions
  uint32_t flags = read_u32_le(ptr + 4);
  flags |= (storage->pub.authdata_initialized ? (1u << 18) : 0) |
           (storage->pub.authdata_encrypted ? (1u << 19) : 0);
  write_u32_le(ptr + 4, flags);
  memcpy(ptr + 469, storage->pub.authdata_fingerprint, 32);

  // 996 reserved bytes

  // Ignore whatever was in storage->sec. Only encrypted_sec can be committed.
  // Yes, this is a potential footgun. No, there's nothing we can do about it
  // here.

  // Note: the encrypted_sec_version is not necessarily STORAGE_VERSION. If
  // storage is committed without pin entry on storage upgrade, the plaintext
  // and ciphertext storage sections will have different versions.
  write_u32_le(ptr + 1497, storage->encrypted_sec_version);

  memcpy(ptr + 1501, storage->encrypted_sec, sizeof(storage->encrypted_sec));
}

void storage_readStorageV17(Storage *storage, const char *ptr, size_t len) {

  // V16 shares most of the same non-secret storage format as V17
  storage_readStorageV16Plaintext(storage, ptr, len);
  
  // V17 additions
  uint32_t flags = read_u32_le(ptr + 4);
  storage->pub.authdata_initialized = flags & (1u << 18);
  storage->pub.authdata_encrypted = flags & (1u << 19);
  memcpy(storage->pub.authdata_fingerprint, ptr + 469, 32);

  // 996 reserved bytes

  storage->has_sec = false;
  memzero(&storage->sec, sizeof(storage->sec));
  storage->encrypted_sec_version = read_u32_le(ptr + 1497);
  memcpy(storage->encrypted_sec, ptr + 1501, sizeof(storage->encrypted_sec));
}


void storage_readCacheV1(Cache *cache, const char *ptr, size_t len) {
  if (len < 65 + 10) return;
  cache->root_seed_cache_status = read_u8(ptr);
  memcpy(cache->root_seed_cache, ptr + 1, 64);
  memcpy(cache->root_ecdsa_curve_type, ptr + 65, 10);
}

void storage_writeCacheV1(char *ptr, size_t len, const Cache *cache) {
  if (len < 65 + 10) return;
  write_u8(ptr, cache->root_seed_cache_status);
  memcpy(ptr + 1, cache->root_seed_cache, 64);
  memcpy(ptr + 65, cache->root_ecdsa_curve_type, 10);
}

_Static_assert(offsetof(Cache, root_seed_cache) == 1, "rsc");
_Static_assert(offsetof(Cache, root_ecdsa_curve_type) == 65, "rect");
_Static_assert(sizeof(((Cache *)0)->root_ecdsa_curve_type) == 10, "rect");

void storage_readV1(SessionState *ss, ConfigFlash *dst, const char *flash,
                    size_t len) {
  if (len < 44 + 528) return;
  storage_readMeta(&dst->meta, flash, 44);
  storage_readStorageV1(ss, &dst->storage, flash + 44, 481);
}

void storage_readV2(SessionState *ss, ConfigFlash *dst, const char *flash,
                    size_t len) {
  if (len < 528 + 75) return;
  storage_readMeta(&dst->meta, flash, 44);
  storage_readStorageV1(ss, &dst->storage, flash + 44, 481);
}

void storage_readV11(ConfigFlash *dst, const char *flash, size_t len) {
  if (len < 1024) return;
  storage_readMeta(&dst->meta, flash, 44);
  storage_readStorageV11(&dst->storage, flash + 44, 852);
}

void storage_writeV11(char *flash, size_t len, const ConfigFlash *src) {
  if (len < 1024) return;
  storage_writeMeta(flash, 44, &src->meta);
  storage_writeStorageV11(flash + 44, 852, &src->storage);
}

void storage_readV16(ConfigFlash *dst, const char *flash, size_t len) {
  if (len < 1024) return;
  storage_readMeta(&dst->meta, flash, 44);
  storage_readStorageV16(&dst->storage, flash + 44, 852);
}

void storage_writeV16(char *flash, size_t len, const ConfigFlash *src) {
  if (len < 1024) return;
  storage_writeMeta(flash, 44, &src->meta);
  storage_writeStorageV16(flash + 44, 852, &src->storage);
}

void storage_readV17(ConfigFlash *dst, const char *flash, size_t len) {
  if (len < 1024) return;
  storage_readMeta(&dst->meta, flash, 44);
  storage_readStorageV17(&dst->storage, flash + 44, 852);
}

void storage_writeV17(char *flash, size_t len, const ConfigFlash *src) {
  if (len < 1024) return;
  storage_writeMeta(flash, 44, &src->meta);
  storage_writeStorageV17(flash + 44, 852, &src->storage);
}

StorageUpdateStatus storage_fromFlash(SessionState *ss, ConfigFlash *dst,
                                      const char *flash) {
  memzero(dst, sizeof(*dst));

  // Load config values from active config node.
  enum StorageVersion version = version_from_int(read_u32_le(flash + 44));

  switch (version) {
    case StorageVersion_1:
      storage_readV1(ss, dst, flash, STORAGE_SECTOR_LEN);
      dst->storage.version = STORAGE_VERSION;
      return SUS_Updated;

    case StorageVersion_2:
    case StorageVersion_3:
    case StorageVersion_4:
    case StorageVersion_5:
    case StorageVersion_6:
    case StorageVersion_7:
    case StorageVersion_8:
    case StorageVersion_9:
    case StorageVersion_10:
      storage_readV2(ss, dst, flash, STORAGE_SECTOR_LEN);
      dst->storage.version = STORAGE_VERSION;

      /* We have to do this for users with bootloaders <= v1.0.2. This
      scenario would only happen after a firmware install from the same
      storage version */
      if (dst->storage.pub.policies_count == 0xFFFFFFFF) {
        storage_resetPolicies(&dst->storage);
        storage_resetCache(&dst->storage.sec.cache);
        return SUS_Updated;
      }

      storage_upgradePolicies(&dst->storage);

      return dst->storage.version == version ? SUS_Valid : SUS_Updated;

    case StorageVersion_11:
    case StorageVersion_12:
    case StorageVersion_13:
    case StorageVersion_14:
    case StorageVersion_15:
      storage_readV11(dst, flash, STORAGE_SECTOR_LEN);
      dst->storage.version = STORAGE_VERSION;
      return dst->storage.version == version ? SUS_Valid : SUS_Updated;
    case StorageVersion_16:
      storage_readV16(dst, flash, STORAGE_SECTOR_LEN);
      dst->storage.version = STORAGE_VERSION;
      return dst->storage.version == version ? SUS_Valid : SUS_Updated;
    case StorageVersion_17:
      storage_readV17(dst, flash, STORAGE_SECTOR_LEN);
      dst->storage.version = STORAGE_VERSION;
      return dst->storage.version == version ? SUS_Valid : SUS_Updated;

    case StorageVersion_NONE:
      return SUS_Invalid;

      // DO *NOT* add a default case
  }

#ifdef DEBUG_ON
  // Should be unreachable, but we don't want to tell the compiler that in a
  // release build. The benefit to doing it this way is that with the
  // unreachable and lack of default case in the switch, the compiler will
  // tell us if we have not covered every case in the switch.
  __builtin_unreachable();
#endif

  return SUS_Invalid;
}

/// \brief Shifts sector for config storage
static void wear_leveling_shift(void) {
  switch (storage_location) {
    case FLASH_STORAGE1: {
      storage_location = FLASH_STORAGE2;
      break;
    }

    case FLASH_STORAGE2: {
      storage_location = FLASH_STORAGE3;
      break;
    }

    /* wraps around */
    case FLASH_STORAGE3: {
      storage_location = FLASH_STORAGE1;
      break;
    }

    default: {
      storage_location = STORAGE_SECT_DEFAULT;
      break;
    }
  }
}

/// \brief Set root session seed in storage.
///
/// \param cfg[in]    The active storage sector.
/// \param seed[in]   Root seed to write into storage.
/// \param curve[in]  ECDSA curve name being used.
static void storage_setRootSeedCache(const SessionState *ss, ConfigFlash *cfg,
                                     const uint8_t *seed, const char *curve) {
  // Don't cache when passphrase protection is enabled.
  if (cfg->storage.pub.passphrase_protection && strlen(ss->passphrase)) return;

  memset(&cfg->storage.sec.cache, 0, sizeof(cfg->storage.sec.cache));

  memcpy(&cfg->storage.sec.cache.root_seed_cache, seed,
         sizeof(cfg->storage.sec.cache.root_seed_cache));

  strlcpy(cfg->storage.sec.cache.root_ecdsa_curve_type, curve,
          sizeof(cfg->storage.sec.cache.root_ecdsa_curve_type));

  cfg->storage.sec.cache.root_seed_cache_status = CACHE_EXISTS;
  cfg->storage.has_sec = true;
  storage_commit();
}

/// \brief Get root session seed cache from storage.
///
/// \param cfg[in]   The active storage sector.
/// \param curve[in] ECDSA curve name being used.
/// \param seed[out] The root seed value.
/// \returns true on success.
static bool storage_getRootSeedCache(const SessionState *ss, ConfigFlash *cfg,
                                     const char *curve, bool usePassphrase,
                                     uint8_t *seed) {
  if (!cfg->storage.has_sec) return false;

  if (cfg->storage.sec.cache.root_seed_cache_status != CACHE_EXISTS)
    return false;

  if (usePassphrase && cfg->storage.pub.passphrase_protection &&
      strlen(ss->passphrase)) {
    return false;
  }

  if (strcmp(cfg->storage.sec.cache.root_ecdsa_curve_type, curve) != 0) {
    return false;
  }

  memset(seed, 0, sizeof(ss->seed));
  memcpy(seed, &cfg->storage.sec.cache.root_seed_cache,
         sizeof(cfg->storage.sec.cache.root_seed_cache));
  _Static_assert(
      sizeof(ss->seed) == sizeof(cfg->storage.sec.cache.root_seed_cache),
      "size mismatch");
  return true;
}

void storage_init(void) {
  // Find storage sector with valid data and set storage_location variable.
  if (!find_active_storage(&storage_location)) {
    // Otherwise initialize it to the default sector.
    storage_location = STORAGE_SECT_DEFAULT;
  }
  const char *flash = (const char *)flash_write_helper(storage_location);

  // Reset shadow configuration in RAM
  storage_reset_impl(&session, &shadow_config);

  // If the storage partition is not already active
  if (!storage_isActiveSector(flash)) {
    // ... activate it by pupoulating new Metadata section,
    // and writing it to flash.
    storage_resetUuid();
    storage_commit();
    return;
  }

  // Otherwise clear out flash before looking for end config node.
  memcpy(shadow_config.meta.uuid, ((const Metadata *)flash)->uuid,
         sizeof(shadow_config.meta.uuid));
  data2hex(shadow_config.meta.uuid, sizeof(shadow_config.meta.uuid),
           shadow_config.meta.uuid_str);

  // Load storage from flash, and update it if necessary.
  switch (storage_fromFlash(&session, &shadow_config, flash)) {
    case SUS_Invalid:
      storage_reset();
      storage_commit();
      break;
    case SUS_Valid:
      break;
    case SUS_Updated:
      // If the version changed, write the new storage to flash so
      // that it's available on next boot without conversion.
      storage_commit();
      break;
  }

  if (!storage_hasPin()) {
    // Cache the PIN
#ifndef NDEBUG
    bool ret =
#endif
        storage_isPinCorrect("");
    assert(ret && "Empty PIN not cached?");
  }
}

void storage_resetUuid(void) { storage_resetUuid_impl(&shadow_config); }

void storage_resetUuid_impl(ConfigFlash *cfg) {
#ifdef EMULATOR
  random_buffer(cfg->meta.uuid, sizeof(cfg->meta.uuid));
#else
  _Static_assert(sizeof(cfg->meta.uuid) == 3 * sizeof(uint32_t),
                 "uuid not large enough");
  desig_get_unique_id((uint32_t *)cfg->meta.uuid);
#endif
  data2hex(cfg->meta.uuid, sizeof(cfg->meta.uuid), cfg->meta.uuid_str);
}

void storage_reset(void) { storage_reset_impl(&session, &shadow_config); }

void storage_reset_impl(SessionState *ss, ConfigFlash *cfg) {
  memset(&cfg->storage, 0, sizeof(cfg->storage));

  storage_resetPolicies(&cfg->storage);

  storage_setPin_impl(ss, &cfg->storage, "");

  cfg->storage.version = STORAGE_VERSION;

  memzero(ss, sizeof(*ss));

  cfg->storage.has_sec = false;
  memzero(&cfg->storage.sec, sizeof(cfg->storage.sec));
}

void storage_wipe(void) {
  flash_erase_word(FLASH_STORAGE1);
  flash_erase_word(FLASH_STORAGE2);
  flash_erase_word(FLASH_STORAGE3);
}

void storage_clearKeys(void) {
  session_clear_impl(&session, &shadow_config.storage, false);
  memzero(&session.storageKey, sizeof(session.storageKey));
  memzero(&shadow_config.storage.pub.wrapped_storage_key,
          sizeof(shadow_config.storage.pub.wrapped_storage_key));
  memzero(&shadow_config.storage.pub.storage_key_fingerprint,
          sizeof(shadow_config.storage.pub.storage_key_fingerprint));

  session.pinCached = false;
  storage_commit();
}

void session_clear(bool clear_pin) {
  if (PIN_REWRAP ==
      session_clear_impl(&session, &shadow_config.storage, clear_pin)) {
    storage_commit();
  }
}

pintest_t session_clear_impl(SessionState *ss, Storage *storage,
                             bool clear_pin) {
  /*
     This is a *_impl() function that is assumed to not modify the flash
     storage config state. Because this function calls
     storage_isPinCorrect_impl(), the storage config may need updating: This
     function will return PIN_WRONG  - PIN is incorrect PIN_GOOD   - PIN is
     correct PIN_REWRAP -> PIN is correct, storage key was rewrapped, CALLING
     FUNCTION SHOULD storage_commit()

     If the pin is correct, the shadow config may be out of sync with the
     storage config in flash. Thus, if the return is PIN_REWRAP, then the
     calling function is required to update the flash with a storage_commit().
  */
  pintest_t ret = PIN_WRONG;

  ss->seedCached = false;
  memset(&ss->seed, 0, sizeof(ss->seed));

  ss->passphraseCached = false;
  memset(&ss->passphrase, 0, sizeof(ss->passphrase));

  if (!storage_hasPin_impl(storage)) {
    ret = storage_isPinCorrect_impl("", storage->pub.wrapped_storage_key,
                                    storage->pub.storage_key_fingerprint,
                                    &storage->pub.sca_hardened, 
                                    &storage->pub.v15_16_trans, 
                                    ss->storageKey,
                                    shadow_config.storage.pub.random_salt);

    if (ret == PIN_WRONG) {
      ss->pinCached = false;
    } else {
      ss->pinCached = true;
    }

    if (!ss->pinCached) goto clear;
    storage_secMigrate(ss, storage, /*encrypt=*/false);
    return (ret);
  }

  if (!clear_pin) {
    return (ret);
  }

clear:
  memzero(ss->storageKey, sizeof(ss->storageKey));
  ss->pinCached = false;
  storage->has_sec = false;
  memzero(&storage->sec, sizeof(storage->sec));
  return (ret);
}

void storage_commit(void) {
  // Temporary storage for marshalling secrets in & out of flash.
  // Size of v17 storage layout (2525 bytes) + size of meta (44 bytes) + 1
  static char flash_temp[2570];

  memzero(flash_temp, sizeof(flash_temp));

  if (session.pinCached || !shadow_config.storage.pub.has_pin) {
    storage_secMigrate(&session, &shadow_config.storage, /*encrypt=*/true);
  } else {
    // commit what was in storage->encrypted_sec
  }

  storage_writeV17(flash_temp, sizeof(flash_temp), &shadow_config);

  memcpy(&shadow_config, STORAGE_MAGIC_STR, STORAGE_MAGIC_LEN);

  uint32_t retries = 0;
  for (retries = 0; retries < STORAGE_RETRIES; retries++) {
    /* Capture CRC for verification at restore */
    uint32_t shadow_ram_crc32 =
        calc_crc32(flash_temp, sizeof(flash_temp) / sizeof(uint32_t));

    if (shadow_ram_crc32 == 0) {
      continue; /* Retry */
    }

    /* Make sure storage sector is valid before proceeding */
    if (storage_location < FLASH_STORAGE1 ||
        storage_location > FLASH_STORAGE3) {
      /* Let it exhaust the retries and error out */
      continue;
    }

    flash_erase_word(storage_location);
    wear_leveling_shift();
    flash_erase_word(storage_location);

    /* Write storage data first before writing storage magic  */
    if (!flash_write_word(storage_location, STORAGE_MAGIC_LEN,
                          sizeof(flash_temp) - STORAGE_MAGIC_LEN,
                          (uint8_t *)flash_temp + STORAGE_MAGIC_LEN)) {
      flash_erase_word(storage_location);
      continue;  // Retry
    }

    if (!flash_write_word(storage_location, 0, STORAGE_MAGIC_LEN,
                          (uint8_t *)flash_temp)) {
      flash_erase_word(storage_location);
      continue;  // Retry
    }

    /* Flash write completed successfully.  Verify CRC */
    uint32_t shadow_flash_crc32 =
        calc_crc32((const void *)flash_write_helper(storage_location),
                   sizeof(flash_temp) / sizeof(uint32_t));

    if (shadow_flash_crc32 == shadow_ram_crc32) {
      storage_protect_off();
      /* Commit successful, break to exit */
      break;
    }
  }

  memzero(flash_temp, sizeof(flash_temp));

  if (retries >= STORAGE_RETRIES) {
    storage_wipe();
    layout_warning_static("Error Detected.  Reboot Device!");
    shutdown();
  }
}

// Great candidate for C++ templates... sigh.
void storage_dumpNode(HDNodeType *dst, const HDNode *src) {
#if DEBUG_LINK
  dst->depth = src->depth;
  dst->fingerprint = 0;
  dst->child_num = src->child_num;

  dst->chain_code.size = sizeof(src->chain_code);
  memcpy(dst->chain_code.bytes, src->chain_code, sizeof(src->chain_code));
  _Static_assert(sizeof(dst->chain_code.bytes) == sizeof(src->chain_code),
                 "chain_code type mismatch");

  dst->has_private_key = true;
  dst->private_key.size = sizeof(src->private_key);
  memcpy(dst->private_key.bytes, src->private_key, sizeof(src->private_key));
  _Static_assert(sizeof(dst->private_key.bytes) == sizeof(src->private_key),
                 "private_key type mismatch");

  dst->has_public_key = true;
  dst->public_key.size = sizeof(src->public_key);
  memcpy(dst->public_key.bytes, src->public_key, sizeof(src->public_key));
  _Static_assert(sizeof(dst->public_key.bytes) == sizeof(src->public_key),
                 "public_key type mismatch");
#else
  (void)dst;
  (void)src;
#endif
}

void storage_loadNode(HDNode *dst, const HDNodeType *src) {
  dst->depth = src->depth;
  dst->child_num = src->child_num;

  memcpy(dst->chain_code, src->chain_code.bytes, sizeof(src->chain_code.bytes));
  _Static_assert(sizeof(dst->chain_code) == sizeof(src->chain_code.bytes),
                 "chain_code type mismatch");

  if (src->has_private_key) {
    memcpy(dst->private_key, src->private_key.bytes,
           sizeof(src->private_key.bytes));
    _Static_assert(sizeof(dst->private_key) == sizeof(src->private_key.bytes),
                   "private_key type mismatch");
  } else {
    memzero(dst->private_key, sizeof(dst->private_key));
  }

  if (src->has_public_key) {
    memcpy(dst->public_key, src->public_key.bytes, sizeof(src->public_key));
    _Static_assert(sizeof(dst->public_key) == sizeof(src->public_key.bytes),
                   "public_key type mismatch");
  } else {
    memzero(dst->public_key, sizeof(dst->public_key));
  }
}

void storage_loadDevice(LoadDevice *msg) {
  storage_reset_impl(&session, &shadow_config);

  shadow_config.storage.pub.imported = true;

  storage_setPin(msg->has_pin ? msg->pin : "");

  shadow_config.storage.pub.no_backup = false;
  shadow_config.storage.pub.passphrase_protection =
      msg->has_passphrase_protection && msg->passphrase_protection;

  if (msg->has_node) {
    shadow_config.storage.pub.has_node = true;
    shadow_config.storage.pub.has_mnemonic = false;
    shadow_config.storage.has_sec = true;
    memcpy(&shadow_config.storage.sec.node, &msg->node, sizeof(msg->node));
#if DEBUG_LINK
    storage_loadNode(&debuglink_node, &msg->node);
#endif
    session.seedCached = false;
    memset(&session.seed, 0, sizeof(session.seed));
  } else if (msg->has_mnemonic) {
    shadow_config.storage.pub.has_mnemonic = true;
    shadow_config.storage.pub.has_node = false;
    shadow_config.storage.has_sec = true;
    strlcpy(shadow_config.storage.sec.mnemonic, msg->mnemonic,
            sizeof(shadow_config.storage.sec.mnemonic));
#if DEBUG_LINK
    memcpy(debuglink_mnemonic, msg->mnemonic, sizeof(debuglink_mnemonic));
#endif
    storage_compute_u2froot(&session, shadow_config.storage.sec.mnemonic,
                            &shadow_config.storage.pub.u2froot);
    shadow_config.storage.pub.has_u2froot = true;
    session.seedCached = false;
    memset(&session.seed, 0, sizeof(session.seed));
  }

  if (msg->has_language) {
    storage_setLanguage(msg->language);
  }

  if (msg->has_label) {
    storage_setLabel(msg->label);
  }

  if (msg->has_u2f_counter) {
    storage_setU2FCounter(msg->u2f_counter);
  }
}

void storage_setLabel(const char *label) {
  if (!label) {
    return;
  }

  shadow_config.storage.pub.has_label = true;
  memset(shadow_config.storage.pub.label, 0,
         sizeof(shadow_config.storage.pub.label));
  strlcpy(shadow_config.storage.pub.label, label,
          sizeof(shadow_config.storage.pub.label));
}

const char *storage_getLabel(void) {
  if (!shadow_config.storage.pub.has_label) {
    return NULL;
  }

  return shadow_config.storage.pub.label;
}

void storage_setLanguage(const char *lang) {
  if (!lang) {
    return;
  }

  // sanity check
  if (strcmp(lang, "english") == 0) {
    shadow_config.storage.pub.has_language = true;
    memset(shadow_config.storage.pub.language, 0,
           sizeof(shadow_config.storage.pub.language));
    strlcpy(shadow_config.storage.pub.language, lang,
            sizeof(shadow_config.storage.pub.language));
  }
}

const char *storage_getLanguage(void) {
  if (!shadow_config.storage.pub.has_language) {
    return NULL;
  }

  return shadow_config.storage.pub.language;
}

bool storage_isPinCorrect(const char *pin) {

  pintest_t ret = storage_isPinCorrect_impl(
      pin, shadow_config.storage.pub.wrapped_storage_key,
      shadow_config.storage.pub.storage_key_fingerprint,
      &shadow_config.storage.pub.sca_hardened, 
      &shadow_config.storage.pub.v15_16_trans, 
      session.storageKey,
      shadow_config.storage.pub.random_salt);

  switch (ret) {
    case PIN_REWRAP:
      session.pinCached = true;
      storage_commit();
      storage_secMigrate(&session, &shadow_config.storage, /*encrypt=*/false);
      break;
    case PIN_GOOD:
      session.pinCached = true;
      storage_secMigrate(&session, &shadow_config.storage, /*encrypt=*/false);
      break;
    case PIN_WRONG:
    default:
      session.pinCached = false;
      session_clear_impl(&session, &shadow_config.storage, /*clear_pin=*/true);
      memzero(session.storageKey, sizeof(session.storageKey));
      break;
  }

  return ret;
}

bool storage_hasPin(void) {
  return storage_hasPin_impl(&shadow_config.storage);
}

bool storage_hasPin_impl(const Storage *storage) {
  return storage->pub.has_pin;
}

void storage_setPin(const char *pin) {
  storage_setPin_impl(&session, &shadow_config.storage, pin);

  session.pinCached = true;

#if DEBUG_LINK
  strlcpy(debuglink_pin, pin, sizeof(debuglink_pin));
#endif
}

void storage_setPin_impl(SessionState *ss, Storage *storage, const char *pin) {
  // Derive the wrapping key for the new pin
  uint8_t wrapping_key[64];
  storage_deriveWrappingKey(pin, wrapping_key, /*sca_hardened=*/true, 
                            /*v15_16_trans=*/true,
                            storage->pub.random_salt, _("Encrypting Secrets"));

  // Derive a new storageKey.
  random_buffer(ss->storageKey, 64);

  // Wrap the new storageKey.
  storage_wrapStorageKey(wrapping_key, ss->storageKey,
                         storage->pub.wrapped_storage_key);
  storage->pub.sca_hardened = true;
  storage->pub.v15_16_trans = true;

  // Fingerprint the storageKey.
  storage_keyFingerprint(ss->storageKey, storage->pub.storage_key_fingerprint);

  // Clean up secrets to get them off the stack.
  memzero(wrapping_key, sizeof(wrapping_key));

  storage->pub.has_pin = !!strlen(pin);
  storage_secMigrate(ss, storage, /*encrypt=*/true);
}

bool storage_isWipeCodeCorrect(const char *wipe_code) {
  uint8_t scratch_key[64];
  pintest_t ret = storage_isWipeCodeCorrect_impl(
      wipe_code, shadow_config.storage.pub.wrapped_wipe_code_key,
      shadow_config.storage.pub.wipe_code_key_fingerprint, scratch_key,
      shadow_config.storage.pub.random_salt);

  if (ret == PIN_WRONG) {
    session_clear_impl(&session, &shadow_config.storage, /*clear_pin=*/true);
    memzero(session.storageKey, sizeof(session.storageKey));
  }

  memset(scratch_key, 0, sizeof(scratch_key));
  return ret;
}

bool storage_hasWipeCode(void) {
  return storage_hasWipeCode_impl(&shadow_config.storage);
}

bool storage_hasWipeCode_impl(const Storage *storage) {
  return storage->pub.has_wipe_code;
}

void storage_setWipeCode(const char *wipe_code) {
  storage_setWipeCode_impl(&session, &shadow_config.storage, wipe_code);

#if DEBUG_LINK
  strlcpy(debuglink_wipe_code, wipe_code, sizeof(debuglink_wipe_code));
#endif
}

void storage_setWipeCode_impl(SessionState *ss, Storage *storage,
                              const char *wipe_code) {
  uint8_t scratch_key[64];
  // Derive the wrapping key for the new wipe code
  uint8_t wrapping_key[64];
  storage_deriveWrappingKey(wipe_code, wrapping_key, /*sca_hardened=*/true,
                            /*v15_16_trans=*/true,
                            storage->pub.random_salt, _("Updating Wipe Code"));

  // Derive a new wipe code key .
  random_buffer(scratch_key, 64);

  // Wrap the new wipe code key.
  storage_wrapStorageKey(wrapping_key, scratch_key,
                         storage->pub.wrapped_wipe_code_key);
  storage->pub.sca_hardened = true;

  // Fingerprint the wipe code key.
  storage_keyFingerprint(scratch_key, storage->pub.wipe_code_key_fingerprint);

  // Clean up secrets to get them off the stack.
  memzero(wrapping_key, sizeof(wrapping_key));
  memzero(scratch_key, sizeof(scratch_key));

  storage->pub.has_wipe_code = !!strlen(wipe_code);

  storage_secMigrate(ss, storage, /*encrypt=*/true);
}

bool session_isPinCached(void) { return session.pinCached; }

void storage_resetPinFails(void) {
  shadow_config.storage.pub.pin_failed_attempts = 0;

  storage_commit();
}

void storage_increasePinFails(void) {
  shadow_config.storage.pub.pin_failed_attempts++;

  storage_commit();
}

uint32_t storage_getPinFails(void) {
  return shadow_config.storage.pub.pin_failed_attempts;
}

/// \brief Calls animation callback.
/// \param iter Current iteration.
/// \param total Total iterations.
static void get_root_node_callback(uint32_t iter, uint32_t total) {
  animating_progress_handler(_("Waking up"), 1000 * iter / total);
}

const uint8_t *storage_getSeed(const ConfigFlash *cfg, bool usePassphrase) {
  // root node is properly cached
  if (usePassphrase == session.seedUsesPassphrase && session.seedCached) {
    return session.seed;
  }

  // if storage has mnemonic, convert it to node and use it
  if (cfg->storage.pub.has_mnemonic) {
    if (!cfg->storage.has_sec) {
      return NULL;
    }

    if (usePassphrase && !passphrase_protect()) {
      return NULL;
    }

    mnemonic_to_seed(cfg->storage.sec.mnemonic,
                     usePassphrase ? session.passphrase : "", session.seed,
                     get_root_node_callback);  // BIP-0039
    session.seedCached = true;
    session.seedUsesPassphrase = usePassphrase;
    return session.seed;
  }

  return NULL;
}

bool storage_getRootNode(const char *curve, bool usePassphrase, HDNode *node) {
  // if storage has node, decrypt and use it
  if (shadow_config.storage.pub.has_node &&
      strcmp(curve, SECP256K1_NAME) == 0) {
    if (!shadow_config.storage.has_sec) {
      return false;
    }

    if (!passphrase_protect()) {
      /* passphrased failed. Bailing */
      return false;
    }

    if (hdnode_from_xprv(shadow_config.storage.sec.node.depth,
                         shadow_config.storage.sec.node.child_num,
                         shadow_config.storage.sec.node.chain_code.bytes,
                         shadow_config.storage.sec.node.private_key.bytes,
                         curve, node) == 0) {
      return false;
    }

    if (shadow_config.storage.pub.passphrase_protection &&
        session.passphraseCached && strlen(session.passphrase) > 0) {
      // decrypt hd node
      static uint8_t CONFIDENTIAL secret[64];
      PBKDF2_HMAC_SHA512_CTX pctx;
      pbkdf2_hmac_sha512_Init(&pctx, (const uint8_t *)session.passphrase,
                              strlen(session.passphrase),
                              (const uint8_t *)"TREZORHD", 8, 1);
      for (int i = 0; i < 8; i++) {
        pbkdf2_hmac_sha512_Update(&pctx, BIP39_PBKDF2_ROUNDS / 8);
        get_root_node_callback((i + 1) * BIP39_PBKDF2_ROUNDS / 8,
                               BIP39_PBKDF2_ROUNDS);
      }
      pbkdf2_hmac_sha512_Final(&pctx, secret);
      aes_decrypt_ctx ctx;
      aes_decrypt_key256(secret, &ctx);
      aes_cbc_decrypt(node->chain_code, node->chain_code, 32, secret + 32,
                      &ctx);
      aes_cbc_decrypt(node->private_key, node->private_key, 32, secret + 32,
                      &ctx);
      memzero(&ctx, sizeof(ctx));
      memzero(secret, sizeof(secret));
    }

    return true;
  }

  /* get node from mnemonic */
  if (shadow_config.storage.pub.has_mnemonic) {
    if (!shadow_config.storage.has_sec) {
      return false;
    }

    if (!passphrase_protect()) {
      /* passphrased failed. Bailing */
      return false;
    }

    if (!session.seedCached) {
      session.seedCached = storage_getRootSeedCache(
          &session, &shadow_config, curve, usePassphrase, session.seed);

      if (!session.seedCached) {
        /* calculate session seed and update the global
         * sessionSeed/sessionSeedCached variables */
        storage_getSeed(&shadow_config, usePassphrase);

        if (!session.seedCached) {
          return false;
        }

        storage_setRootSeedCache(&session, &shadow_config, session.seed, curve);
      }
    }

    if (hdnode_from_seed(session.seed, 64, curve, node) == 1) {
      return true;
    }
  }

  return false;
}

bool storage_isInitialized(void) {
  return shadow_config.storage.pub.has_node ||
         shadow_config.storage.pub.has_mnemonic;
}

const char *storage_getUuidStr(void) { return shadow_config.meta.uuid_str; }

bool storage_getPassphraseProtected(void) {
  return shadow_config.storage.pub.passphrase_protection;
}

void storage_setPassphraseProtected(bool passphrase) {
  shadow_config.storage.pub.passphrase_protection = passphrase;
}

void session_cachePassphrase(const char *passphrase) {
  strlcpy(session.passphrase, passphrase, sizeof(session.passphrase));
  session.passphraseCached = true;
}

bool session_isPassphraseCached(void) { return session.passphraseCached; }

void storage_setMnemonicFromWords(const char (*words)[12],
                                  unsigned int word_count) {
  strlcpy(shadow_config.storage.sec.mnemonic, words[0],
          sizeof(shadow_config.storage.sec.mnemonic));
#if DEBUG_LINK
  strlcpy(debuglink_mnemonic, words[0], sizeof(debuglink_mnemonic));
#endif

  for (uint32_t i = 1; i < word_count; i++) {
    strlcat(shadow_config.storage.sec.mnemonic, " ",
            sizeof(shadow_config.storage.sec.mnemonic));
    strlcat(shadow_config.storage.sec.mnemonic, words[i],
            sizeof(shadow_config.storage.sec.mnemonic));
#if DEBUG_LINK
    strlcat(debuglink_mnemonic, " ", sizeof(debuglink_mnemonic));
    strlcat(debuglink_mnemonic, words[i], sizeof(debuglink_mnemonic));
#endif
  }

  shadow_config.storage.pub.has_mnemonic = true;
  shadow_config.storage.has_sec = true;

  storage_compute_u2froot(&session, shadow_config.storage.sec.mnemonic,
                          &shadow_config.storage.pub.u2froot);
  shadow_config.storage.pub.has_u2froot = true;
}

void storage_setMnemonic(const char *m) {
  memset(shadow_config.storage.sec.mnemonic, 0,
         sizeof(shadow_config.storage.sec.mnemonic));
  strlcpy(shadow_config.storage.sec.mnemonic, m,
          sizeof(shadow_config.storage.sec.mnemonic));
#if DEBUG_LINK
  memset(debuglink_mnemonic, 0, sizeof(debuglink_mnemonic));
  strlcpy(debuglink_mnemonic, m, sizeof(debuglink_mnemonic));
#endif
  shadow_config.storage.pub.has_mnemonic = true;
  shadow_config.storage.has_sec = true;

  storage_compute_u2froot(&session, shadow_config.storage.sec.mnemonic,
                          &shadow_config.storage.pub.u2froot);
  shadow_config.storage.pub.has_u2froot = true;
}

bool storage_hasMnemonic(void) {
  return shadow_config.storage.pub.has_mnemonic;
}

/* Check whether mnemonic matches storage. The mnemonic must be
 * a null-terminated string.
 */
bool storage_containsMnemonic(const char *mnemonic) {
  if (!storage_hasMnemonic()) return false;
  if (!shadow_config.storage.has_sec) return false;

  // Compare the digests to mitigate side-channel attacks.
  uint8_t digest_stored[SHA256_DIGEST_LENGTH];
  sha256_Raw((const uint8_t *)shadow_config.storage.sec.mnemonic,
             strnlen(shadow_config.storage.sec.mnemonic, MAX_MNEMONIC_LEN),
             digest_stored);

  uint8_t digest_input[SHA256_DIGEST_LENGTH];
  sha256_Raw((const uint8_t *)mnemonic, strnlen(mnemonic, MAX_MNEMONIC_LEN),
             digest_input);

  uint8_t diff = 0;
  for (size_t i = 0; i < sizeof(digest_input); i++) {
    diff |= (digest_stored[i] - digest_input[i]);
  }
  memzero(digest_stored, sizeof(digest_stored));
  memzero(digest_input, sizeof(digest_input));
  return diff == 0;
}

const char *storage_getShadowMnemonic(void) {
  if (!shadow_config.storage.has_sec) return NULL;
  return shadow_config.storage.sec.mnemonic;
}

bool storage_getImported(void) { return shadow_config.storage.pub.imported; }

void storage_setImported(bool val) { shadow_config.storage.pub.imported = val; }

bool storage_hasNode(void) { return shadow_config.storage.pub.has_node; }

Allocation storage_getLocation(void) { return storage_location; }

bool storage_setPolicy(const char *policy_name, bool enabled) {
  return storage_setPolicy_impl(shadow_config.storage.pub.policies, policy_name,
                                enabled);
}

bool storage_setPolicy_impl(PolicyType ps[POLICY_COUNT],
                            const char *policy_name, bool enabled) {
  for (unsigned i = 0; i < POLICY_COUNT; ++i) {
    if (strcmp(policy_name, ps[i].policy_name) == 0) {
      ps[i].has_enabled = true;
      ps[i].enabled = enabled;
      return true;
    }
  }

  return false;
}

void storage_getPolicies(PolicyType *policy_data) {
  for (size_t i = 0; i < POLICY_COUNT; ++i) {
    memcpy(&policy_data[i], &shadow_config.storage.pub.policies[i],
           sizeof(policy_data[i]));
  }
}

bool storage_isPolicyEnabled(const char *policy_name) {
  return storage_isPolicyEnabled_impl(shadow_config.storage.pub.policies,
                                      policy_name);
}

bool storage_isPolicyEnabled_impl(const PolicyType ps[POLICY_COUNT],
                                  const char *policy_name) {
  for (unsigned i = 0; i < POLICY_COUNT; ++i) {
    if (strcmp(policy_name, ps[i].policy_name) == 0) {
      return ps[i].enabled;
    }
  }
  return false;
}

bool storage_noBackup(void) { return shadow_config.storage.pub.no_backup; }

void storage_setNoBackup(void) { shadow_config.storage.pub.no_backup = true; }

uint32_t storage_getAutoLockDelayMs() {
  return shadow_config.storage.pub.has_auto_lock_delay_ms
             ? MAX(shadow_config.storage.pub.auto_lock_delay_ms,
                   STORAGE_MIN_SCREENSAVER_TIMEOUT)
             : STORAGE_DEFAULT_SCREENSAVER_TIMEOUT;
}

void storage_setAutoLockDelayMs(uint32_t auto_lock_delay_ms) {
  shadow_config.storage.pub.has_auto_lock_delay_ms = true;
  shadow_config.storage.pub.auto_lock_delay_ms =
      MAX(auto_lock_delay_ms, STORAGE_MIN_SCREENSAVER_TIMEOUT);
}

#if DEBUG_LINK
const char *storage_getPin(void) {
  return shadow_config.storage.pub.has_pin ? debuglink_pin : NULL;
}

const char *storage_getMnemonic(void) { return debuglink_mnemonic; }

HDNode *storage_getNode(void) { return &debuglink_node; }
#endif
