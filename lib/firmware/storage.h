/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2022 markrypto
 * Copyright (C) 2018 KeepKey LLC
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

#ifndef STORAGEPB_H
#define STORAGEPB_H

#include "keepkey/board/keepkey_board.h"
#include "keepkey/firmware/authenticator.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/firmware/policy.h"

// The length of the external salt in bytes.
#define EXTERNAL_SALT_SIZE 32

#define V16_ENCSEC_SIZE 512  // for reading old encrypted sec size
#define V17_ENCSEC_SIZE 1024

/* Retired V18 clear-sign identity record. The fixed-size fields remain in the
 * in-memory/storage layout for backward compatibility, but RC18 never trusts,
 * returns, or writes their contents: this public section lacks authenticated
 * integrity against physical flash modification.
 *   pubkey  : 33-byte compressed secp256k1 (matches signed_metadata slots)
 *   alias   : METADATA_ALIAS_MAX_LEN(31)+1, printable [A-Za-z0-9 _-]
 *   icon    : 1bpp mono row-major bitmap, <= CLEARSIGN_ICON_MAX bytes,
 *             icon_len==0 => text-only identity (no logo)
 * Serialized size is fixed (CLEARSIGN_IDENTITY_SERIALIZED_LEN) — appended after
 * encrypted_sec in the V18 storage layout; never reorder existing fields. */
#define CLEARSIGN_ICON_MAX 384
#define CLEARSIGN_IDENTITY_ALIAS_SIZE 32 /* METADATA_ALIAS_MAX_LEN(31) + 1 */
#define PERSISTENT_IDENTITY_COUNT 2
typedef struct _ClearsignIdentity {
  bool present;
  uint8_t key_id;  // the signer slot (1..METADATA_MAX_KEYS-1) this identity
                   // reloads into; the per-tx blob's key_id selects it
  uint8_t pubkey[33];
  char alias[CLEARSIGN_IDENTITY_ALIAS_SIZE];
  uint8_t icon_w;
  uint8_t icon_h;
  uint16_t icon_len;
  uint8_t icon[CLEARSIGN_ICON_MAX];
} ClearsignIdentity;

typedef struct _authBlockType {
  authType authData[AUTHDATA_SIZE];                          // 450
  uint8_t reserved[512 - sizeof(authType) * AUTHDATA_SIZE];  // 62
} authBlockType;

typedef struct _Storage {
  uint32_t version;
  struct Public {
    uint8_t wrapped_storage_key[64];
    uint8_t storage_key_fingerprint[32];
    uint8_t wrapped_wipe_code_key[64];
    uint8_t wipe_code_key_fingerprint[32];
    bool has_pin;
    bool has_wipe_code;
    uint32_t pin_failed_attempts;
    bool has_language;
    char language[16];
    bool has_label;
    char label[48];
    bool imported;
    uint32_t policies_count;
    PolicyType policies[POLICY_COUNT];
    bool has_auto_lock_delay_ms;
    uint32_t auto_lock_delay_ms;
    bool passphrase_protection;
    bool initialized;
    bool has_node;
    bool has_mnemonic;
    bool has_u2froot;
    HDNodeType u2froot;
    uint32_t u2f_counter;
    bool no_backup;
    bool sca_hardened;
    bool v15_16_trans;
    bool pin_kdf_v2;
    bool authdata_initialized;
    bool authdata_encrypted;
    uint8_t random_salt[32];
    uint8_t authdata_fingerprint[32];
    /* V18 legacy clear-sign records. Always scrubbed on read and write. */
    ClearsignIdentity clearsign_identities[PERSISTENT_IDENTITY_COUNT];
  } pub;

  bool has_sec;

  struct Secret {
    HDNodeType node;
    char mnemonic[241];
    char pin[10];
    Cache cache;
    uint8_t authBlock[sizeof(authBlockType)];
  } sec;

  bool has_sec_fingerprint;
  uint8_t sec_fingerprint[32];

  uint32_t encrypted_sec_version;
  uint8_t encrypted_sec[V17_ENCSEC_SIZE];
} Storage;

typedef struct _ConfigFlash {
  Metadata meta;
  Storage storage;
} ConfigFlash;

typedef struct _SessionState {
  bool seedUsesPassphrase;
  bool seedCached;
  uint8_t seed[64];

  bool pinCached;
  uint8_t storageKey[64];

  bool passphraseCached;
  char passphrase[51];
} SessionState;

typedef enum {
  PIN_WRONG,  // PIN incorrect
  PIN_GOOD,   // PIN correct
  PIN_REWRAP  // PIN correct but storage key rewrapped, requires storage update
} pintest_t;

typedef enum {
  PIN_KDF_V15,
  PIN_KDF_V16,
  PIN_KDF_V19,
} pin_kdf_version_t;

/* Gate for the storage-version-19 PIN KDF.
 *
 * 0 = implemented, tested, and NOT reachable from flash. This firmware writes
 * storage version 17, and the flag that records a v19 wrap only round-trips in
 * version 19, so persisting a v19 wrap here would lock the wallet out on the
 * next boot.
 *
 * Do not flip this to 1 on its own. Version 19 is a one-way migration: any
 * device that boots firmware writing it can no longer be downgraded without
 * being wiped, and the wipe is the correct anti-rollback behaviour, not a bug
 * to work around. Enable it only in a release whose bootloader enforces a
 * minimum security epoch that refuses firmware unable to read version 19 --
 * so the downgrade is rejected up front rather than costing a user their
 * wallet. The full gate list is in docs/security/pin-kdf-v19-migration.md. */
#define STORAGE_PIN_KDF_V19 0

/* Single source of truth for KDF selection, so tests cannot drift from
 * production by reimplementing the choice. Both the unlock path and the unit
 * tests must call these rather than naming a PIN_KDF_* constant directly. */
pin_kdf_version_t storage_activePinKdfVersion(bool v15_16_trans,
                                              bool pin_kdf_v2);
pin_kdf_version_t storage_rewrapPinKdfVersion(void);

#define MAX_MNEMONIC_LEN 240

void storage_loadNode(HDNode* dst, const HDNodeType* src);

/// Derive the wrapping key from the user's pin.
void storage_deriveWrappingKey(const char* pin, uint8_t wrapping_key[64],
                               bool sca_hardened,
                               pin_kdf_version_t pin_kdf_version,
                               const uint8_t random_salt[RANDOM_SALT_LEN],
                               const char* message);

/// Wrap the storage key.
void storage_wrapStorageKey(const uint8_t wrapping_key[64],
                            const uint8_t key[64], uint8_t wrapped_key[64]);

/// Attempt to unnwrap the storage key.
void storage_unwrapStorageKey(const uint8_t wrapping_key[64],
                              const uint8_t wrapped_key[64], uint8_t key[64]);

/// Attempt to unnwrap the storage key using aes256.
void storage_unwrapStorageKey256(const uint8_t wrapping_key[64],
                                 const uint8_t wrapped_key[64],
                                 uint8_t key[64]);

/// Get the fingerprint for an unwrapped storage key.
void storage_keyFingerprint(const uint8_t key[64], uint8_t fingerprint[32]);

/// \return: PIN_WRONG     - PIN is incorrect
///          PIN_GOOD      - PIN is correct
///          PIN_REWRAPPED -> PIN is correct, storage key was rewrapped, CALLING
///          FUNCTION SHOULD storage_commit()
pintest_t storage_isPinCorrect_impl(const char* pin, uint8_t wrapped_key[64],
                                    const uint8_t fingerprint[32],
                                    bool* sca_hardened, bool* v15_16_trans,
                                    bool* pin_kdf_v2, uint8_t key[64],
                                    uint8_t random_salt[RANDOM_SALT_LEN]);

pintest_t storage_isWipeCodeCorrect_impl(const char* wipe_code,
                                         uint8_t wrapped_key[64],
                                         const uint8_t fingerprint[32],
                                         uint8_t key[64],
                                         uint8_t random_salt[RANDOM_SALT_LEN]);

/// Migrate data in Storage to/from sec/encrypted_sec.
void storage_secMigrate(SessionState* ss, Storage* storage, bool encrypt);

void storage_resetUuid_impl(ConfigFlash* cfg);

void storage_reset_impl(SessionState* ss, ConfigFlash* cfg);

void storage_setPin_impl(SessionState* ss, Storage* storage, const char* pin);

bool storage_hasPin_impl(const Storage* storage);

void storage_setWipeCode_impl(SessionState* ss, Storage* storage,
                              const char* wipe_code);

bool storage_hasWipeCode_impl(const Storage* storage);

/// \return: PIN_WRONG     - PIN is incorrect
///          PIN_GOOD        - PIN is correct
///          PIN_REWRAP -> PIN is correct, storage key was rewrapped, CALLING
///          FUNCTION SHOULD storage_commit()
pintest_t session_clear_impl(SessionState* ss, Storage* storage,
                             bool clear_pin);

/// \brief Get user private seed.
/// \returns NULL on error, otherwise \returns the private seed.
const uint8_t* storage_getSeed(const ConfigFlash* cfg, bool usePassphrase);

typedef enum {
  SUS_Invalid,
  SUS_Valid,
  SUS_Updated,
  /// Storage was written by bitcoin-only firmware and this build must not load
  /// it. The wallet stays INTACT in flash -- this is a refusal, never a wipe.
  SUS_BitcoinOnlyLocked,
} StorageUpdateStatus;

/// \brief Copy configuration from storage partition in flash memory to shadow
/// memory in RAM
/// \returns true iff successful.
StorageUpdateStatus storage_fromFlash(SessionState* ss, ConfigFlash* dst,
                                      const char* flash);

void storage_upgradePolicies(Storage* storage);
void storage_resetPolicies(Storage* storage);
void storage_resetCache(Cache* cache);

void storage_readV1(SessionState* ss, ConfigFlash* dst, const char* flash,
                    size_t len);
void storage_readV2(SessionState* ss, ConfigFlash* dst, const char* flash,
                    size_t len);
void storage_readV11(ConfigFlash* dst, const char* flash, size_t len);
void storage_readV16(ConfigFlash* dst, const char* flash, size_t len);
void storage_readV17(ConfigFlash* dst, const char* flash, size_t len);
void storage_readV18(ConfigFlash* dst, const char* flash, size_t len);
void storage_readV19(ConfigFlash* dst, const char* flash, size_t len);
void storage_writeV11(char* flash, size_t len, const ConfigFlash* src);
void storage_writeV16(char* flash, size_t len, const ConfigFlash* src);
void storage_writeV17(char* flash, size_t len, const ConfigFlash* src);
void storage_writeV18(char* flash, size_t len, const ConfigFlash* src);
void storage_writeV19(char* flash, size_t len, const ConfigFlash* src);

void storage_readMeta(Metadata* meta, const char* ptr, size_t len);
void storage_readPolicyV1(PolicyType* policy, const char* ptr, size_t len);
void storage_readHDNode(HDNodeType* node, const char* ptr, size_t len);
void storage_readStorageV1(SessionState* ss, Storage* storage, const char* ptr,
                           size_t len);
void storage_readStorageV11(Storage* storage, const char* ptr, size_t len);
void storage_readCacheV1(Cache* cache, const char* ptr, size_t len);

void storage_writeMeta(char* ptr, size_t len, const Metadata* meta);
void storage_writePolicyV1(char* ptr, size_t len, const PolicyType* policy);
void storage_writeHDNode(char* ptr, size_t len, const HDNodeType* node);
void storage_writeStorageV11(char* ptr, size_t len, const Storage* storage);
void storage_writeCacheV1(char* ptr, size_t len, const Cache* cache);

bool storage_setPolicy_impl(PolicyType ps[POLICY_COUNT],
                            const char* policy_name, bool enabled);
bool storage_isPolicyEnabled_impl(const PolicyType ps[POLICY_COUNT],
                                  const char* policy_name);

bool storageHasWipeCode(void);
bool storageChangeWipeCode(uint32_t pin, const uint8_t* ext_salt,
                           uint32_t wipe_code);

#endif
