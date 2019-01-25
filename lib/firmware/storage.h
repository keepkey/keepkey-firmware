/*
 * This file is part of the KeepKey project.
 *
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
#include "keepkey/firmware/policy.h"

typedef struct _Storage {
    uint32_t version;
    struct Public {
        uint8_t wrapped_storage_key[64];
        uint8_t storage_key_fingerprint[32];
        bool has_pin;
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
    } pub;

    bool has_sec;
    struct Secret {
        HDNodeType node;
        char mnemonic[241];
        char pin[10];
        Cache cache;
    } sec;

    bool has_sec_fingerprint;
    uint8_t sec_fingerprint[32];

    uint32_t encrypted_sec_version;
    uint8_t encrypted_sec[512];
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

void storage_loadNode(HDNode *dst, const HDNodeType *src);

/// Derive the wrapping key from the user's pin.
void storage_deriveWrappingKey(const char *pin, uint8_t wrapping_key[64]);

/// Wrap the storage key.
void storage_wrapStorageKey(const uint8_t wrapping_key[64], const uint8_t key[64], uint8_t wrapped_key[64]);

/// Attempt to unnwrap the storage key.
void storage_unwrapStorageKey(const uint8_t wrapping_key[64], const uint8_t wrapped_key[64], uint8_t key[64]);

/// Get the fingerprint for an unwrapped storage key.
void storage_keyFingerprint(const uint8_t key[64], uint8_t fingerprint[32]);

/// Check whether a pin is correct.
/// \returns true iff the pin was correct.
bool storage_isPinCorrect_impl(const char *pin, const uint8_t wrapped_key[64], const uint8_t fingerprint[32], uint8_t key[64]);

/// Migrate data in Storage to/from sec/encrypted_sec.
void storage_secMigrate(SessionState *state, Storage *storage, bool encrypt);

void storage_resetUuid_impl(ConfigFlash *cfg);

void storage_reset_impl(SessionState *session, ConfigFlash *cfg);

void storage_setPin_impl(SessionState *session, Storage *storage, const char *pin);

bool storage_hasPin_impl(const Storage *storage);

void session_cachePin_impl(SessionState *session, Storage *storage, const char *pin);

void session_clear_impl(SessionState *session, Storage *storage, bool clear_pin);

/// \brief Get user private seed.
/// \returns NULL on error, otherwise \returns the private seed.
const uint8_t *storage_getSeed(const ConfigFlash *cfg, bool usePassphrase);

typedef enum {
   SUS_Invalid,
   SUS_Valid,
   SUS_Updated,
} StorageUpdateStatus;

/// \brief Copy configuration from storage partition in flash memory to shadow
/// memory in RAM
/// \returns true iff successful.
StorageUpdateStatus storage_fromFlash(SessionState *ss, ConfigFlash *dst, const char *flash);

void storage_upgradePolicies(Storage *storage);
void storage_resetPolicies(Storage *storage);
void storage_resetCache(Cache *cache);

void storage_readV1(SessionState *session, ConfigFlash *dst, const char *ptr, size_t len);
void storage_readV2(SessionState *session, ConfigFlash *dst, const char *ptr, size_t len);
void storage_readV11(ConfigFlash *dst, const char *ptr, size_t len);
void storage_writeV11(char *ptr, size_t len, const ConfigFlash *src);

void storage_readMeta(Metadata *meta, const char *ptr, size_t len);
void storage_readPolicyV1(PolicyType *policy, const char *ptr, size_t len);
void storage_readHDNode(HDNodeType *node, const char *ptr, size_t len);
void storage_readStorageV1(SessionState *session, Storage *storage, const char *ptr, size_t len);
void storage_readStorageV11(Storage *storage, const char *ptr, size_t len);
void storage_readCacheV1(Cache *cache, const char *ptr, size_t len);

void storage_writeMeta(char *ptr, size_t len, const Metadata *meta);
void storage_writePolicyV1(char *ptr, size_t len, const PolicyType *policy);
void storage_writeHDNode(char *ptr, size_t len, const HDNodeType *node);
void storage_writeStorageV11(char *ptr, size_t len, const Storage *storage);
void storage_writeCacheV1(char *ptr, size_t len, const Cache *cache);

bool storage_setPolicy_impl(PolicyType policies[POLICY_COUNT], const char *policy_name, bool enabled);
bool storage_isPolicyEnabled_impl(const PolicyType policies[POLICY_COUNT], const char *policy_name);

#endif
