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

/* === Includes ============================================================ */

#ifndef STORAGEPB_H
#define STORAGEPB_H

#include "keepkey/board/keepkey_board.h"
#include "keepkey/firmware/policy.h"

typedef struct _StorageHDNode {
    uint32_t depth;
    uint32_t fingerprint;
    uint32_t child_num;
    struct {
        uint32_t size;
        uint8_t bytes[32];
    } chain_code;
    bool has_private_key;
    struct {
        uint32_t size;
        uint8_t bytes[32];
    } private_key;
    bool has_public_key;
    struct {
        uint32_t size;
        uint8_t bytes[33];
    } public_key;
} StorageHDNode;

typedef struct _Storage {
    uint32_t version;
    struct Public {
        bool has_pin;
        bool has_pin_failed_attempts;
        uint32_t pin_failed_attempts;
        bool has_language;
        char language[17];
        bool has_label;
        char label[33];
        bool imported;
        uint32_t policies_count;
        PolicyType policies[POLICY_COUNT];
    } pub;

    struct Secret {
        char magic[7];
        bool has_node;
        bool has_mnemonic;
        bool passphrase_protection;
        StorageHDNode node;
        char mnemonic[241];
        char pin[10];
        bool has_auto_lock_delay_ms;
        uint32_t auto_lock_delay_ms;
    } sec;
} Storage;

typedef struct _ConfigFlash {
    Metadata meta;
    Storage storage;
    Cache cache;
} ConfigFlash;

typedef struct _Cache Cache;

/// Derive the wrapping key from the user's pin.
void storage_deriveWrappingKey(const char *pin, uint8_t wrapping_key[64]);

/// Wrap the storage key.
void storage_wrapStorageKey(const uint8_t wrapping_key[64], const uint8_t key[64], uint8_t wrapped_key[64]);

/// Attempt to unnwrap the storage key.
/// \returns true iff unwrapping was successful.
bool storage_unwrapStorageKey(const uint8_t wrapping_key[64], const uint8_t wrapped_key[64], uint8_t key[64]);

void storage_resetUuid_impl(ConfigFlash *cfg);

void storage_reset_impl(ConfigFlash *cfg);

void storage_commit_impl(ConfigFlash *cfg);

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
StorageUpdateStatus storage_fromFlash(ConfigFlash *dst, const char *flash);

void storage_upgradePolicies(Storage *storage);
void storage_resetPolicies(Storage *storage);
void storage_resetCache(Cache *cache);

void storage_readV1(ConfigFlash *dst, const char *ptr, size_t len);
void storage_readV2(ConfigFlash *dst, const char *ptr, size_t len);
void storage_readV3(ConfigFlash *dst, const char *ptr, size_t len);
void storage_writeV3(char *ptr, size_t len, const ConfigFlash *src);

void storage_readMeta(Metadata *meta, const char *ptr, size_t len);
void storage_readPolicy(PolicyType *policy, const char *ptr, size_t len);
void storage_readHDNode(StorageHDNode *node, const char *ptr, size_t len);
void storage_readStorageV1(Storage *storage, const char *ptr, size_t len);
void storage_readStorageV3(Storage *storage, const char *ptr, size_t len);
void storage_readCacheV1(Cache *cache, const char *ptr, size_t len);

void storage_writeMeta(char *ptr, size_t len, const Metadata *meta);
void storage_writePolicy(char *ptr, size_t len, const PolicyType *policy);
void storage_writeHDNode(char *ptr, size_t len, const StorageHDNode *node);
void storage_writeStorageV1(char *ptr, size_t len, const Storage *storage);
void storage_writeStorageV3(char *ptr, size_t len, const Storage *storage);
void storage_writeCacheV1(char *ptr, size_t len, const Cache *cache);


#endif
