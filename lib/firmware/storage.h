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
    bool has_node;
    StorageHDNode node;
    bool has_mnemonic;
    char mnemonic[241];
    bool passphrase_protection;
    bool has_pin_failed_attempts;
    uint32_t pin_failed_attempts;
    bool has_pin;
    char pin[10];
    bool has_language;
    char language[17];
    bool has_label;
    char label[33];
    bool imported;
    uint32_t policies_count;
    PolicyType policies[POLICY_COUNT];
} Storage;

typedef struct _ConfigFlash {
    Metadata meta;
    Storage storage;
    Cache cache;
} ConfigFlash;

typedef struct _Cache Cache;

void storage_resetUuid_impl(ConfigFlash *cfg);

void storage_reset_impl(ConfigFlash *cfg);

void storage_commit_impl(ConfigFlash *cfg);

/// \brief Get user private seed.
/// \returns NULL on error, otherwise \returns the private seed.
const uint8_t *storage_getSeed(const ConfigFlash *cfg, bool usePassphrase);

void storage_resetPolicies(Storage *storage);
void storage_resetCache(Cache *cache);

void storage_readMeta(Metadata *meta, const char *addr);
void storage_readPolicy(PolicyType *policy, const char *addr);
void storage_readHDNode(StorageHDNode *node, const char *addr);
void storage_readStorageV1(Storage *storage, const char *addr);
void storage_readCacheV1(Cache *cache, const char *addr);

void storage_writeMeta(char *addr, const Metadata *meta);
void storage_writePolicy(char *addr, const PolicyType *policy);
void storage_writeHDNode(char *addr, const StorageHDNode *node);
void storage_writeStorageV1(char *addr, const Storage *storage);
void storage_writeCacheV1(char *addr, const Cache *cache);

#endif
