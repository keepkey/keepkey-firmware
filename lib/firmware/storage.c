/*
 * This file is part of the TREZOR project.
 *
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
#  include <libopencm3/stm32/flash.h>
#endif

#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/keepkey_flash.h"
#include "keepkey/board/memory.h"
#include "keepkey/board/variant.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/passphrase_sm.h"
#include "keepkey/firmware/policy.h"
#include "keepkey/firmware/util.h"
#include "keepkey/rand/rng.h"
#include "keepkey/transport/interface.h"
#include "trezor/crypto/aes/aes.h"
#include "trezor/crypto/bip39.h"
#include "trezor/crypto/curves.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/pbkdf2.h"
#include "trezor/crypto/rand.h"

#include <string.h>
#include <stdint.h>

static bool sessionSeedCached, sessionSeedUsesPassphrase;
static uint8_t CONFIDENTIAL sessionSeed[64];

static bool sessionPinCached;
static char CONFIDENTIAL sessionPin[17];

static bool sessionPassphraseCached;
static char CONFIDENTIAL sessionPassphrase[51];

static Allocation storage_location = FLASH_INVALID;

/* Shadow memory for configuration data in storage partition */
_Static_assert(sizeof(ConfigFlash) <= FLASH_STORAGE_LEN,
               "ConfigFlash struct is too large for storage partition");
static ConfigFlash CONFIDENTIAL shadow_config;

// Temporary storage for marshalling secrets in & out of flash.
static CONFIDENTIAL char flash_temp[1024];

void storage_upgradePolicies(Storage *storage) {
    for (int i = storage->pub.policies_count; i < POLICY_COUNT; ++i) {
        memcpy(&storage->pub.policies[i], &policies[i], sizeof(storage->pub.policies[i]));
    }
    storage->pub.policies_count = POLICY_COUNT;
}

void storage_resetPolicies(Storage *storage) {
    storage->pub.policies_count = 0;
    storage_upgradePolicies(storage);
}

void storage_resetCache(Cache *cache)
{
    memset(cache, 0, sizeof(*cache));
}

static uint8_t read_u8(const char *ptr) {
    return *ptr;
}

static void write_u8(char *ptr, uint8_t val) {
    *ptr = val;
}

static uint32_t read_u32_le(const char *ptr) {
    return ptr[0] | ptr[1] << 8 | ptr[2] << 16 | ((uint32_t)ptr[3]) << 24;
}

static void write_u32_le(char *ptr, uint32_t val) {
    ptr[0] = val & 0xff;
    ptr[1] = (val >> 8) & 0xff;
    ptr[2] = (val >> 16) & 0xff;
    ptr[3] = (val >> 24) & 0xff;
}

static bool read_bool(const char *ptr) {
    return *ptr;
}

static void write_bool(char *ptr, bool val) {
    *ptr = val ? 1 : 0;
}

enum StorageVersion {
    StorageVersion_NONE,
    #define STORAGE_VERSION_ENTRY(VAL) \
        StorageVersion_ ##VAL,
    #include "storage_versions.inc"
};

static enum StorageVersion version_from_int(int version) {
    #define STORAGE_VERSION_LAST(VAL) \
      _Static_assert(VAL == STORAGE_VERSION, \
                     "need to update storage_versions.inc");
    #include "storage_versions.inc"

    switch (version) {
    #define STORAGE_VERSION_ENTRY(VAL) \
        case VAL: return StorageVersion_ ##VAL;
    #include "storage_versions.inc"
    default:
        return StorageVersion_NONE;
    }
}

void storage_readMeta(Metadata *meta, const char *ptr, size_t len) {
    if (len < 16 + STORAGE_UUID_STR_LEN)
        return;
    memcpy(meta->magic, ptr, STORAGE_MAGIC_LEN);
    memcpy(meta->uuid, ptr + 4, STORAGE_UUID_LEN);
    memcpy(meta->uuid_str, ptr + 16, STORAGE_UUID_STR_LEN);
}

void storage_writeMeta(char *ptr, size_t len, const Metadata *meta) {
    if (len < 16 + STORAGE_UUID_STR_LEN)
        return;
    memcpy(ptr, meta->magic, STORAGE_MAGIC_LEN);
    memcpy(ptr + 4, meta->uuid, STORAGE_UUID_LEN);
    memcpy(ptr + 16, meta->uuid_str, STORAGE_UUID_STR_LEN);
}

void storage_readPolicy(PolicyType *policy, const char *ptr, size_t len) {
    if (len < 17)
        return;
    policy->has_policy_name = read_bool(ptr);
    memset(policy->policy_name, 0, sizeof(policy->policy_name));
    memcpy(policy->policy_name, ptr + 1, 15);
    policy->has_enabled = read_bool(ptr + 16);
    policy->enabled = read_bool(ptr + 17);
}

void storage_writePolicy(char *ptr, size_t len, const PolicyType *policy) {
    if (len < 17)
        return;
    write_bool(ptr, policy->has_policy_name);
    memcpy(ptr + 1, policy->policy_name, 15);
    write_bool(ptr + 16, policy->has_enabled);
    write_bool(ptr + 17, policy->enabled);
}

void storage_readHDNode(StorageHDNode *node, const char *ptr, size_t len) {
    if (len < 96 + 33)
        return;
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

void storage_writeHDNode(char *ptr, size_t len, const StorageHDNode *node) {
    if (len < 96 + 33)
        return;
    write_u32_le(ptr, node->depth);
    write_u32_le(ptr + 4, node->fingerprint);
    write_u32_le(ptr + 8, node->child_num);
    write_u32_le(ptr + 12, 32);
    memcpy(ptr + 16, node->chain_code.bytes, 32);
    write_bool(ptr + 48, node->has_private_key);
    ptr[49] = 0; // reserved
    ptr[50] = 0; // reserved
    ptr[51] = 0; // reserved
    write_u32_le(ptr + 52, 32);
    memcpy(ptr + 56, node->private_key.bytes, 32);
    write_bool(ptr + 88, node->has_public_key);
    ptr[89] = 0; // reserved
    ptr[90] = 0; // reserved
    ptr[91] = 0; // reserved
    write_u32_le(ptr + 92, 33);
    memcpy(ptr + 96, node->public_key.bytes, 33);
}

void storage_readStorageV1(Storage *storage, const char *ptr, size_t len) {
    if (len < 464 + 17)
        return;
    storage->version = read_u32_le(ptr);
    storage->sec.has_node = read_bool(ptr + 4);
    storage_readHDNode(&storage->sec.node, ptr + 8, 140);
    storage->sec.has_mnemonic = read_bool(ptr + 140);
    memcpy(storage->sec.mnemonic, ptr + 141, 241);
    storage->sec.passphrase_protection = read_bool(ptr + 383);
    storage->pub.has_pin_failed_attempts = read_bool(ptr + 384);
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
    storage->pub.imported = read_bool(ptr + 456);
    storage->pub.policies_count = 1;
    storage_readPolicy(&storage->pub.policies[0], ptr + 464, 17);
    storage->sec.has_auto_lock_delay_ms = true;
    storage->sec.auto_lock_delay_ms = 60 * 1000U;
}

void storage_writeStorageV1(char *ptr, size_t len, const Storage *storage) {
    if (len < 464 + 17)
        return;
    write_u32_le(ptr, storage->version);
    write_bool(ptr + 4, storage->sec.has_node);
    ptr[5] = 0; // reserved
    ptr[6] = 0; // reserved
    ptr[7] = 0; // reserved
    storage_writeHDNode(ptr + 8, 140, &storage->sec.node);
    ptr[137] = 0; // reserved
    ptr[138] = 0; // reserved
    ptr[139] = 0; // reserved
    write_bool(ptr + 140, storage->sec.has_mnemonic);
    memcpy(ptr + 141, storage->sec.mnemonic, 241);
    write_bool(ptr + 382, true); // formerly has_passphrase_protection
    write_bool(ptr + 383, storage->sec.passphrase_protection);
    write_bool(ptr + 384, storage->pub.has_pin_failed_attempts);
    ptr[385] = 0; // reserved
    ptr[386] = 0; // reserved
    ptr[387] = 0; // reserved
    write_u32_le(ptr + 388, storage->pub.pin_failed_attempts);
    write_bool(ptr + 392, storage->pub.has_pin);
    memcpy(ptr + 393, storage->sec.pin, 10);
    write_bool(ptr + 403, storage->pub.has_language);
    memcpy(ptr + 404, storage->pub.language, 17);
    write_bool(ptr + 421, storage->pub.has_label);
    memcpy(ptr + 422, storage->pub.label, 33);
    write_bool(ptr + 455, true); // formerly has_imported
    write_bool(ptr + 456, storage->pub.imported);
    ptr[457] = 0; // reserved
    ptr[458] = 0; // reserved
    ptr[459] = 0; // reserved
    write_u32_le(ptr + 460, 1);
    storage_writePolicy(ptr + 464, 17, &storage->pub.policies[0]);
}

void storage_writeStorageV3(char *ptr, size_t len, const Storage *storage) {
    if (len < 800)
        return;
    storage_writeStorageV1(ptr, + 464 + 17, storage);
    storage_writePolicy(ptr + 464 + 18, 17, &storage->pub.policies[1]);
    // reserved bytes for policies 2:8
    write_bool(ptr + 626, storage->sec.has_auto_lock_delay_ms);
    write_u32_le(ptr + 627, storage->sec.auto_lock_delay_ms);
}

void storage_readStorageV3(Storage *storage, const char *ptr, size_t len) {
    if (len < 800)
        return;
    storage_readStorageV1(storage, ptr, 464 + 18);
    storage_readPolicy(&storage->pub.policies[1], ptr + 464 + 18, 18);
    // reserved bytes for policies 2:8
    storage->sec.has_auto_lock_delay_ms = read_bool(ptr + 626);
    storage->sec.auto_lock_delay_ms = read_u32_le(ptr + 627);
}

void storage_readCacheV1(Cache *cache, const char *ptr, size_t len) {
    if (len < 65 + 10)
        return;
    cache->root_seed_cache_status = read_u8(ptr);
    memcpy(cache->root_seed_cache, ptr + 1, 64);
    memcpy(cache->root_ecdsa_curve_type, ptr + 65, 10);
}

void storage_writeCacheV1(char *ptr, size_t len, const Cache *cache) {
    if (len < 65 + 10)
        return;
    write_u8(ptr, cache->root_seed_cache_status);
    memcpy(ptr + 1, cache->root_seed_cache, 64);
    memcpy(ptr + 65, cache->root_ecdsa_curve_type, 10);
}

_Static_assert(offsetof(Cache, root_seed_cache) == 1, "rsc");
_Static_assert(offsetof(Cache, root_ecdsa_curve_type) == 65, "rect");
_Static_assert(sizeof(((Cache*)0)->root_ecdsa_curve_type) == 10, "rect");

void storage_readV1(ConfigFlash *dst, const char *flash, size_t len) {
    if (len < 44 + 528)
        return;
    storage_readMeta(&dst->meta, flash, 44);
    storage_readStorageV1(&dst->storage, flash + 44, 481);
    storage_resetPolicies(&dst->storage);
    storage_resetCache(&dst->cache);
}

void storage_readV2(ConfigFlash *dst, const char *flash, size_t len) {
    if (len < 528 + 75)
        return;
    storage_readMeta(&dst->meta, flash, 44);
    storage_readStorageV1(&dst->storage, flash + 44, 481);
    storage_readCacheV1(&dst->cache, flash + 528, 75);
}

void storage_readV3(ConfigFlash *dst, const char *flash, size_t len) {
    if (len < 672 + 75)
        return;
    storage_readMeta(&dst->meta, flash, 44);
    storage_readStorageV3(&dst->storage, flash + 44, 800);
    storage_readCacheV1(&dst->cache, flash + 800, 75);
}

void storage_writeV3(char *flash, size_t len, const ConfigFlash *src) {
    if (len < 672 + 75)
        return;
    storage_writeMeta(flash, 44, &src->meta);
    storage_writeStorageV3(flash + 44, 800, &src->storage);
    storage_writeCacheV1(flash + 800, 75, &src->cache);
}

StorageUpdateStatus storage_fromFlash(ConfigFlash *dst, const char *flash)
{
    // Load config values from active config node.
    enum StorageVersion version =
        version_from_int(read_u32_le(flash + 44));

    // Don't restore storage in MFR firmware
    if (variant_isMFR()) {
        version = StorageVersion_NONE;
    }

    switch (version)
    {
        case StorageVersion_1:
            storage_readV1(dst, flash, STORAGE_SECTOR_LEN);
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
            storage_readV2(dst, flash, STORAGE_SECTOR_LEN);
            dst->storage.version = STORAGE_VERSION;

            /* We have to do this for users with bootloaders <= v1.0.2. This
            scenario would only happen after a firmware install from the same
            storage version */
            if (dst->storage.pub.policies_count == 0xFFFFFFFF)
            {
                storage_resetPolicies(&dst->storage);
                storage_resetCache(&dst->cache);
                return SUS_Updated;
            }

            storage_upgradePolicies(&dst->storage);

            return dst->storage.version == version
                ? SUS_Valid
                : SUS_Updated;

        case StorageVersion_11:
            storage_readV3(dst, flash, STORAGE_SECTOR_LEN);
            return SUS_Valid;

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
static void wear_leveling_shift(void)
{
    switch(storage_location)
    {
        case FLASH_STORAGE1:
        {
            storage_location = FLASH_STORAGE2;
            break;
        }

        case FLASH_STORAGE2:
        {
            storage_location = FLASH_STORAGE3;
            break;
        }

        /* wraps around */
        case FLASH_STORAGE3:
        {
            storage_location = FLASH_STORAGE1;
            break;
        }

        default:
        {
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
static void storage_setRootSeedCache(ConfigFlash *cfg, const uint8_t *seed, const char* curve)
{
    // Don't cache when passphrase protection is enabled.
    if (cfg->storage.sec.passphrase_protection && strlen(sessionPassphrase))
        return;

    memset(&cfg->cache, 0, sizeof(((ConfigFlash *)NULL)->cache));

    memcpy(&cfg->cache.root_seed_cache, seed,
           sizeof(((ConfigFlash *)NULL)->cache.root_seed_cache));

    strlcpy(cfg->cache.root_ecdsa_curve_type, curve,
            sizeof(cfg->cache.root_ecdsa_curve_type));

    cfg->cache.root_seed_cache_status = CACHE_EXISTS;
    storage_commit();
}

/// \brief Get root session seed cache from storage.
///
/// \param cfg[in]   The active storage sector.
/// \param curve[in] ECDSA curve name being used.
/// \param seed[out] The root seed value.
/// \returns true on success.
static bool storage_getRootSeedCache(ConfigFlash *cfg, const char *curve,
                                     bool usePassphrase, uint8_t *seed)
{
    if (cfg->cache.root_seed_cache_status != CACHE_EXISTS)
        return false;

    if (usePassphrase && cfg->storage.sec.passphrase_protection &&
        strlen(sessionPassphrase)) {
        return false;
    }

    if (strcmp(cfg->cache.root_ecdsa_curve_type, curve) != 0) {
        return false;
    }

    memset(seed, 0, sizeof(sessionSeed));
    memcpy(seed, &cfg->cache.root_seed_cache,
           sizeof(cfg->cache.root_seed_cache));
    _Static_assert(sizeof(sessionSeed) == sizeof(cfg->cache.root_seed_cache),
                   "size mismatch");
    return true;
}

static bool storage_isUninitialized(const char *flash) {
    return memcmp(((const Metadata *)flash)->magic, STORAGE_MAGIC_STR,
                  STORAGE_MAGIC_LEN) != 0;
}

void storage_init(void)
{
#ifndef EMULATOR
    if (strcmp("MFR", variant_getName()) == 0)
    {
        // Storage should have been wiped due to the MANUFACTURER firmware
        // having a STORAGE_VERSION of 0, but to be absolutely safe and
        // guarante that secrets cannot leave the device via FlashHash/FlashDump,
        // we wipe them here.

        ConfigFlash *stor_1 = (ConfigFlash*)flash_write_helper(FLASH_STORAGE1);
        if (memcmp((void *)stor_1->meta.magic, STORAGE_MAGIC_STR, STORAGE_MAGIC_LEN) == 0)
            flash_erase_word(FLASH_STORAGE1);

        ConfigFlash *stor_2 = (ConfigFlash*)flash_write_helper(FLASH_STORAGE2);
        if (memcmp((void *)stor_2->meta.magic, STORAGE_MAGIC_STR, STORAGE_MAGIC_LEN) == 0)
            flash_erase_word(FLASH_STORAGE2);

        ConfigFlash *stor_3 = (ConfigFlash*)flash_write_helper(FLASH_STORAGE3);
        if (memcmp((void *)stor_3->meta.magic, STORAGE_MAGIC_STR, STORAGE_MAGIC_LEN) == 0)
            flash_erase_word(FLASH_STORAGE3);
    }
#endif

    // Find storage sector with valid data and set storage_location variable.
    if (!find_active_storage(&storage_location)) {
        // Otherwise initialize it to the default sector.
        storage_location = STORAGE_SECT_DEFAULT;
    }
    const char *flash = (const char *)flash_write_helper(storage_location);

    // Reset shadow configuration in RAM
    storage_reset_impl(&shadow_config);

    // If the storage partition is uninitialized
    if (storage_isUninitialized(flash)) {
        // ... then keep the storage area cleared.
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
    switch (storage_fromFlash(&shadow_config, flash)) {
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
}

void storage_resetUuid(void)
{
    storage_resetUuid_impl(&shadow_config);
}

void storage_resetUuid_impl(ConfigFlash *cfg)
{
    // set random uuid
    random_buffer(cfg->meta.uuid, sizeof(cfg->meta.uuid));
    data2hex(cfg->meta.uuid, sizeof(cfg->meta.uuid), cfg->meta.uuid_str);
}

void storage_reset(void)
{
    storage_reset_impl(&shadow_config);
}

void storage_reset_impl(ConfigFlash *cfg)
{
    memset(&cfg->storage, 0, sizeof(cfg->storage));
    memset(&cfg->cache, 0, sizeof(cfg->cache));

    storage_resetPolicies(&cfg->storage);

    cfg->storage.version = STORAGE_VERSION;
    session_clear(true); // clear PIN as well
}

void session_clear(bool clear_pin)
{
    sessionSeedCached = false;
    memset(&sessionSeed, 0, sizeof(sessionSeed));

    sessionPassphraseCached = false;
    memset(&sessionPassphrase, 0, sizeof(sessionPassphrase));

    if (clear_pin) {
        memzero(sessionPin, sizeof(sessionPin));
        sessionPinCached = false;
    }
}

void storage_commit(void) {
    storage_commit_impl(&shadow_config);
}

void storage_commit_impl(ConfigFlash *cfg)
{
    memzero(flash_temp, sizeof(flash_temp));
    storage_writeV3(flash_temp, sizeof(flash_temp), cfg);

    memcpy(cfg, STORAGE_MAGIC_STR, STORAGE_MAGIC_LEN);

    uint32_t retries = 0;
    for (retries = 0; retries < STORAGE_RETRIES; retries++) {
        /* Capture CRC for verification at restore */
        uint32_t shadow_ram_crc32 =
            calc_crc32(flash_temp, sizeof(flash_temp) / sizeof(uint32_t));

        if (shadow_ram_crc32 == 0) {
            continue; /* Retry */
        }

#ifndef EMULATOR
        /* Make sure flash is in good state before proceeding */
        if (!flash_chk_status()) {
            flash_clear_status_flags();
            continue; /* Retry */
        }
#endif

        /* Make sure storage sector is valid before proceeding */
        if(storage_location < FLASH_STORAGE1 || storage_location > FLASH_STORAGE3)
        {
            /* Let it exhaust the retries and error out */
            continue;
        }

#ifndef EMULATOR
        flash_unlock();
#endif
        flash_erase_word(storage_location);
        wear_leveling_shift();
        flash_erase_word(storage_location);

        /* Write storage data first before writing storage magic  */
        if (!flash_write_word(storage_location, STORAGE_MAGIC_LEN,
                              sizeof(flash_temp) - STORAGE_MAGIC_LEN,
                              (uint8_t *)flash_temp + STORAGE_MAGIC_LEN)) {
            continue; // Retry
        }

        if (!flash_write_word(storage_location, 0, STORAGE_MAGIC_LEN,
                              (uint8_t *)flash_temp)) {
            continue; // Retry
        }

        /* Flash write completed successfully.  Verify CRC */
        uint32_t shadow_flash_crc32 =
            calc_crc32((const void*)flash_write_helper(storage_location),
                       sizeof(flash_temp) / sizeof(uint32_t));

        if (shadow_flash_crc32 == shadow_ram_crc32) {
            /* Commit successful, break to exit */
            break;
        }
    }

#ifndef EMULATOR
    flash_lock();
#endif

    memzero(flash_temp, sizeof(flash_temp));

    if(retries >= STORAGE_RETRIES) {
        layout_warning_static("Error Detected.  Reboot Device!");
        shutdown();
    }
}

void storage_dumpNode(HDNodeType *dst, const StorageHDNode *src) {
#if DEBUG_LINK
    dst->depth = src->depth;
    dst->fingerprint = src->fingerprint;
    dst->child_num = src->child_num;

    dst->chain_code.size = src->chain_code.size;
    memcpy(dst->chain_code.bytes, src->chain_code.bytes,
           sizeof(src->chain_code.bytes));
    _Static_assert(sizeof(dst->chain_code.bytes) ==
                   sizeof(src->chain_code.bytes), "chain_code type mismatch");

    dst->has_private_key = src->has_private_key;
    if (src->has_private_key) {
        dst->private_key.size = src->private_key.size;
        memcpy(dst->private_key.bytes, src->private_key.bytes,
               sizeof(src->private_key.bytes));
        _Static_assert(sizeof(dst->private_key.bytes) ==
                       sizeof(src->private_key.bytes), "private_key type mismatch");
    }

    dst->has_public_key = src->has_public_key;
    if (src->has_public_key) {
        dst->public_key.size = src->public_key.size;
        memcpy(dst->public_key.bytes, src->public_key.bytes,
               sizeof(src->public_key.bytes));
        _Static_assert(sizeof(dst->public_key.bytes) ==
                       sizeof(src->public_key.bytes), "public_key type mismatch");
    }
#else
    (void)dst;
    (void)src;
#endif
}

void storage_loadDevice(LoadDevice *msg)
{
    storage_reset_impl(&shadow_config);

    shadow_config.storage.pub.imported = true;

    if(msg->has_pin > 0)
    {
        storage_setPin(msg->pin);
    }

    shadow_config.storage.sec.passphrase_protection =
        msg->has_passphrase_protection && msg->passphrase_protection;

    if(msg->has_node)
    {
        shadow_config.storage.sec.has_node = true;
        shadow_config.storage.sec.has_mnemonic = false;
        memcpy(&shadow_config.storage.sec.node, &(msg->node), sizeof(HDNodeType));

        sessionSeedCached = false;
        memset(&sessionSeed, 0, sizeof(sessionSeed));
    }
    else if(msg->has_mnemonic)
    {
        shadow_config.storage.sec.has_mnemonic = true;
        shadow_config.storage.sec.has_node = false;
        strlcpy(shadow_config.storage.sec.mnemonic, msg->mnemonic,
                sizeof(shadow_config.storage.sec.mnemonic));

        sessionSeedCached = false;
        memset(&sessionSeed, 0, sizeof(sessionSeed));
    }

    if(msg->has_language)
    {
        storage_setLanguage(msg->language);
    }

    if(msg->has_label)
    {
        storage_setLabel(msg->label);
    }
}


void storage_setLabel(const char *label)
{
    if(!label) { return; }

    shadow_config.storage.pub.has_label = true;
    memset(shadow_config.storage.pub.label, 0, sizeof(shadow_config.storage.pub.label));
    strlcpy(shadow_config.storage.pub.label, label,
            sizeof(shadow_config.storage.pub.label));
}

const char *storage_getLabel(void)
{
    if (!shadow_config.storage.pub.has_label) {
        return NULL;
    }

    return shadow_config.storage.pub.label;
}

void storage_setLanguage(const char *lang)
{
    if(!lang) { return; }

    // sanity check
    if(strcmp(lang, "english") == 0)
    {
        shadow_config.storage.pub.has_language = true;
        memset(shadow_config.storage.pub.language, 0,
               sizeof(shadow_config.storage.pub.language));
        strlcpy(shadow_config.storage.pub.language, lang,
                sizeof(shadow_config.storage.pub.language));
    }
}

const char *storage_getLanguage(void)
{
    if (!shadow_config.storage.pub.has_language) {
        return NULL;
    }

    return shadow_config.storage.pub.language;
}

bool storage_isPinCorrect(const char *pin)
{
    uint8_t pinIdx = 0;
    uint32_t sumXors = UINT32_MAX;
    uint8_t result1 = 0;
    uint8_t result2 = 0;
    uint8_t result3 = 0;
    uint8_t result = 0;

    // Beware when changing.
    // This is carefully coded to take a constant amount of time.

    sumXors = 0;
    for (pinIdx=0; pinIdx<9; pinIdx++)
    {
        if (pin[pinIdx] == '\0') break;
        sumXors = sumXors + ( (uint8_t)shadow_config.storage.sec.pin[pinIdx] ^ (uint8_t)pin[pinIdx] );
    }

    result1 = ('\0' == shadow_config.storage.sec.pin[pinIdx]);
    result2 = (1 <= pinIdx);
    result3 = (0 == sumXors);
    result = result1 + result2 + result3;

    return (result == 3);
}

bool storage_hasPin(void)
{
    return shadow_config.storage.pub.has_pin && strlen(shadow_config.storage.sec.pin) > 0;
}

void storage_setPin(const char *pin)
{
    if(pin && strlen(pin) > 0)
    {
        shadow_config.storage.pub.has_pin = true;
        strlcpy(shadow_config.storage.sec.pin, pin, sizeof(shadow_config.storage.sec.pin));
        session_cachePin(pin);
    }
    else
    {
        shadow_config.storage.pub.has_pin = false;
        memset(shadow_config.storage.sec.pin, 0, sizeof(shadow_config.storage.sec.pin));
        memzero(sessionPin, sizeof(sessionPin));
        sessionPinCached = false;
    }
}

void session_cachePin(const char *pin)
{
    memzero(sessionPin, sizeof(sessionPin));
    strlcpy(sessionPin, pin, sizeof(sessionPin));
    sessionPinCached = true;
}

bool session_isPinCached(void)
{
    return sessionPinCached && strcmp(sessionPin, shadow_config.storage.sec.pin) == 0;
}

void storage_resetPinFails(void)
{
    shadow_config.storage.pub.has_pin_failed_attempts = false;
    shadow_config.storage.pub.pin_failed_attempts = 0;

    storage_commit_impl(&shadow_config);
}

void storage_increasePinFails(void)
{
    shadow_config.storage.pub.has_pin_failed_attempts = true;
    shadow_config.storage.pub.pin_failed_attempts++;

    storage_commit_impl(&shadow_config);
}

uint32_t storage_getPinFails(void)
{
    return shadow_config.storage.pub.has_pin_failed_attempts ?
           shadow_config.storage.pub.pin_failed_attempts : 0;
}

/// \brief Calls animation callback.
/// \param iter Current iteration.
/// \param total Total iterations.
static void get_root_node_callback(uint32_t iter, uint32_t total)
{
    (void)iter;
    (void)total;
    animating_progress_handler();
}

const uint8_t *storage_getSeed(const ConfigFlash *cfg, bool usePassphrase)
{
    // root node is properly cached
    if (usePassphrase == sessionSeedUsesPassphrase
        && sessionSeedCached) {
        return sessionSeed;
    }

    // if storage has mnemonic, convert it to node and use it
    if (cfg->storage.sec.has_mnemonic) {
        if (usePassphrase && !passphrase_protect()) {
            return NULL;
        }

        layout_loading();
        mnemonic_to_seed(cfg->storage.sec.mnemonic,
                         usePassphrase ? sessionPassphrase : "",
                         sessionSeed, get_root_node_callback); // BIP-0039
        sessionSeedCached = true;
        sessionSeedUsesPassphrase = usePassphrase;
        return sessionSeed;
    }

    return NULL;
}

bool storage_getRootNode(const char *curve, bool usePassphrase, HDNode *node) {
    // if storage has node, decrypt and use it
    if (shadow_config.storage.sec.has_node && strcmp(curve, SECP256K1_NAME) == 0) {
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

        if (shadow_config.storage.sec.passphrase_protection &&
            sessionPassphraseCached &&
            strlen(sessionPassphrase) > 0) {
            // decrypt hd node
            static uint8_t CONFIDENTIAL secret[64];
            PBKDF2_HMAC_SHA512_CTX pctx;
            pbkdf2_hmac_sha512_Init(&pctx, (const uint8_t *)sessionPassphrase, strlen(sessionPassphrase), (const uint8_t *)"TREZORHD", 8);
            for (int i = 0; i < 8; i++) {
                pbkdf2_hmac_sha512_Update(&pctx, BIP39_PBKDF2_ROUNDS / 8);
                get_root_node_callback((i + 1) * BIP39_PBKDF2_ROUNDS / 8, BIP39_PBKDF2_ROUNDS);
            }
            pbkdf2_hmac_sha512_Final(&pctx, secret);
            aes_decrypt_ctx ctx;
            aes_decrypt_key256(secret, &ctx);
            aes_cbc_decrypt(node->chain_code, node->chain_code, 32, secret + 32, &ctx);
            aes_cbc_decrypt(node->private_key, node->private_key, 32, secret + 32, &ctx);
            memzero(&ctx, sizeof(ctx));
            memzero(secret, sizeof(secret));
        }

        return true;
    }

    /* get node from mnemonic */
    if (shadow_config.storage.sec.has_mnemonic) {
        if (!passphrase_protect()) {
            /* passphrased failed. Bailing */
            return false;
        }

        if(!sessionSeedCached) {
            sessionSeedCached = storage_getRootSeedCache(&shadow_config, curve, usePassphrase, sessionSeed);

            if(!sessionSeedCached) {
                /* calculate session seed and update the global sessionSeed/sessionSeedCached variables */
                storage_getSeed(&shadow_config, usePassphrase);

                if (!sessionSeedCached) {
                    return false;
                }

                storage_setRootSeedCache(&shadow_config, sessionSeed, curve);
            }
        }

        if (hdnode_from_seed(sessionSeed, 64, curve, node) == 1) {
            return true;
        }
    }

    return false;
}

bool storage_isInitialized(void)
{
    return shadow_config.storage.sec.has_node || shadow_config.storage.sec.has_mnemonic;
}

const char *storage_getUuidStr(void)
{
    return shadow_config.meta.uuid_str;
}

bool storage_getPassphraseProtected(void)
{
    return shadow_config.storage.sec.passphrase_protection;
}

void storage_setPassphraseProtected(bool passphrase)
{
    shadow_config.storage.sec.passphrase_protection = passphrase;
}

void session_cachePassphrase(const char *passphrase)
{
    strlcpy(sessionPassphrase, passphrase, sizeof(sessionPassphrase));
    sessionPassphraseCached = true;
}

bool session_isPassphraseCached(void)
{
    return sessionPassphraseCached;
}

void storage_setMnemonicFromWords(const char (*words)[12],
                                  unsigned int word_count)
{
    strlcpy(shadow_config.storage.sec.mnemonic, words[0],
            sizeof(shadow_config.storage.sec.mnemonic));

    for(uint32_t i = 1; i < word_count; i++)
    {
        strlcat(shadow_config.storage.sec.mnemonic, " ",
                sizeof(shadow_config.storage.sec.mnemonic));
        strlcat(shadow_config.storage.sec.mnemonic, words[i],
                sizeof(shadow_config.storage.sec.mnemonic));
    }

    shadow_config.storage.sec.has_mnemonic = true;
}

void storage_setMnemonic(const char *m)
{
    memset(shadow_config.storage.sec.mnemonic, 0,
           sizeof(shadow_config.storage.sec.mnemonic));
    strlcpy(shadow_config.storage.sec.mnemonic, m,
            sizeof(shadow_config.storage.sec.mnemonic));
    shadow_config.storage.sec.has_mnemonic = true;
}

bool storage_hasMnemonic(void)
{
    return shadow_config.storage.sec.has_mnemonic;
}

const char *storage_getShadowMnemonic(void)
{
    return shadow_config.storage.sec.mnemonic;
}

bool storage_getImported(void)
{
    return shadow_config.storage.pub.imported;
}

bool storage_hasNode(void)
{
    return shadow_config.storage.sec.has_node;
}

Allocation storage_getLocation(void)
{
    return storage_location;
}

bool storage_setPolicy(const PolicyType *policy)
{
    for (unsigned i = 0; i < POLICY_COUNT; ++i)
    {
        if(strcmp(policy->policy_name, shadow_config.storage.pub.policies[i].policy_name) == 0)
        {
            memcpy(&shadow_config.storage.pub.policies[i], policy, sizeof(PolicyType));
            return true;
        }
    }

    return false;
}

void storage_getPolicies(PolicyType *policy_data)
{
    for (size_t i = 0; i < POLICY_COUNT; ++i) {
        memcpy(&policy_data[i], &shadow_config.storage.pub.policies[i], sizeof(policy_data[i]));
    }
}

bool storage_isPolicyEnabled(char *policy_name)
{
    for (unsigned i = 0; i < POLICY_COUNT; ++i)
    {
        if(strcmp(policy_name, shadow_config.storage.pub.policies[i].policy_name) == 0)
        {
            return shadow_config.storage.pub.policies[i].enabled;
        }
    }
    return false;
}

uint32_t storage_getAutoLockDelayMs()
{
	const uint32_t default_delay_ms = 10 * 60 * 1000U; // 10 minutes
	return shadow_config.storage.sec.has_auto_lock_delay_ms ? shadow_config.storage.sec.auto_lock_delay_ms : default_delay_ms;
}

void storage_setAutoLockDelayMs(uint32_t auto_lock_delay_ms)
{
	const uint32_t min_delay_ms = 10 * 1000U; // 10 seconds
	auto_lock_delay_ms = auto_lock_delay_ms > min_delay_ms ? auto_lock_delay_ms : min_delay_ms;
	shadow_config.storage.sec.has_auto_lock_delay_ms = true;
	shadow_config.storage.sec.auto_lock_delay_ms = auto_lock_delay_ms;
}

#if DEBUG_LINK
const char *storage_getPin(void)
{
    return shadow_config.storage.pub.has_pin ? shadow_config.storage.sec.pin : NULL;
}

const char *storage_getMnemonic(void)
{
    return shadow_config.storage.sec.mnemonic;
}

StorageHDNode *storage_getNode(void)
{
    return &shadow_config.storage.sec.node;
}
#endif
