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

/// \brief Reset Policies
void storage_resetPolicies(Storage *storage)
{
    storage->policies_count = POLICY_COUNT;
    for (int i = 0; i < POLICY_COUNT; i++) {
        memcpy(&storage->policies[i], &policies[i], sizeof(storage->policies[i]));
    }
}

/// \brief Reset Cache
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

void storage_readMeta(Metadata *meta, const char *addr) {
    memcpy(meta->magic, addr, STORAGE_MAGIC_LEN);
    memcpy(meta->uuid, addr + 4, STORAGE_UUID_LEN);
    memcpy(meta->uuid_str, addr + 16, STORAGE_UUID_STR_LEN);
}

void storage_writeMeta(char *addr, const Metadata *meta) {
    memcpy(addr, meta->magic, STORAGE_MAGIC_LEN);
    memcpy(addr + 4, meta->uuid, STORAGE_UUID_LEN);
    memcpy(addr + 16, meta->uuid_str, STORAGE_UUID_STR_LEN);
}

void storage_readPolicy(PolicyType *policy, const char *addr) {
    policy->has_policy_name = read_bool(addr);
    memset(policy->policy_name, 0, sizeof(policy->policy_name));
    memcpy(policy->policy_name, addr + 1, 15);
    policy->has_enabled = read_bool(addr + 16);
    policy->enabled = read_bool(addr + 17);
}

void storage_writePolicy(char *addr, const PolicyType *policy) {
    write_bool(addr, policy->has_policy_name);
    memcpy(addr + 1, policy->policy_name, 15);
    write_bool(addr + 16, policy->has_enabled);
    write_bool(addr + 17, policy->enabled);
}

void storage_readHDNode(StorageHDNode *node, const char *addr) {
    node->depth = read_u32_le(addr);
    node->fingerprint = read_u32_le(addr + 4);
    node->child_num = read_u32_le(addr + 8);
    node->chain_code.size = 32;
    memcpy(node->chain_code.bytes, addr + 16, 32);
    node->has_private_key = read_bool(addr + 48);
    node->private_key.size = 32;
    memcpy(node->private_key.bytes, addr + 56, 32);
    node->has_public_key = read_bool(addr + 88);
    node->public_key.size = 33;
    memcpy(node->public_key.bytes, addr + 96, 33);
}

void storage_writeHDNode(char *addr, const StorageHDNode *node) {
    write_u32_le(addr, node->depth);
    write_u32_le(addr + 4, node->fingerprint);
    write_u32_le(addr + 8, node->child_num);
    write_u32_le(addr + 12, 32);
    memcpy(addr + 16, node->chain_code.bytes, 32);
    write_bool(addr + 48, node->has_private_key);
    addr[49] = 0; // reserved
    addr[50] = 0; // reserved
    addr[51] = 0; // reserved
    write_u32_le(addr + 52, 32);
    memcpy(addr + 56, node->private_key.bytes, 32);
    write_bool(addr + 88, node->has_public_key);
    addr[89] = 0; // reserved
    addr[90] = 0; // reserved
    addr[91] = 0; // reserved
    write_u32_le(addr + 92, 33);
    memcpy(addr + 96, node->public_key.bytes, 33);
}

void storage_readStorageV1(Storage *storage, const char *addr) {
    storage->version = read_u32_le(addr);
    storage->has_node = read_bool(addr + 4);
    storage_readHDNode(&storage->node, addr + 8);
    storage->has_mnemonic = read_bool(addr + 140);
    memcpy(storage->mnemonic, addr + 141, 241);
    storage->passphrase_protection = read_bool(addr + 383);
    storage->has_pin_failed_attempts = read_bool(addr + 384);
    storage->pin_failed_attempts = read_u32_le(addr + 388);
    storage->has_pin = read_bool(addr + 392);
    memset(storage->pin, 0, sizeof(storage->pin));
    memcpy(storage->pin, addr + 393, 10);
    storage->has_language = read_bool(addr + 403);
    memset(storage->language, 0, sizeof(storage->language));
    memcpy(storage->language, addr + 404, 17);
    storage->has_label = read_bool(addr + 421);
    memset(storage->label, 0, sizeof(storage->label));
    memcpy(storage->label, addr + 422, 33);
    storage->imported = read_bool(addr + 456);
    storage->policies_count = 1;
    storage_readPolicy(&storage->policies[0], addr + 464);
}

void storage_writeStorageV1(char *addr, const Storage *storage) {
    write_u32_le(addr, storage->version);
    write_bool(addr + 4, storage->has_node);
    addr[5] = 0; // reserved
    addr[6] = 0; // reserved
    addr[7] = 0; // reserved
    storage_writeHDNode(addr + 8, &storage->node);
    addr[137] = 0; // reserved
    addr[138] = 0; // reserved
    addr[139] = 0; // reserved
    write_bool(addr + 140, storage->has_mnemonic);
    memcpy(addr + 141, storage->mnemonic, 241);
    write_bool(addr + 382, true); // formerly has_passphrase_protection
    write_bool(addr + 383, storage->passphrase_protection);
    write_bool(addr + 384, storage->has_pin_failed_attempts);
    addr[385] = 0; // reserved
    addr[386] = 0; // reserved
    addr[387] = 0; // reserved
    write_u32_le(addr + 388, storage->pin_failed_attempts);
    write_bool(addr + 392, storage->has_pin);
    memcpy(addr + 393, storage->pin, 10);
    write_bool(addr + 403, storage->has_language);
    memcpy(addr + 404, storage->language, 17);
    write_bool(addr + 421, storage->has_label);
    memcpy(addr + 422, storage->label, 33);
    write_bool(addr + 455, true); // formerly has_imported
    write_bool(addr + 456, storage->imported);
    addr[457] = 0; // reserved
    addr[458] = 0; // reserved
    addr[459] = 0; // reserved
    write_u32_le(addr + 460, 1);
    storage_writePolicy(addr + 464, &storage->policies[0]);
}

void storage_readCacheV1(Cache *cache, const char *addr) {
    cache->root_seed_cache_status = read_u8(addr);
    memcpy(cache->root_seed_cache, addr + 1, 64);
    memcpy(cache->root_ecdsa_curve_type, addr + 65, 10);
}

void storage_writeCacheV1(char *addr, const Cache *cache) {
    write_u8(addr, cache->root_seed_cache_status);
    memcpy(addr + 1, cache->root_seed_cache, 64);
    memcpy(addr + 65, cache->root_ecdsa_curve_type, 10);
}

_Static_assert(offsetof(Cache, root_seed_cache) == 1, "rsc");
_Static_assert(offsetof(Cache, root_ecdsa_curve_type) == 65, "rect");
_Static_assert(sizeof(((Cache*)0)->root_ecdsa_curve_type) == 10, "rect");

typedef enum {
   SUS_Invalid,
   SUS_Valid,
   SUS_Updated,
} StorageUpdateStatus;

/// \brief Copy configuration from storage partition in flash memory to shadow
/// memory in RAM
/// \returns true iff successful.
static StorageUpdateStatus storage_fromFlash(ConfigFlash *dst, const char *flash)
{
    // Load config values from active config node.
    enum StorageVersion version =
        version_from_int(read_u32_le(flash + 44));

    // Don't restore storage in MFR firmware
    if (variant_isMFR())
        version = StorageVersion_NONE;

    switch (version)
    {
        case StorageVersion_1:
            storage_readMeta(&dst->meta, flash);
            storage_readStorageV1(&dst->storage, flash + 44);
            storage_resetPolicies(&dst->storage);
            storage_resetCache(&dst->cache);
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
            storage_readMeta(&dst->meta, flash);
            storage_readStorageV1(&dst->storage, flash + 44);
            storage_readCacheV1(&dst->cache, flash + 528);

            dst->storage.version = STORAGE_VERSION;

            /* We have to do this for users with bootloaders <= v1.0.2. This
            scenario would only happen after a firmware install from the same
            storage version */
            if (dst->storage.policies_count == 0xFFFFFFFF)
            {
                storage_resetPolicies(&dst->storage);
                storage_resetCache(&dst->cache);
                return SUS_Updated;
            }

            return dst->storage.version == version
                ? SUS_Valid
                : SUS_Updated;

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
    if (cfg->storage.passphrase_protection && strlen(sessionPassphrase))
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

    if (usePassphrase && cfg->storage.passphrase_protection &&
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

    if(clear_pin)
    {
        sessionPinCached = false;
    }
}

void storage_commit(void) {
    storage_commit_impl(&shadow_config);
}

void storage_commit_impl(ConfigFlash *cfg)
{
    // TODO: implemelnt storage on the emulator
#ifndef EMULATOR
    static CONFIDENTIAL char to_write[1024];

    memzero(to_write, sizeof(to_write));

    storage_writeMeta(to_write, &cfg->meta);
    storage_writeStorageV1(to_write + 44, &cfg->storage);
    _Static_assert(offsetof(ConfigFlash, storage) == 44, "storage");
    storage_writeCacheV1(to_write + 528, &cfg->cache);
    _Static_assert(offsetof(ConfigFlash, cache) == 528, "cache");

    memcpy(cfg, STORAGE_MAGIC_STR, STORAGE_MAGIC_LEN);

    uint32_t retries = 0;
    for (retries = 0; retries < STORAGE_RETRIES; retries++) {
        /* Capture CRC for verification at restore */
        uint32_t shadow_ram_crc32 =
            calc_crc32(to_write, sizeof(to_write) / sizeof(uint32_t));

        if (shadow_ram_crc32 == 0) {
            continue; /* Retry */
        }

        /* Make sure flash is in good state before proceeding */
        if (!flash_chk_status()) {
            flash_clear_status_flags();
            continue; /* Retry */
        }

        /* Make sure storage sector is valid before proceeding */
        if (storage_location < FLASH_STORAGE1 && storage_location > FLASH_STORAGE3) {
            /* Let it exhaust the retries and error out */
            continue;
        }

        flash_unlock();
        flash_erase_word(storage_location);
        wear_leveling_shift();
        flash_erase_word(storage_location);

        /* Write storage data first before writing storage magic  */
        if (!flash_write_word(storage_location, STORAGE_MAGIC_LEN,
                              sizeof(to_write) - STORAGE_MAGIC_LEN,
                              (uint8_t *)to_write + STORAGE_MAGIC_LEN)) {
            continue; // Retry
        }

        if (!flash_write_word(storage_location, 0, STORAGE_MAGIC_LEN,
                              (uint8_t *)to_write)) {
            continue; // Retry
        }

        /* Flash write completed successfully.  Verify CRC */
        uint32_t shadow_flash_crc32 =
            calc_crc32((const void*)flash_write_helper(storage_location),
                       sizeof(to_write) / sizeof(uint32_t));

        if (shadow_flash_crc32 == shadow_ram_crc32) {
            /* Commit successful, break to exit */
            break;
        }
    }

    flash_lock();

    memzero(to_write, sizeof(to_write));

    if(retries >= STORAGE_RETRIES) {
        layout_warning_static("Error Detected.  Reboot Device!");
        shutdown();
    }
#endif
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

    shadow_config.storage.imported = true;

    if(msg->has_pin > 0)
    {
        storage_setPin(msg->pin);
    }

    shadow_config.storage.passphrase_protection =
        msg->has_passphrase_protection && msg->passphrase_protection;

    if(msg->has_node)
    {
        shadow_config.storage.has_node = true;
        shadow_config.storage.has_mnemonic = false;
        memcpy(&shadow_config.storage.node, &(msg->node), sizeof(HDNodeType));

        sessionSeedCached = false;
        memset(&sessionSeed, 0, sizeof(sessionSeed));
    }
    else if(msg->has_mnemonic)
    {
        shadow_config.storage.has_mnemonic = true;
        shadow_config.storage.has_node = false;
        strlcpy(shadow_config.storage.mnemonic, msg->mnemonic,
                sizeof(shadow_config.storage.mnemonic));

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

    shadow_config.storage.has_label = true;
    memset(shadow_config.storage.label, 0, sizeof(shadow_config.storage.label));
    strlcpy(shadow_config.storage.label, label,
            sizeof(shadow_config.storage.label));
}

const char *storage_getLabel(void)
{
    if (!shadow_config.storage.has_label) {
        return NULL;
    }

    return shadow_config.storage.label;
}

void storage_setLanguage(const char *lang)
{
    if(!lang) { return; }

    // sanity check
    if(strcmp(lang, "english") == 0)
    {
        shadow_config.storage.has_language = true;
        memset(shadow_config.storage.language, 0,
               sizeof(shadow_config.storage.language));
        strlcpy(shadow_config.storage.language, lang,
                sizeof(shadow_config.storage.language));
    }
}

const char *storage_getLanguage(void)
{
    if (!shadow_config.storage.has_language) {
        return NULL;
    }

    return shadow_config.storage.language;
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
        sumXors = sumXors + ( (uint8_t)shadow_config.storage.pin[pinIdx] ^ (uint8_t)pin[pinIdx] );
    }

    result1 = ('\0' == shadow_config.storage.pin[pinIdx]);
    result2 = (1 <= pinIdx);
    result3 = (0 == sumXors);
    result = result1 + result2 + result3;

    return (result == 3);
}

bool storage_hasPin(void)
{
    return shadow_config.storage.has_pin && strlen(shadow_config.storage.pin) > 0;
}

void storage_setPin(const char *pin)
{
    if(pin && strlen(pin) > 0)
    {
        shadow_config.storage.has_pin = true;
        strlcpy(shadow_config.storage.pin, pin, sizeof(shadow_config.storage.pin));
        session_cachePin(pin);
    }
    else
    {
        shadow_config.storage.has_pin = false;
        memset(shadow_config.storage.pin, 0, sizeof(shadow_config.storage.pin));
        sessionPinCached = false;
    }
}

void session_cachePin(const char *pin)
{
    strlcpy(sessionPin, pin, sizeof(sessionPin));
    sessionPinCached = true;
}

bool session_isPinCached(void)
{
    return sessionPinCached && strcmp(sessionPin, shadow_config.storage.pin) == 0;
}

void storage_resetPinFails(void)
{
    shadow_config.storage.has_pin_failed_attempts = false;
    shadow_config.storage.pin_failed_attempts = 0;

    storage_commit_impl(&shadow_config);
}

void storage_increasePinFails(void)
{
    shadow_config.storage.has_pin_failed_attempts = true;
    shadow_config.storage.pin_failed_attempts++;

    storage_commit_impl(&shadow_config);
}

uint32_t storage_getPinFails(void)
{
    return shadow_config.storage.has_pin_failed_attempts ?
           shadow_config.storage.pin_failed_attempts : 0;
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
    if (cfg->storage.has_mnemonic) {
        if (usePassphrase && !passphrase_protect()) {
            return NULL;
        }

        layout_loading();
        mnemonic_to_seed(cfg->storage.mnemonic,
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
    if (shadow_config.storage.has_node && strcmp(curve, SECP256K1_NAME) == 0) {
        if (!passphrase_protect()) {
            /* passphrased failed. Bailing */
            return false;
        }

        if (hdnode_from_xprv(shadow_config.storage.node.depth,
                             shadow_config.storage.node.child_num,
                             shadow_config.storage.node.chain_code.bytes,
                             shadow_config.storage.node.private_key.bytes,
                             curve, node) == 0) {
            return false;
        }

        if (shadow_config.storage.passphrase_protection &&
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
    if (shadow_config.storage.has_mnemonic) {
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
    return shadow_config.storage.has_node || shadow_config.storage.has_mnemonic;
}

const char *storage_getUuidStr(void)
{
    return shadow_config.meta.uuid_str;
}

bool storage_getPassphraseProtected(void)
{
    return shadow_config.storage.passphrase_protection;
}

void storage_setPassphraseProtected(bool passphrase)
{
    shadow_config.storage.passphrase_protection = passphrase;
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
    strlcpy(shadow_config.storage.mnemonic, words[0],
            sizeof(shadow_config.storage.mnemonic));

    for(uint32_t i = 1; i < word_count; i++)
    {
        strlcat(shadow_config.storage.mnemonic, " ",
                sizeof(shadow_config.storage.mnemonic));
        strlcat(shadow_config.storage.mnemonic, words[i],
                sizeof(shadow_config.storage.mnemonic));
    }

    shadow_config.storage.has_mnemonic = true;
}

void storage_setMnemonic(const char *m)
{
    memset(shadow_config.storage.mnemonic, 0,
           sizeof(shadow_config.storage.mnemonic));
    strlcpy(shadow_config.storage.mnemonic, m,
            sizeof(shadow_config.storage.mnemonic));
    shadow_config.storage.has_mnemonic = true;
}

bool storage_hasMnemonic(void)
{
    return shadow_config.storage.has_mnemonic;
}

const char *storage_getShadowMnemonic(void)
{
    return shadow_config.storage.mnemonic;
}

bool storage_getImported(void)
{
    return shadow_config.storage.imported;
}

bool storage_hasNode(void)
{
    return shadow_config.storage.has_node;
}

Allocation storage_getLocation(void)
{
    return storage_location;
}

bool storage_setPolicy(const PolicyType *policy)
{
    for (unsigned i = 0; i < POLICY_COUNT; ++i)
    {
        if(strcmp(policy->policy_name, shadow_config.storage.policies[i].policy_name) == 0)
        {
            memcpy(&shadow_config.storage.policies[i], policy, sizeof(PolicyType));
            return true;
        }
    }

    return false;
}

void storage_getPolicies(PolicyType *policy_data)
{
    for (size_t i = 0; i < POLICY_COUNT; ++i) {
        memcpy(&policy_data[i], &shadow_config.storage.policies[i], sizeof(policy_data[i]));
    }
}

bool storage_isPolicyEnabled(char *policy_name)
{
    for (unsigned i = 0; i < POLICY_COUNT; ++i)
    {
        if(strcmp(policy_name, shadow_config.storage.policies[i].policy_name) == 0)
        {
            return shadow_config.storage.policies[i].enabled;
        }
    }
    return false;
}

#if DEBUG_LINK
const char *storage_getPin(void)
{
    return (shadow_config.storage.has_pin) ? shadow_config.storage.pin : NULL;
}

const char *storage_getMnemonic(void)
{
    return shadow_config.storage.mnemonic;
}

StorageHDNode *storage_getNode(void)
{
    return &shadow_config.storage.node;
}
#endif
