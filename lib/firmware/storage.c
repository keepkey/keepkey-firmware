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
#include "keepkey/firmware/storagepb.h"
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
_Static_assert(sizeof(ConfigFlash) <= FLASH_STORAGE_LEN, "ConfigFlash struct is too large for storage partition");
static ConfigFlash CONFIDENTIAL shadow_config;

/// \brief Reset Policies
void storage_resetPolicies(ConfigFlash *cfg)
{
    cfg->storage.policies_count = POLICY_COUNT;
    memcpy(&cfg->storage.policies, policies, POLICY_COUNT * sizeof(PolicyType));
}

/// \brief Reset Cache
void storage_resetCache(ConfigFlash *cfg)
{
    memset(&cfg->cache, 0, sizeof(cfg->cache));
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

/// \brief Copy configuration from storage partition in flash memory to shadow
/// memory in RAM
/// \returns true iff successful.
static bool storage_fromFlash(ConfigFlash *dst, const ConfigFlash *src)
{
    /* load config values from active config node */
    enum StorageVersion version = version_from_int(src->storage.version);

    // Don't restore storage in MFR firmware
    if (variant_isMFR())
        version = StorageVersion_NONE;

    switch (version)
    {
        case StorageVersion_1:
            memcpy(&dst->meta, &src->meta, sizeof(dst->meta));
            memcpy(&dst->storage, &src->storage, sizeof(dst->storage));
            storage_resetPolicies(dst);
            storage_resetCache(dst);
            dst->storage.version = STORAGE_VERSION;
            return true;

        case StorageVersion_2:
        case StorageVersion_3:
        case StorageVersion_4:
        case StorageVersion_5:
        case StorageVersion_6:
        case StorageVersion_7:
        case StorageVersion_8:
        case StorageVersion_9:
        case StorageVersion_10:
            memcpy(&dst, src, sizeof(*dst));

            /* We have to do this for users with bootloaders <= v1.0.2. This
            scenario would only happen after a firmware install from the same
            storage version */
            if(dst->storage.policies_count == 0xFFFFFFFF)
            {
                storage_resetPolicies(dst);
                storage_resetCache(dst);
                storage_commit();
            }

            dst->storage.version = STORAGE_VERSION;
            return true;

        case StorageVersion_NONE:
            return false;

        // DO *NOT* add a default case
    }

#ifdef DEBUG_ON
     // Should be unreachable, but we don't want to tell the compiler that in a
     // release build. The benefit to doing it this way is that with the
     // unreachable and lack of default case in the switch, the compiler will
     // tell us if we have not covered every case in the switch.
     __builtin_unreachable();
#endif

    return false;
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
    if(!(cfg->storage.has_passphrase_protection &&
         cfg->storage.passphrase_protection && strlen(sessionPassphrase)))
    {
        memset(&cfg->cache, 0, sizeof(((ConfigFlash *)NULL)->cache));

        memcpy(&cfg->cache.root_seed_cache, seed,
               sizeof(((ConfigFlash *)NULL)->cache.root_seed_cache));

        strlcpy(cfg->cache.root_ecdsa_curve_type, curve,
                sizeof(cfg->cache.root_ecdsa_curve_type));

        cfg->cache.root_seed_cache_status = CACHE_EXISTS;
        storage_commit();
    }
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
    if(cfg->cache.root_seed_cache_status == CACHE_EXISTS)
    {
        if(usePassphrase)
        {
            if(cfg->storage.has_passphrase_protection &&
                cfg->storage.passphrase_protection && strlen(sessionPassphrase))
            {
                return false;
            }
        }

        if(!strcmp(cfg->cache.root_ecdsa_curve_type, curve))
        {
            memset(seed, 0, sizeof(sessionSeed));
            memcpy(seed, &cfg->cache.root_seed_cache,
                   sizeof(cfg->cache.root_seed_cache));
            return true;
        }
    }

    return false;
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

    ConfigFlash *stor_config;

    /* Find storage sector with valid data and set storage_location variable */
    if(find_active_storage(&storage_location))
    {
        stor_config = (ConfigFlash *)flash_write_helper(storage_location);
    }
    else
    {
        /* Set to storage sector1 as default if no sector has been initialized */
        storage_location = STORAGE_SECT_DEFAULT;
        stor_config = (ConfigFlash *)flash_write_helper(storage_location);
    }

    /* Reset shadow configuration in RAM */
    storage_reset();

    /* Verify storage partition is initialized */
    if(memcmp((void *)stor_config->meta.magic , STORAGE_MAGIC_STR,
              STORAGE_MAGIC_LEN) == 0)
    {
        /* Clear out stor_config before finding end config node */
        memcpy(shadow_config.meta.uuid, (void *)&stor_config->meta.uuid,
               sizeof(shadow_config.meta.uuid));
        data2hex(shadow_config.meta.uuid, sizeof(shadow_config.meta.uuid),
                 shadow_config.meta.uuid_str);

        if(stor_config->storage.version)
        {
            if(stor_config->storage.version <= STORAGE_VERSION)
            {
                storage_fromFlash(&shadow_config, stor_config);
            }
        }

        /* New app with storage version changed!  update the storage space */
        if(stor_config->storage.version != STORAGE_VERSION)
        {
            storage_commit();
        }
    }
    else
    {
        /* Keep storage area cleared */
        storage_resetUuid();
        storage_commit();
    }
}

void storage_resetUuid(void)
{
    // set random uuid
    random_buffer(shadow_config.meta.uuid, sizeof(shadow_config.meta.uuid));
    data2hex(shadow_config.meta.uuid, sizeof(shadow_config.meta.uuid),
             shadow_config.meta.uuid_str);
}

void storage_reset(void)
{
    memset(&shadow_config.storage, 0, sizeof(shadow_config.storage));
    memset(&shadow_config.cache, 0, sizeof(shadow_config.cache));

    storage_resetPolicies(&shadow_config);

    shadow_config.storage.version = STORAGE_VERSION;
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

void storage_commit(void)
{
    // TODO: implemelnt storage on the emulator
#ifndef EMULATOR
    uint32_t shadow_ram_crc32, shadow_flash_crc32, retries;

    memcpy((void *)&shadow_config, STORAGE_MAGIC_STR, STORAGE_MAGIC_LEN);

    for(retries = 0; retries < STORAGE_RETRIES; retries++)
    {
        /* Capture CRC for verification at restore */
        shadow_ram_crc32 = calc_crc32((uint32_t *)&shadow_config,
                                      sizeof(shadow_config) / sizeof(uint32_t));

        if(shadow_ram_crc32 == 0)
        {
            continue; /* Retry */
        }

        /* Make sure flash is in good state before proceeding */
        if(!flash_chk_status())
        {
            flash_clear_status_flags();
            continue; /* Retry */
        }

        /* Make sure storage sector is valid before proceeding */
        if(storage_location < FLASH_STORAGE1 && storage_location > FLASH_STORAGE3)
        {
            /* Let it exhaust the retries and error out */
            continue;
        }

        flash_unlock();
        flash_erase_word(storage_location);
        wear_leveling_shift();


        flash_erase_word(storage_location);

        /* Load storage data first before loading storage magic  */
        if(flash_write_word(storage_location, STORAGE_MAGIC_LEN,
                            sizeof(shadow_config) - STORAGE_MAGIC_LEN,
                            (uint8_t *)&shadow_config + STORAGE_MAGIC_LEN))
        {
            if(!flash_write_word(storage_location, 0, STORAGE_MAGIC_LEN,
                                 (uint8_t *)&shadow_config))
            {
                continue; /* Retry */
            }
        }
        else
        {
            continue; /* Retry */
        }

        /* Flash write completed successfully.  Verify CRC */
        shadow_flash_crc32 = calc_crc32((uint32_t *)flash_write_helper(
                                            storage_location),
                                        sizeof(shadow_config) / sizeof(uint32_t));

        if(shadow_flash_crc32 == shadow_ram_crc32)
        {
            /* Commit successful, break to exit */
            break;
        }
        else
        {
            continue; /* Retry */
        }
    }

    flash_lock();

    if(retries >= STORAGE_RETRIES)
    {
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
    storage_reset();

    shadow_config.storage.has_imported = true;
    shadow_config.storage.imported = true;

    if(msg->has_pin > 0)
    {
        storage_setPin(msg->pin);
    }

    if(msg->has_passphrase_protection)
    {
        shadow_config.storage.has_passphrase_protection = true;
        shadow_config.storage.passphrase_protection = msg->passphrase_protection;
    }
    else
    {
        shadow_config.storage.has_passphrase_protection = false;
    }

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

    storage_commit();
}

void storage_increasePinFails(void)
{
    shadow_config.storage.has_pin_failed_attempts = true;
    shadow_config.storage.pin_failed_attempts++;

    storage_commit();
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

bool storage_getRootNode(const char *curve, bool usePassphrase, HDNode *node)
{
    bool ret_stat = false;

    // if storage has node, decrypt and use it
    if(shadow_config.storage.has_node && strcmp(curve, SECP256K1_NAME) == 0)
    {
        if(!passphrase_protect())
        {
            /* passphrased failed. Bailing */
            goto storage_getRootNode_exit;
        }
        if (hdnode_from_xprv(shadow_config.storage.node.depth,
                             shadow_config.storage.node.child_num,
                             shadow_config.storage.node.chain_code.bytes,
                             shadow_config.storage.node.private_key.bytes,
                             curve, node) == 0)
        {
            goto storage_getRootNode_exit;
        }

        if (shadow_config.storage.has_passphrase_protection &&
            shadow_config.storage.passphrase_protection &&
            sessionPassphraseCached &&
            strlen(sessionPassphrase) > 0)
        {
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

        ret_stat = true;
        goto storage_getRootNode_exit;
    }

    /* get node from mnemonic */
    if(shadow_config.storage.has_mnemonic)
    {
        if(!passphrase_protect())
        {
            /* passphrased failed. Bailing */
            goto storage_getRootNode_exit;
        }

        if(!sessionSeedCached)
        {

            sessionSeedCached = storage_getRootSeedCache(&shadow_config, curve, usePassphrase, sessionSeed);

            if(!sessionSeedCached)
            {
                /* calculate session seed and update the global sessionSeed/sessionSeedCached variables */
                storage_getSeed(&shadow_config, usePassphrase);

                if (sessionSeedCached)
                {
                    storage_setRootSeedCache(&shadow_config, sessionSeed, curve);
                }
                else
                {
                    goto storage_getRootNode_exit;
                }
            }
        }

        if(hdnode_from_seed(sessionSeed, 64, curve, node) == 1)
        {
            ret_stat = true;
        }
    }
storage_getRootNode_exit:

    return ret_stat;
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
    if (!shadow_config.storage.has_passphrase_protection)
    {
        return false;
    }

    return shadow_config.storage.passphrase_protection;
}

void storage_setPassphraseProtected(bool passphrase)
{
    shadow_config.storage.has_passphrase_protection = true;
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
    return shadow_config.storage.has_imported && shadow_config.storage.imported;
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
    for (int i = 0; i < POLICY_COUNT; ++i)
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
        PolicyType *dst = &policy_data[i];
        StoragePolicy *src = &shadow_config.storage.policies[i];

        dst->has_policy_name = src->has_policy_name;
        if (src->has_policy_name) {
            memcpy(dst->policy_name, src->policy_name, sizeof(src->policy_name));
            _Static_assert(sizeof(dst->policy_name) ==
                           sizeof(src->policy_name), "PolicyType vs StoragePolicy type mismatch");
        }

        dst->has_enabled = src->has_enabled;
        dst->enabled = src->enabled;

        _Static_assert(sizeof(*dst) == sizeof(*src), "PolicyType vs StoragePolicy type mismatch");
    }
}

bool storage_isPolicyEnabled(char *policy_name)
{
    for (int i = 0; i < POLICY_COUNT; ++i)
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
