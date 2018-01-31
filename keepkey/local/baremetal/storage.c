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

/* === Includes ============================================================ */

#include <string.h>
#include <stdint.h>

#include <libopencm3/stm32/flash.h>

#include <bip39.h>
#include <aes.h>
#include <pbkdf2.h>
#include <keepkey_board.h>
#include <pbkdf2.h>
#include <keepkey_flash.h>
#include <interface.h>
#include <memory.h>
#include <rng.h>

#include "curves.h"
#include "util.h"
#include "storage.h"
#include "passphrase_sm.h"
#include "fsm.h"
#include "policy.h"

/* === Private Variables =================================================== */

static bool sessionSeedCached, sessionSeedUsesPassphrase;
static uint8_t CONFIDENTIAL sessionSeed[64];

static bool sessionPinCached;
static char CONFIDENTIAL sessionPin[17];

static bool sessionPassphraseCached;
static char CONFIDENTIAL sessionPassphrase[51];

static Allocation storage_location = FLASH_INVALID;

/* === Variables =========================================================== */

/* Shadow memory for configuration data in storage partition */
_Static_assert(sizeof(ConfigFlash) <= FLASH_STORAGE_LEN, "ConfigFlash struct is too large for storage partition");
static ConfigFlash CONFIDENTIAL shadow_config;

/* === Private Functions =================================================== */

/*
 * storage_reset_policies() - Resets policies
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 *
 */
static void storage_reset_policies(void)
{
    shadow_config.storage.policies_count = POLICY_COUNT;
    memcpy(&shadow_config.storage.policies, policies, POLICY_COUNT * sizeof(PolicyType));
}

/*
 * storage_reset_cache() - Resets cache
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 *
 */
static void storage_reset_cache(void)
{
    memset(&shadow_config.cache, 0, sizeof(shadow_config.cache));
}

/*
 * storage_from_flash() - Copy configuration from storage partition in flash memory to shadow memory in RAM
 *
 * INPUT
 *     - stor_config: storage config
 * OUTPUT
 *     true/false status
 *
 */
static bool storage_from_flash(ConfigFlash *stor_config)
{
    /* load config values from active config node */
    switch(stor_config->storage.version)
    {
        case 1:
            memcpy(&shadow_config.meta, &stor_config->meta, sizeof(shadow_config.meta));
            memcpy(&shadow_config.storage, &stor_config->storage, sizeof(shadow_config.storage));
            storage_reset_policies();
            storage_reset_cache();
            break;

        case 2:
        case 3:
        case 4:
            memcpy(&shadow_config, stor_config, sizeof(shadow_config));

            /* We have to do this for users with bootloaders <= v1.0.2. This
            scenario would only happen after a firmware install from the same
            storage version */
            if(shadow_config.storage.policies_count == 0xFFFFFFFF)
            {
                storage_reset_policies();
                storage_reset_cache();
                storage_commit();
            }

            break;

        default:
            return false;
    }

    shadow_config.storage.version = STORAGE_VERSION;
    return true;
}

/*
 * wear_leveling_shift() - Shifts sector for config storage
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 *
 */
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

/*
 * storage_set_root_seed_cache() - Sets root session seed  in storage
 *
 * INPUT
 *     seed : source of root seed 
 *     curve : pointer to ecdsa cure being used
 *
 * OUTPUT
 *    none 
 *
 */
static void storage_set_root_seed_cache(const uint8_t *seed, const char* curve)
{
    if(!(shadow_config.storage.has_passphrase_protection &&
            shadow_config.storage.passphrase_protection && strlen(sessionPassphrase)))
    {
        memset(&shadow_config.cache, 0, sizeof(((ConfigFlash *)NULL)->cache));

        memcpy(&shadow_config.cache.root_seed_cache, seed,
               sizeof(((ConfigFlash *)NULL)->cache.root_seed_cache));

        strlcpy(shadow_config.cache.root_ecdsa_curve_type, curve, 
                sizeof(shadow_config.cache.root_ecdsa_curve_type));

        shadow_config.cache.root_seed_cache_status = CACHE_EXISTS; 
        storage_commit();
    }
}

/*
 * storage_get_root_seed_cache() - Gets root session seed cache from storage
 *
 * INPUT
 *    seed : destination seed pointer 
 *    curve : pointer to ecdsa cure being used
 *    usePassphrase : flag to use passphrase or not
 *
 * OUTPUT
 *    return status
 */
static bool storage_get_root_seed_cache(uint8_t *seed,const char* curve, bool usePassphrase)
{
    bool ret_stat = false;

    if(shadow_config.cache.root_seed_cache_status == CACHE_EXISTS)
    {
        if(usePassphrase)
        {
            if(shadow_config.storage.has_passphrase_protection &&
                shadow_config.storage.passphrase_protection && strlen(sessionPassphrase))
            {
                goto storage_get_root_seed_cache_exit;
            }
        }
        if(!strcmp(shadow_config.cache.root_ecdsa_curve_type, curve))
        {
            memset(seed, 0, sizeof(sessionSeed));
            memcpy(seed, &shadow_config.cache.root_seed_cache,
                sizeof(((ConfigFlash *)NULL)->cache.root_seed_cache));
            ret_stat = true;
        }
    }

storage_get_root_seed_cache_exit:

    return(ret_stat);
}

/* === Functions =========================================================== */

/*
 * storage_init() - Validate storage content and copy data to shadow memory
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void storage_init(void)
{
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
                storage_from_flash(stor_config);
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
        storage_reset_uuid();
        storage_commit();
    }
}

/*
 * storage_reset_uuid() - Reset configuration uuid in RAM with random numbers
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 *
 */
void storage_reset_uuid(void)
{
    // set random uuid
    random_buffer(shadow_config.meta.uuid, sizeof(shadow_config.meta.uuid));
    data2hex(shadow_config.meta.uuid, sizeof(shadow_config.meta.uuid),
             shadow_config.meta.uuid_str);
}

/*
 * storage_reset() - Clear configuration in RAM
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void storage_reset(void)
{
    /* Reset storage and cache */
    memset(&shadow_config.storage, 0, sizeof(shadow_config.storage));
    memset(&shadow_config.cache, 0, sizeof(shadow_config.cache));

    storage_reset_policies();

    shadow_config.storage.version = STORAGE_VERSION;
    session_clear(true); // clear PIN as well
}

/*
 * session_clear() - Reset session states
 *
 * INPUT
 *     - clear_pin: whether to clear pin or not
 * OUTPUT
 *     none
 */
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

/*
 * storage_commit() - Write content of configuration in shadow memory to
 * storage partion in flash
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void storage_commit(void)
{
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
        system_halt();
    }
}

/*
 * storage_load_device() - Load configuration data from usb message to shadow memory
 *
 * INPUT
 *     - msg: load device message
 * OUTPUT
 *     none
 */
void storage_load_device(LoadDevice *msg)
{
    storage_reset();

    shadow_config.storage.has_imported = true;
    shadow_config.storage.imported = true;

    if(msg->has_pin > 0)
    {
        storage_set_pin(msg->pin);
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
        storage_set_language(msg->language);
    }

    if(msg->has_label)
    {
        storage_set_label(msg->label);
    }
}

/*
 * storage_set_label() - Set device label
 *
 * INPUT
 *     - label: label to set
 * OUTPUT
 *     none
 */
void storage_set_label(const char *label)
{
    if(!label) { return; }

    shadow_config.storage.has_label = true;
    memset(shadow_config.storage.label, 0, sizeof(shadow_config.storage.label));
    strlcpy(shadow_config.storage.label, label,
            sizeof(shadow_config.storage.label));
}

/*
 * storage_get_label() - Get device's label
 *
 * INPUT
 *     none
 * OUTPUT
 *     device's label
 *
 */
const char *storage_get_label(void)
{
    if(shadow_config.storage.has_label)
    {
        return shadow_config.storage.label;
    }
    else
    {
        return NULL;
    }
}

/*
 * storage_set_language() - Set device language
 *
 * INPUT
 *     - lang: language to apply
 * OUTPUT
 *     none
 */
void storage_set_language(const char *lang)
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

/*
 * storage_get_language() - Get device's language
 *
 * INPUT
 *     none
 * OUTPUT
 *     device's language
 */
const char *storage_get_language(void)
{
    if(shadow_config.storage.has_language)
    {
        return shadow_config.storage.language;
    }
    else
    {
        return NULL;
    }
}

/*
 * storage_is_pin_correct() - Validates PIN
 *
 * INPUT
 *     - pin: PIN to validate
 * OUTPUT
 *     true/false whether PIN is correct
 */
bool storage_is_pin_correct(const char const*pin)
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

/*
 * storage_has_pin() - Determines whther device has PIN
 *
 * INPUT
 *     none
 * OUTPUT
 *     true/false whether device has a PIN
 */
bool storage_has_pin(void)
{
    return shadow_config.storage.has_pin && strlen(shadow_config.storage.pin) > 0;
}

/*
 * storage_set_pin() - Save PIN
 *
 * INPUT
 *     - pin: PIN to save
 * OUTPUT
 *     none
 */
void storage_set_pin(const char *pin)
{
    if(pin && strlen(pin) > 0)
    {
        shadow_config.storage.has_pin = true;
        strlcpy(shadow_config.storage.pin, pin, sizeof(shadow_config.storage.pin));
        session_cache_pin(pin);
    }
    else
    {
        shadow_config.storage.has_pin = false;
        memset(shadow_config.storage.pin, 0, sizeof(shadow_config.storage.pin));
        sessionPinCached = false;
    }
}



/*
 * session_cache_pin() - Save pin in session cache
 *
 * INPUT
 *     - pin: PIN to save to session cache
 * OUTPUT
 *     none
 */
void session_cache_pin(const char *pin)
{
    strlcpy(sessionPin, pin, sizeof(sessionPin));
    sessionPinCached = true;
}

/*
 * session_is_pin_cached() - Is PIN cached in session
 *
 * INPUT
 *     none
 * OUTPUT
 *     true/false whether PIN is cached in session
 *
 */
bool session_is_pin_cached(void)
{
    return sessionPinCached && strcmp(sessionPin, shadow_config.storage.pin) == 0;
}

/*
 * storage_reset_pin_fails() - Reset PIN failures
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void storage_reset_pin_fails(void)
{
    shadow_config.storage.has_pin_failed_attempts = false;
    shadow_config.storage.pin_failed_attempts = 0;

    storage_commit();
}

/*
 * storage_increase_pin_fails() - Increment PIN failed attempts
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void storage_increase_pin_fails(void)
{
    shadow_config.storage.has_pin_failed_attempts = true;
    shadow_config.storage.pin_failed_attempts++;

    storage_commit();
}

/*
 * storage_get_pin_fails() - Get number PIN failures
 *
 * INPUT
 *     none
 * OUTPOUT
 *     number of PIN failures
 */
uint32_t storage_get_pin_fails(void)
{
    return shadow_config.storage.has_pin_failed_attempts ?
           shadow_config.storage.pin_failed_attempts : 0;
}

/*
 * get_root_node_callback() - Calls animation callback
 *
 * INPUT
 *     - iter: current iteration
 *     - total: total iterations
 * OUTPUT
 *     none
 */
void get_root_node_callback(uint32_t iter, uint32_t total)
{
    (void)iter;
    (void)total;
    animating_progress_handler();
}

/*
 * storage_getSeed() - get user private seed
 *
 * INPUT
 *    usePassphrase: argument to use passphrase
 * OUTPUT
 *    sessionSeed - pointer to private seed (if no error)  
 */
const uint8_t *storage_getSeed(bool usePassphrase)
{
	// root node is properly cached
	if (usePassphrase == sessionSeedUsesPassphrase
		&& sessionSeedCached) {
		return sessionSeed;
	}

	// if storage has mnemonic, convert it to node and use it
	if (shadow_config.storage.has_mnemonic) {
		if (usePassphrase && !passphrase_protect())
                {
		    return NULL;
		}
                layout_loading();
		mnemonic_to_seed(shadow_config.storage.mnemonic, usePassphrase ? sessionPassphrase : "", sessionSeed, get_root_node_callback); // BIP-0039
		sessionSeedCached = true;
		sessionSeedUsesPassphrase = usePassphrase;
		return sessionSeed;
	}

	return NULL;
}

/*
 * storage_get_root_node() - Returns root node of device
 *
 * INPUT
 *     - node: where to put the node that is found
 * OUTPUT
 *     true/false whether root node was found
 */
bool storage_get_root_node(HDNode *node, const char *curve, bool usePassphrase)
{
    bool ret_stat = false;

    // if storage has node, decrypt and use it
    if(shadow_config.storage.has_node && strcmp(curve, SECP256K1_NAME) == 0) 
    {
        if(!passphrase_protect())
        {
            /* passphrased failed. Bailing */
            goto storage_get_root_node_exit;
        }
	if(hdnode_from_xprv(shadow_config.storage.node.depth, 
                            shadow_config.storage.node.child_num, 
                            shadow_config.storage.node.chain_code.bytes, 
                            shadow_config.storage.node.private_key.bytes, 
                            curve, node) == 0) 
        {
            goto storage_get_root_node_exit;
        }

        if (shadow_config.storage.has_passphrase_protection && 
            shadow_config.storage.passphrase_protection && 
            sessionPassphraseCached && 
            strlen(sessionPassphrase) > 0) 
        {
	    // decrypt hd node
	    uint8_t secret[64];
	    PBKDF2_HMAC_SHA512_CTX pctx;
	    pbkdf2_hmac_sha512_Init(&pctx, (const uint8_t *)sessionPassphrase, strlen(sessionPassphrase), (const uint8_t *)"TREZORHD", 8);
	    for (int i = 0; i < 8; i++) 
            {
	        pbkdf2_hmac_sha512_Update(&pctx, BIP39_PBKDF2_ROUNDS / 8, get_root_node_callback);
	    }
	    pbkdf2_hmac_sha512_Final(&pctx, secret);
	    aes_decrypt_ctx ctx;
	    aes_decrypt_key256(secret, &ctx);
	    aes_cbc_decrypt(node->chain_code, node->chain_code, 32, secret + 32, &ctx);
	    aes_cbc_decrypt(node->private_key, node->private_key, 32, secret + 32, &ctx);
	}

	ret_stat = true;
        goto storage_get_root_node_exit;
    }

    /* get node from mnemonic */
    if(shadow_config.storage.has_mnemonic)
    {
        if(!passphrase_protect())
        {
            /* passphrased failed. Bailing */
            goto storage_get_root_node_exit;
        }

	if(!sessionSeedCached)
        {

            sessionSeedCached = storage_get_root_seed_cache(sessionSeed, curve, usePassphrase);

            if(!sessionSeedCached)
            {
                /* calculate session seed and update the global sessionSeed/sessionSeedCached variables */
                storage_getSeed(usePassphrase);

                if (sessionSeedCached) 
                {
                    storage_set_root_seed_cache(sessionSeed, curve);
                }
                else
                {
                    goto storage_get_root_node_exit;
                }
            }
        }

        if(hdnode_from_seed(sessionSeed, 64, curve, node) == 1)
        {
            ret_stat = true;
        }
    }
storage_get_root_node_exit:

    return ret_stat;
}

/*
 * storage_is_initialized() - Is device initialized?
 *
 * INPUT
 *     none
 * OUTPUT
 *     true/false wether device is initialized
 *
 *
 */
bool storage_is_initialized(void)
{
    return shadow_config.storage.has_node || shadow_config.storage.has_mnemonic;
}

/*
 * storage_get_uuid_str() - Get device's UUID
 *
 * INPUT
 *     none
 * OUTPUT
 *     device's UUID
 */
const char *storage_get_uuid_str(void)
{
    return shadow_config.meta.uuid_str;
}

/*
 * storage_get_passphrase_protected() - Get passphrase protection status
 *
 * INPUT
 *     none
 * OUTPUT
 *     true/false whether device is passphrase protected
 *
 */
bool storage_get_passphrase_protected(void)
{
    if(shadow_config.storage.has_passphrase_protection)
    {
        return shadow_config.storage.passphrase_protection;
    }
    else
    {
        return false;
    }
}

/*
 * storage_set_passphrase_protected() - Set passphrase protection
 *
 * INPUT
 *     - p: state of passphrase protection to set
 * OUTPUT
 *     none
 *
 */
void storage_set_passphrase_protected(bool passphrase)
{
    shadow_config.storage.has_passphrase_protection = true;
    shadow_config.storage.passphrase_protection = passphrase;
}

/*
 * session_cachePassphrase() - Set session passphrase
 *
 * INPUT
 *     - passphrase: passphrase to set for session
 * OUTPUT
 *     none
 */
void session_cache_passphrase(const char *passphrase)
{
    strlcpy(sessionPassphrase, passphrase, sizeof(sessionPassphrase));
    sessionPassphraseCached = true;
}

/*
 * session_isPassphraseCached() - Returns whether there is a cached passphrase
 *
 * INPUT
 *     none
 * OUTPUT
 *     true/false session passphrase cache status
 */
bool session_is_passphrase_cached(void)
{
    return sessionPassphraseCached;
}

/*
 * storage_set_mnemonic_from_words() - Set config mnemonic in shadow memory from words
 *
 * INPUT
 *     - words: mnemonic
 *     - word_count: how words in mnemonic
 * OUTPUT
 *     none
 */
void storage_set_mnemonic_from_words(const char (*words)[12],
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

/*
 * storage_set_mnemonic() - Set config mnemonic in shadow memory
 *
 * INPUT
 *     - m: mnemonic to set in shadow memory
 * OUTPUT
 *     none
 *
 */
void storage_set_mnemonic(const char *m)
{
    memset(shadow_config.storage.mnemonic, 0,
           sizeof(shadow_config.storage.mnemonic));
    strlcpy(shadow_config.storage.mnemonic, m,
            sizeof(shadow_config.storage.mnemonic));
    shadow_config.storage.has_mnemonic = true;
}

/*
 * storage_has_mnemonic() - Does device have mnemonic?
 *
 * INPUT
 *     none
 * OUTPUT
 *     true/false whether device has mnemonic
 *
 */
bool storage_has_mnemonic(void)
{
    return shadow_config.storage.has_mnemonic;
}


/*
 * storage_get_shadow_mnemonic() - Get mnemonic from shadow memory
 *
 * INPUT
 *     none
 * OUTPUT
 *     mnemonic from shadow memory
 */
const char *storage_get_shadow_mnemonic(void)
{
    return shadow_config.storage.mnemonic;
}

/*
 * storage_get_imported() - Whether private key stored on device was imported
 *
 * INPUT
 *     none
 * OUTPUT
 *     true/false whether private key was imported
 */
bool storage_get_imported(void)
{
    return shadow_config.storage.has_imported && shadow_config.storage.imported;
}

/*
 * storage_has_node() - Does device have an HDNode
 *
 * INPUT
 *     none
 * OUTPUT
 *     true/false whether device has HDNode
 */
bool storage_has_node(void)
{
    return shadow_config.storage.has_node;
}

/*
 * get_storage_location() - Get storage data start address
 *
 * INPUT -
 *      none
 * OUTPUT -
 *      none
 *
 */
Allocation get_storage_location(void)
{
    return(storage_location);
}

/*
 * storage_set_policy() - Set policy
 *
 * INPUT
 *     policy: policy data
 * OUTPUT
 *     none
 */
bool storage_set_policy(PolicyType *policy)
{
    uint8_t i;
    bool ret_val = false;

    for(i = 0; i < POLICY_COUNT; ++i)
    {
        if(strcmp(policy->policy_name, shadow_config.storage.policies[i].policy_name) == 0)
        {
            memcpy(&shadow_config.storage.policies[i], policy, sizeof(PolicyType));
            ret_val = true;
        }
    }

    return ret_val;
}

/*
 * storage_get_policies() - Copies policies
 *
 * INPUT
 *     policies: where to copy policies to
 * OUTPUT
 *     none
 */
void storage_get_policies(PolicyType *policy_data)
{
    memcpy(policy_data, shadow_config.storage.policies, POLICY_COUNT * sizeof(PolicyType));
}

/*
 * storage_is_policy_enabled() - Status of policy in storage
 *
 * INPUT
 *     policy_name: name of policy to check
 * OUTPUT
 *     none
 */
bool storage_is_policy_enabled(char *policy_name)
{
    uint8_t i;
    bool ret_val = false;

    for(i = 0; i < POLICY_COUNT; ++i)
    {
        if(strcmp(policy_name, shadow_config.storage.policies[i].policy_name) == 0)
        {
            ret_val = shadow_config.storage.policies[i].enabled;
        }
    }

    return ret_val;
}

/* === Debug Functions =========================================================== */
#if DEBUG_LINK
/*
 * storage_get_pin() - Returns PIN
 *
 * INPUT
 *     none
 * OUTPUT
 *     device's PIN
 */
const char *storage_get_pin(void)
{
    return (shadow_config.storage.has_pin) ? shadow_config.storage.pin : NULL;
}

/*
 * storage_get_mnemonic() - Get mnemonic from flash
 *
 * INPUT
 *     none
 * OUTPUT
 *     mnemonic from storage
 *
 */
const char *storage_get_mnemonic(void)
{
    return shadow_config.storage.mnemonic;
}

/*
 * storage_get_node() - Get HDNode
 *
 * INPUT
 *     none
 * OUTPUT
 *     HDNode from storage
 */
HDNodeType *storage_get_node(void)
{
    return &shadow_config.storage.node;
}

#endif
