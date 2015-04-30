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
 *
 *          --------------------------------------------
 * March 12, 2015 - This file has been modified and adapted for KeepKey project.
 *
 */

#include <string.h>
#include <stdint.h>

#include <libopencm3/stm32/flash.h>

#include <bip39.h>
#include <aes.h>
#include <pbkdf2.h>
#include <interface.h>
#include <keepkey_board.h>
#include <pbkdf2.h>
#include <keepkey_flash.h>


#include "util.h"
#include "memory.h"
#include "storage.h"
#include "rng.h"
#include "passphrase_sm.h"
#include <fsm.h>


/* Static / Global variables */

/* shadow memory for configuration data in storage partition*/
ConfigFlash shadow_config;

static bool   sessionRootNodeCached;
static HDNode sessionRootNode;

static bool sessionPinCached;
static char sessionPin[17];

static bool sessionPassphraseCached;
static char sessionPassphrase[51];


/*
 * storage_from_flash() - copy configuration from storage partition in flash memory to shadow memory in RAM
 *
 * INPUT -
 *      storage version
 * OUTPUT -
 *      true/false status
 *
 */
static bool storage_from_flash(ConfigFlash *stor_config)
{
    /* load cofig values from active config node */
    switch(stor_config->storage.version)
    {
        case 1:
            memcpy(&shadow_config, stor_config, sizeof(shadow_config));
            break;

        default:
            return false;
    }

    shadow_config.storage.version = STORAGE_VERSION;
    return true;
}

/*
 * storage_init() - validate storage content and copy data to shadow memory
 *
 * INPUT - none
 * OUTPUT - none
 */
void storage_init(void)
{
    /* Init to start of storage partition */
    ConfigFlash *stor_config = (ConfigFlash *)FLASH_STORAGE_START;

    /* reset shadow configuration in RAM */
    storage_reset();

    /* verify storage partition is initialized */
    if(memcmp((void *)stor_config->meta.magic , STORAGE_MAGIC_STR, STORAGE_MAGIC_LEN) == 0)
    {
        /* clear out stor_config befor finding end config node */
        // load uuid to shadow memory
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
        /* keep storage area cleared */
        storage_reset_uuid();
        storage_commit();
    }
}

/*
 * storage_reset_uuid() - reset configuration uuid in RAM with random numbers
 *
 * INPUT - none
 * OUTPUT - none
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
 * storage_reset() - clear configuration in RAM
 *
 * INPUT -
 * OUTPUT -
 */
void storage_reset(void)
{
    // reset storage struct
    memset(&shadow_config.storage, 0, sizeof(shadow_config.storage));
    shadow_config.storage.version = STORAGE_VERSION;
    session_clear(true); // clear PIN as well
}

/*
 * session_clear() - reset session states
 *
 * INPUT -
 *     clear_pin - whether to clear pin or not
 * OUTPUT - none
 */
void session_clear(bool clear_pin)
{
    sessionRootNodeCached = false;   memset(&sessionRootNode, 0, sizeof(sessionRootNode));
    sessionPassphraseCached = false; memset(&sessionPassphrase, 0, sizeof(sessionPassphrase));

    if(clear_pin)
    {
        sessionPinCached = false;
    }
}

/*
 * storage_commit() - write content of configuration in shadow memory to
 *          storage partion in flash
 *
 * INPUT -
 *      Commit type
 * OUTPUT - none
 */
void storage_commit(void)
{
    memcpy((void *)&shadow_config, STORAGE_MAGIC_STR, STORAGE_MAGIC_LEN);
    flash_unlock();
    flash_erase_word(FLASH_STORAGE);

    if(flash_write_word(FLASH_STORAGE, 0, sizeof(shadow_config),
                        (uint8_t *)&shadow_config) == false)
    {
        flash_lock();
        layout_warning("Error Dectected.  Reboot Device!");

        do
        {
            animate();
            display_refresh();
        }
        while(1); /* Loop forever */
    }

    flash_lock();
}

/*
 * storage_loadDevice() - load configuration data from usb message to shadow memory
 *
 * INPUT -
 *      msg - usb message buffer
 * OUTPUT -
 *      none
 */
void storage_loadDevice(LoadDevice *msg)
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
        sessionRootNodeCached = false;
        memset(&sessionRootNode, 0, sizeof(sessionRootNode));
    }
    else if(msg->has_mnemonic)
    {
        shadow_config.storage.has_mnemonic = true;
        shadow_config.storage.has_node = false;
        strlcpy(shadow_config.storage.mnemonic, msg->mnemonic,
                sizeof(shadow_config.storage.mnemonic));
        sessionRootNodeCached = false;
        memset(&sessionRootNode, 0, sizeof(sessionRootNode));
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

/*
 * storage_setLabel() - set configuration label
 *
 * INPUT -
 *      *lebel - pointer to label
 * OUTPUT -
 *      none
 */
void storage_setLabel(const char *label)
{
    if(!label) { return; }

    shadow_config.storage.has_label = true;
    memset(shadow_config.storage.label, 0, sizeof(shadow_config.storage.label));
    strlcpy(shadow_config.storage.label, label, sizeof(shadow_config.storage.label));
}

/*
 * storage_setLanguage() - set configuration language
 *
 *  INPUT -
 *      *lang - pointer language
 * OUTPUT -
 *      none
 */
void storage_setLanguage(const char *lang)
{
    if(!lang) { return; }

    // sanity check
    if(strcmp(lang, "english") == 0)
    {
        shadow_config.storage.has_language = true;
        memset(shadow_config.storage.language, 0, sizeof(shadow_config.storage.language));
        strlcpy(shadow_config.storage.language, lang, sizeof(shadow_config.storage.language));
    }
}


/*
 * storage_is_pin_correct() - authenticate PIN
 *
 * INPUT
 *      *pin - pointer to PIN
 * OUTPUT
 *      true/false - status
 */
bool storage_is_pin_correct(const char *pin)
{
    return strcmp(shadow_config.storage.pin, pin) == 0;
}

/*
 * storage_has_pin() - get PIN state
 *
 * INPUT - none
 * OUTPUT -
 *      pin state
 */
bool storage_has_pin(void)
{
    return shadow_config.storage.has_pin && strlen(shadow_config.storage.pin) > 0;
}

/*
 * storage_set_pin() - save pin in shadow memory
 *
 * INPUT -
 *      *pin - pointer pin string
 * OUTPUT -
 *      none
 */
void storage_set_pin(const char *pin)
{
    if(pin && strlen(pin) > 0)
    {
        shadow_config.storage.has_pin = true;
        strlcpy(shadow_config.storage.pin, pin, sizeof(shadow_config.storage.pin));
    }
    else
    {
        shadow_config.storage.has_pin = false;
        memset(shadow_config.storage.pin, 0, sizeof(shadow_config.storage.pin));
    }

    sessionPinCached = false;
}

/*
 * storage_get_pin() - returns pin
 *
 * INPUT - none
 * OUTPUT -
 *      pin
 */
const char *storage_get_pin(void)
{
    return (shadow_config.storage.has_pin) ? shadow_config.storage.pin : NULL;
}

/*
 * session_cache_pin() - save pin in session cache
 *
 * INPUT
 *      *pin - pointer pin string
 * OUTPUT -
 *      none
 */
void session_cache_pin(const char *pin)
{
    strlcpy(sessionPin, pin, sizeof(sessionPin));
    sessionPinCached = true;
}

/*
 * session_is_pin_cached() - get state Pin cached in session
 *
 * INPUT - none
 * OUTPUT - none
 *
 */
bool session_is_pin_cached(void)
{
    return sessionPinCached && strcmp(sessionPin, shadow_config.storage.pin) == 0;
}

/*
 * storage_reset_pin_fails() - reset pin failure info in storage partition.
 *
 * INPUT - none
 * OUTPUT - none
 */
void storage_reset_pin_fails(void)
{
    /* only write to flash if there's a change in status */
    if(shadow_config.storage.has_pin_failed_attempts == true)
    {
        shadow_config.storage.has_pin_failed_attempts = false;
        shadow_config.storage.pin_failed_attempts = 0;
        storage_commit();
    }

}

/*
 * storage_increase_pin_fails() - update pin failed attempts in storage partition
 *
 * INPUT - none
 * OUTPUT - none
 */
void storage_increase_pin_fails(void)
{
    if(!shadow_config.storage.has_pin_failed_attempts)
    {
        shadow_config.storage.has_pin_failed_attempts = true;
        shadow_config.storage.pin_failed_attempts = 1;
    }
    else
    {
        shadow_config.storage.pin_failed_attempts++;
    }

    storage_commit();
}

/*
 * storage_get_pin_fails() - get number pin failed attempts
 *
 * INPUT - none
 * OUTPOUT -
 *      number of pin failed attempts
 */
uint32_t storage_get_pin_fails(void)
{
    return shadow_config.storage.has_pin_failed_attempts ?
           shadow_config.storage.pin_failed_attempts : 0;
}

/*
 * get_root_node_callback() -
 *
 * INPUT -
 *
 * OUTPUT
 *      none
 */
void get_root_node_callback(void)
{
    animating_progress_handler();
}

/*
 * storage_getRootNode() -
 *
 * INPUT -
 * OUTPUT -
 */
bool storage_getRootNode(HDNode *node)
{
    // root node is properly cached
    if(sessionRootNodeCached)
    {
        memcpy(node, &sessionRootNode, sizeof(HDNode));
        return true;
    }

    // if storage has node, decrypt and use it
    if(shadow_config.storage.has_node)
    {
        if(!passphrase_protect())
        {
            return false;
        }

        if(hdnode_from_xprv(shadow_config.storage.node.depth,
                            shadow_config.storage.node.fingerprint,
                            shadow_config.storage.node.child_num,
                            shadow_config.storage.node.chain_code.bytes,
                            shadow_config.storage.node.private_key.bytes,
                            &sessionRootNode) == 0)
        {
            return false;
        }

        if(shadow_config.storage.has_passphrase_protection &&
                shadow_config.storage.passphrase_protection && strlen(sessionPassphrase))
        {
            // decrypt hd node
            uint8_t secret[64];

            animating_progress_handler();

            pbkdf2_hmac_sha512((const uint8_t *)sessionPassphrase, strlen(sessionPassphrase),
                               (uint8_t *)"A!B@C#D$", 8, BIP39_PBKDF2_ROUNDS, secret, 64, get_root_node_callback);
            aes_decrypt_ctx ctx;
            aes_decrypt_key256(secret, &ctx);
            aes_cbc_decrypt(sessionRootNode.chain_code, sessionRootNode.chain_code, 32, secret + 32,
                            &ctx);
            aes_cbc_decrypt(sessionRootNode.private_key, sessionRootNode.private_key, 32, secret + 32,
                            &ctx);
        }

        memcpy(node, &sessionRootNode, sizeof(HDNode));
        sessionRootNodeCached = true;
        return true;
    }

    // if storage has mnemonic, convert it to node and use it
    if(shadow_config.storage.has_mnemonic)
    {
        layout_loading();

        if(!passphrase_protect())
        {
            return false;
        }

        uint8_t seed[64];

        animating_progress_handler();

        mnemonic_to_seed(shadow_config.storage.mnemonic, sessionPassphrase, seed,
                         get_root_node_callback); // BIP-0039

        if(hdnode_from_seed(seed, sizeof(seed), &sessionRootNode) == 0)
        {
            return false;
        }

        memcpy(node, &sessionRootNode, sizeof(HDNode));
        sessionRootNodeCached = true;
        return true;
    }

    return false;
}

/*
 * char *storage_getLanguage() - get configuration language
 *
 * INPUT - none
 * OUTPUT -
 *      pointer to language
 */
const char *storage_getLanguage(void)
{
    return shadow_config.storage.has_language ? shadow_config.storage.language : NULL;
}

/*
 * session_cachePassphrase() - set session passphrase
 *
 * INPUT -
 *      *passphrase - pointer to passphrase
 * OUTPUT -
 *      none
 */
void session_cachePassphrase(const char *passphrase)
{
    strlcpy(sessionPassphrase, passphrase, sizeof(sessionPassphrase));
    sessionPassphraseCached = true;
}

/*
 * session_isPassphraseCached() -
 *
 * INPUT - none
 * OUTPUT -
 *      Session Passphrase cache status
 */
bool session_isPassphraseCached(void)
{
    return sessionPassphraseCached;
}

/*
 * storage_isInitialized() - get configuration init status
 *
 * INPUT - none
 * OUTPUT -
 *      init status
 *
 *
 */
bool storage_isInitialized(void)
{
    return shadow_config.storage.has_node || shadow_config.storage.has_mnemonic;
}

/*
 * storage_get_uuid_str() - get uuid string
 *
 * INPUT - none
 * OUTPUT
 *      configuration UUID string
 */
const char *storage_get_uuid_str(void)
{
    return shadow_config.meta.uuid_str;
}

/*
 * storage_get_language() - get configuration language
 *
 * INPUT - none
 * OUTPUT
 *      pointer to config language
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
 * storage_get_label() - get config label
 *
 * INPUT - none
 * OUTPUT -
 *      pointer config label
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
 * storage_get_passphrase_protected() -  get passphrase protection status
 *
 * INPUT  - none
 * OUTPUT -
 *      passphrase protection status
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
 * storage_set_passphrase_protected() - set passphrase state
 *
 * INPUT -
 *      passphrase state
 * OUTPUT -
 *      none
 *
 */
void storage_set_passphrase_protected(bool p)
{
    shadow_config.storage.has_passphrase_protection = true;
    shadow_config.storage.passphrase_protection = p;
}

/*
 * storage_set_mnemonic_from_words() -  set config mnemonic in shadow memory from words
 *
 * INPUT
 *      pointer mnemonic words
 * OUTPUT -
 *      none
 */
void storage_set_mnemonic_from_words(const char (*words)[12], unsigned int word_count)
{
    strlcpy(shadow_config.storage.mnemonic, words[0], sizeof(shadow_config.storage.mnemonic));

    for(uint32_t i = 1; i < word_count; i++)
    {
        strlcat(shadow_config.storage.mnemonic, " ", sizeof(shadow_config.storage.mnemonic));
        strlcat(shadow_config.storage.mnemonic, words[i], sizeof(shadow_config.storage.mnemonic));
    }

    shadow_config.storage.has_mnemonic = true;
}

/*
 * storage_set_mnemonic() - set config mnemonic in shadow memory
 *
 * INPUT -
 *     pointer to storage mnemonic
 * OUTPUT -
 *     none
 *
 */
void storage_set_mnemonic(const char *m)
{
    memset(shadow_config.storage.mnemonic, 0, sizeof(shadow_config.storage.mnemonic));
    strlcpy(shadow_config.storage.mnemonic, m, sizeof(shadow_config.storage.mnemonic));
    shadow_config.storage.has_mnemonic = true;
}

/*
 * storage_has_mnemonic() - state of storage has_mnemonic
 *
 * INPUT - none
 * OUTPUT -
 *      true/false - status
 *
 */
bool storage_has_mnemonic(void)
{
    return shadow_config.storage.has_mnemonic;
}

/*
 * storage_get_mnemonic() - get state of config mnemonic from flash
 *
 * INPUT - none
 * OUTPUT -
 *      mnemonic array pointer in storage partition
 *
 */
const char *storage_get_mnemonic(void)
{
    return shadow_config.storage.mnemonic;
}

/*
 * storage_get_shadow_mnemonic() - get state of config mnemonic from shadow memory
 *
 * INPUT -  none
 * OUTPUT -
 *      mnemonic array pointer in ram
 */
const char *storage_get_shadow_mnemonic(void)
{
    return shadow_config.storage.mnemonic;
}

/*
 * storage_get_imported() - get state of config data from storage partition
 *
 * INPUT - none
 * OUTPUT -
 *      true/false - status
 */
bool storage_get_imported(void)
{
    return shadow_config.storage.has_imported && shadow_config.storage.imported;
}

/*
 * storage_has_node() - get state of storage has_node
 *
 * INPUT - none
 * OUTPUT -
 *      true/false - status
 */
bool storage_has_node(void)
{
    return shadow_config.storage.has_node;
}

/*
 * storage_get_node() - get state of storage node
 *
 * INPUT - none
 * OUTPUT -
 *      true/false - status
 */
HDNodeType *storage_get_node(void)
{
    return &shadow_config.storage.node;
}
