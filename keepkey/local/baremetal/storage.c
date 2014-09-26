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

#include <string.h>
#include <stdint.h>

#include <libopencm3/stm32/flash.h>

#include <crypto.h>
#include <interface.h>
#include <keepkey_board.h>

#include "trezor.h"
#include "util.h"
#include "memory.h"
#include "storage.h"
#include "debug.h"
#include "protect.h"


/*
 storage layout:

 offset | type/length |  description
--------+-------------+-------------------------------
 0x0000 |  4 bytes    |  magic = 'stor'
 0x0004 |  12 bytes   |  uuid
 0x0010 |  ?          |  Storage structure
 */


/*
 * Specify the length of the uuid binary string
 */ 
#define STORAGE_UUID_LEN 12

/*
 * Length of the uuid binary converted to readable ASCII.
 */
#define STORAGE_UUID_STR_LEN 25

#define META_MAGIC (uint32_t)('stor')

/*
 * Flash metadata structure which will contains unique identifier
 * information that spans device resets.
 */
typedef struct
{
    uint32_t magic;  
    uint8_t uuid[STORAGE_UUID_LEN];
    char uuid_str[STORAGE_UUID_STR_LEN];
} Metadata;

/*
 * Config flash overlay structure.
 *
 * TODO: There needs to be a meta version as well.  This is not present in the
 * current Trezor code.
 */
typedef struct 
{
    Metadata meta;
    Storage storage;
} ConfigFlash;

ConfigFlash* real_config = (ConfigFlash*)FLASH_CONFIG_START;
ConfigFlash shadow_config;

static bool   sessionRootNodeCached;
static HDNode sessionRootNode;

static bool sessionPassphraseCached;
static char sessionPassphrase[51];

#define STORAGE_VERSION 1

bool storage_from_flash(uint32_t version)
{
    switch (version) {
        case 1:
            memcpy(&shadow_config, real_config, sizeof(shadow_config));
            break;
        default:
            return false;
    }
    shadow_config.storage.version = STORAGE_VERSION;
    return true;
}

void storage_init(void)
{
    storage_reset();

    //TODO: Add checksum functionality to config store.
    // if magic is ok
    if (real_config->meta.magic == META_MAGIC &&
        storage_from_flash(real_config->storage.version))
    {
        storage_commit();
    } else {
        /*
         *  Handle unknown invalid storage config here.
         */
        shadow_config.meta.magic = META_MAGIC;
        storage_reset_uuid();
        storage_commit();
    }
}

void storage_reset_uuid(void)
{
    // set random uuid
    random_buffer(shadow_config.meta.uuid, sizeof(shadow_config.meta.uuid));
    data2hex(shadow_config.meta.uuid, sizeof(shadow_config.meta.uuid), shadow_config.meta.uuid_str);
}

void storage_reset(void)
{
    // reset storage struct
    memset(&shadow_config.storage, 0, sizeof(shadow_config.storage));
    shadow_config.storage.version = STORAGE_VERSION;
    sessionRootNodeCached = false;   memset(&sessionRootNode, 0, sizeof(sessionRootNode));
    sessionPassphraseCached = false; memset(&sessionPassphrase, 0, sizeof(sessionPassphrase));
}

/**
 * Blow away the flash config storage, and reapply the meta configuration settings.
 */
void storage_commit()
{
    int i;
    uint32_t *w;

    flash_unlock();

    flash_erase(FLASH_CONFIG);
    flash_write(FLASH_CONFIG, 0, sizeof(shadow_config), (uint8_t*)&shadow_config);

    flash_lock();
}

void storage_commit_with_tick(void (*tick)())
{
    int i;
    uint32_t *w;

    flash_unlock();

    flash_erase_with_tick(FLASH_CONFIG, tick);
    flash_write_with_tick(FLASH_CONFIG, 0, sizeof(shadow_config), (uint8_t*)&shadow_config, tick);

    flash_lock();
}

void storage_loadDevice(LoadDevice *msg)
{
    storage_reset();

    if (msg->has_passphrase_protection) {
        shadow_config.storage.has_passphrase_protection = true;
        shadow_config.storage.passphrase_protection = msg->passphrase_protection;
    } else {
        shadow_config.storage.has_passphrase_protection = false;
    }

    if (msg->has_node) {
        shadow_config.storage.has_node = true;
        shadow_config.storage.has_mnemonic = false;
        memcpy(&shadow_config.storage.node, &(msg->node), sizeof(HDNodeType));
        sessionRootNodeCached = false;
        memset(&sessionRootNode, 0, sizeof(sessionRootNode));
    } else if (msg->has_mnemonic) {
        shadow_config.storage.has_mnemonic = true;
        shadow_config.storage.has_node = false;
        strlcpy(shadow_config.storage.mnemonic, msg->mnemonic, sizeof(shadow_config.storage.mnemonic));
        sessionRootNodeCached = false;
        memset(&sessionRootNode, 0, sizeof(sessionRootNode));
    }

    if (msg->has_language) {
        storage_setLanguage(msg->language);
    }

    if (msg->has_label) {
        storage_setLabel(msg->label);
    }
}

void storage_setLabel(const char *label)
{
    if (!label) return;
    shadow_config.storage.has_label = true;
    strlcpy(shadow_config.storage.label, label, sizeof(shadow_config.storage.label));
}

void storage_setLanguage(const char *lang)
{
    if (!lang) return;
    // sanity check
    if (strcmp(lang, "english") == 0) {
        shadow_config.storage.has_language = true;
        strlcpy(shadow_config.storage.language, lang, sizeof(shadow_config.storage.language));
    }
}

void get_root_node_callback(uint32_t iter, uint32_t total)
{
    static uint8_t i;
    layout_standard_notification("Waking up", "Building root node");
    display_refresh();
}

bool storage_getRootNode(HDNode *node)
{
    // root node is properly cached
    if (sessionRootNodeCached) {
        memcpy(node, &sessionRootNode, sizeof(HDNode));
        return true;
    }

    // if storage has node, decrypt and use it
    if (real_config->storage.has_node) {
        if (!protectPassphrase()) {
            return false;
        }

        hdnode_from_xprv(real_config->storage.node.depth, 
                         real_config->storage.node.fingerprint, 
                         real_config->storage.node.child_num, 
                         real_config->storage.node.chain_code.bytes, 
                         real_config->storage.node.private_key.bytes, 
                         &sessionRootNode);

        if (real_config->storage.has_passphrase_protection > 0) {
            // decrypt hd node
            aes_ctx ctx;
            aes_enc_key((const uint8_t *)sessionPassphrase, strlen(sessionPassphrase), &ctx);
            aes_enc_blk(sessionRootNode.chain_code, sessionRootNode.chain_code, &ctx);
            aes_enc_blk(sessionRootNode.chain_code + 16, sessionRootNode.chain_code + 16, &ctx);
            aes_enc_blk(sessionRootNode.private_key, sessionRootNode.private_key, &ctx);
            aes_enc_blk(sessionRootNode.private_key + 16, sessionRootNode.private_key + 16, &ctx);
        }
        memcpy(node, &sessionRootNode, sizeof(HDNode));
        sessionRootNodeCached = true;
        return true;
    }

    // if storage has mnemonic, convert it to node and use it
    if (real_config->storage.has_mnemonic) {
        if (!protectPassphrase()) {
            return false;
        }
        uint8_t seed[64];
        layout_standard_notification("Waking up","");
        display_refresh();
        mnemonic_to_seed(real_config->storage.mnemonic, sessionPassphrase, seed, get_root_node_callback); // BIP-0039
        hdnode_from_seed(seed, sizeof(seed), &sessionRootNode);
        memcpy(node, &sessionRootNode, sizeof(HDNode));
        sessionRootNodeCached = true;
        return true;
    }

    return false;
}

const char *storage_getLabel(void)
{
    return real_config->storage.has_label ? real_config->storage.label : NULL;
}

const char *storage_getLanguage(void)
{
    return real_config->storage.has_language ? real_config->storage.language : NULL;
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

bool storage_isInitialized(void)
{
	return real_config->storage.has_node || real_config->storage.has_mnemonic;
}

const char* storage_get_uuid_str(void)
{
    return real_config->meta.uuid_str;
}

const char* storage_get_language(void)
{
    if(real_config->storage.has_language)
    {
        return real_config->storage.language;
    } else {
        return NULL;
    }
}

const char* storage_get_label(void)
{
    if(real_config->storage.has_label)
    {
        return real_config->storage.label;
    } else {
        return NULL;
    }
}

bool storage_get_passphrase_protected(void)
{
    if(real_config->storage.has_passphrase_protection)
    {
        return real_config->storage.passphrase_protection;
    } else {
        return false;
    }
}

void storage_set_passphrase_protected(bool p)
{
    shadow_config.storage.has_passphrase_protection = true;
    shadow_config.storage.passphrase_protection = p;
}

void storage_set_mnemonic_from_words(const char* words[], unsigned int num_words)
{
    memset(shadow_config.storage.mnemonic, 0, sizeof(shadow_config.storage.mnemonic));

    for(unsigned int i=0; i < num_words; i++)
    {
        if(i == 1)
        {
            strlcat(shadow_config.storage.mnemonic, " ", sizeof(shadow_config.storage.mnemonic));
        }
        strlcat(shadow_config.storage.mnemonic, words[i], sizeof(shadow_config.storage.mnemonic));
    }

    shadow_config.storage.has_mnemonic = true;
}

void storage_set_mnemonic(const char* m)
{
    memset(shadow_config.storage.mnemonic, 0, sizeof(shadow_config.storage.mnemonic));
    strlcpy(shadow_config.storage.mnemonic, m, sizeof(shadow_config.storage.mnemonic));
    shadow_config.storage.has_mnemonic = true;
}

const char* storage_get_mnemonic(void)
{
    return real_config->storage.mnemonic;
}
