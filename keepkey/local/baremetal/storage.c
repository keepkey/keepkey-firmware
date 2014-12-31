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

#include <bip39.h>
#include <aes.h>
#include <pbkdf2.h>
#include <interface.h>
#include <keepkey_board.h>
#include <pbkdf2.h>

#include "trezor.h"
#include "util.h"
#include "memory.h"
#include "storage.h"
#include "debug.h"
#include "rng.h"
#include "passphrase_sm.h"




ConfigFlash* real_config = (ConfigFlash*)FLASH_STORAGE_START;
ConfigFlash shadow_config;

static progress_handler_t progress_handler;

static bool   sessionRootNodeCached;
static HDNode sessionRootNode;

static bool sessionPinCached;
static char sessionPin[17];

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
	/* verify storage area is valid */
	if (memcmp((void *)FLASH_STORAGE_START, "stor", 4) == 0) {
		// load uuid
		memcpy(shadow_config.meta.uuid, (void *)(FLASH_STORAGE_START + 4), sizeof(shadow_config.meta.uuid));
		data2hex(shadow_config.meta.uuid, sizeof(shadow_config.meta.uuid), shadow_config.meta.uuid_str);
		// load storage struct
		uint32_t version = real_config->storage.version;
		if (version && version <= STORAGE_VERSION) {
			storage_from_flash(version);
		}
        /* New app with storage version changed!  update the storage space */
		if (version != STORAGE_VERSION) {
			storage_commit();
		}
	} else {
        /* keep storage area cleared */
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
    session_clear();
}

void session_clear(void)
{
	sessionRootNodeCached = false;   memset(&sessionRootNode, 0, sizeof(sessionRootNode));
	sessionPassphraseCached = false; memset(&sessionPassphrase, 0, sizeof(sessionPassphrase));
	sessionPinCached = false;        memset(&sessionPin, 0, sizeof(sessionPin));
}

/**
 * Blow away the flash config storage, and reapply the meta configuration settings.
 */
void storage_commit()
{
    int i;
    uint32_t *w;

    if(progress_handler)
    	(*progress_handler)();

    flash_unlock();

    flash_erase(FLASH_STORAGE);
    memcpy(&shadow_config.meta.magic, "stor", 4);

    if(progress_handler)
    	flash_write_with_progress(FLASH_STORAGE, 0, sizeof(shadow_config), (uint8_t*)&shadow_config, progress_handler);
    else
    	flash_write(FLASH_STORAGE, 0, sizeof(shadow_config), (uint8_t*)&shadow_config);

    flash_lock();
}

void storage_loadDevice(LoadDevice *msg)
{
    storage_reset();

    shadow_config.storage.has_imported = true;
    shadow_config.storage.imported = true;

    if (msg->has_pin > 0) {
    	storage_set_pin(msg->pin);
    }

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


bool storage_is_pin_correct(const char *pin)
{
    if(real_config->storage.has_pin)
    {
    	return strcmp(real_config->storage.pin, pin) == 0;
    } else {
    	return false;
    }
}

bool storage_has_pin(void)
{
	return real_config->storage.has_pin && strlen(real_config->storage.pin) > 0;
}

void storage_set_pin(const char *pin)
{
	if (pin && strlen(pin) > 0) {
		shadow_config.storage.has_pin = true;
		strlcpy(shadow_config.storage.pin, pin, sizeof(shadow_config.storage.pin));
	} else {
		shadow_config.storage.has_pin = false;
		shadow_config.storage.pin[0] = 0;
	}
	sessionPinCached = false;
}

void session_cache_pin(const char *pin)
{
	strlcpy(sessionPin, pin, sizeof(sessionPin));
	sessionPinCached = true;
}

bool session_is_pin_cached(void)
{
	return sessionPinCached && strcmp(sessionPin, real_config->storage.pin) == 0;
}

void storage_reset_pin_fails(void)
{
	shadow_config.storage.has_pin_failed_attempts = true;
	shadow_config.storage.pin_failed_attempts = 0;
	storage_commit();
}

void storage_increase_pin_fails(void)
{
	if (!real_config->storage.has_pin_failed_attempts) {
		shadow_config.storage.has_pin_failed_attempts = true;
		shadow_config.storage.pin_failed_attempts = 1;
	} else {
		shadow_config.storage.pin_failed_attempts++;
	}
	storage_commit();
}

uint32_t storage_get_pin_fails(void)
{
	return real_config->storage.has_pin_failed_attempts ? real_config->storage.pin_failed_attempts : 0;
}

void get_root_node_callback(uint32_t iter, uint32_t total)
{
    static uint8_t i;
    layout_standard_notification("Waking up", "Building root node", NOTIFICATION_INFO);
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
        if (!passphrase_protect()) {
            return false;
        }

        if (hdnode_from_xprv(real_config->storage.node.depth,
        		real_config->storage.node.fingerprint,
				real_config->storage.node.child_num,
				real_config->storage.node.chain_code.bytes,
				real_config->storage.node.private_key.bytes,
				&sessionRootNode) == 0)
        {
			return false;
		}

        if (real_config->storage.has_passphrase_protection && real_config->storage.passphrase_protection && strlen(sessionPassphrase)) {
        	// decrypt hd node
			uint8_t secret[64];

			layout_standard_notification("Waking up","", NOTIFICATION_INFO);
			display_refresh();

			pbkdf2_hmac_sha512((const uint8_t *)sessionPassphrase, strlen(sessionPassphrase), (uint8_t *)"TREZORHD", 8, BIP39_PBKDF2_ROUNDS, secret, 64, get_root_node_callback);
			aes_decrypt_ctx ctx;
			aes_decrypt_key256(secret, &ctx);
			aes_cbc_decrypt(sessionRootNode.chain_code, sessionRootNode.chain_code, 32, secret + 32, &ctx);
			aes_cbc_decrypt(sessionRootNode.private_key, sessionRootNode.private_key, 32, secret + 32, &ctx);
        }
        memcpy(node, &sessionRootNode, sizeof(HDNode));
        sessionRootNodeCached = true;
        return true;
    }

    // if storage has mnemonic, convert it to node and use it
    if (real_config->storage.has_mnemonic) {
        if (!passphrase_protect()) {
            return false;
        }
        uint8_t seed[64];

        layout_standard_notification("Waking up","", NOTIFICATION_INFO);
        display_refresh();

		mnemonic_to_seed(real_config->storage.mnemonic, sessionPassphrase, seed, get_root_node_callback); // BIP-0039
		if (hdnode_from_seed(seed, sizeof(seed), &sessionRootNode) == 0) {
			return false;
		}
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

const char* storage_get_shadow_mnemonic(void)
{
	return shadow_config.storage.mnemonic;
}

void storage_set_progress_handler(progress_handler_t handler)
{
	progress_handler = handler;
}
