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

#ifndef STORAGE_H
#define STORAGE_H

#include "trezor/crypto/bip32.h"
#include "keepkey/board/memory.h"
#include "keepkey/firmware/storagepb.h"

#define STORAGE_VERSION 10 /* Must add case fallthrough in storage_fromFlash after increment*/
#define STORAGE_RETRIES 3

typedef struct _ConfigFlash ConfigFlash;

typedef struct _HDNodeType HDNodeType;
typedef struct _LoadDevice LoadDevice;
typedef struct _PolicyType PolicyType;

typedef struct _Storage Storage;
typedef struct _StorageHDNode StorageHDNode;
typedef struct _StoragePolicy StoragePolicy;

void storage_init(void);
void storage_resetUuid(void);
void storage_reset(void);
void session_clear(bool clear_pin);
void storage_commit(void);

void storage_dumpNode(HDNodeType *dst, const StorageHDNode *src);
void storage_loadDevice(LoadDevice *msg);

const uint8_t *storage_getSeed(ConfigFlash *cfg, bool usePassphrase);
bool storage_getRootNode(HDNode *node, const char *curve, bool usePassphrase);

void storage_setLabel(const char *label);
const char *storage_getLabel(void);

void storage_setLanguage(const char *lang);
const char *storage_getLanguage(void);

bool storage_isPinCorrect(const char *pin);
bool storage_hasPin(void);
void storage_setPin(const char *pin);
const char *storage_getPin(void);
void session_cache_pin(const char *pin);
bool session_is_pin_cached(void);
void storage_resetPinFails(void);
void storage_increasePinFails(void);
uint32_t storage_getPinFails(void);

bool storage_isInitialized(void);

const char *storage_getUuidStr(void);

bool storage_getPassphraseProtected(void);
void storage_setPassphraseProtected(bool passphrase);
void session_cache_passphrase(const char *passphrase);
bool session_is_passphrase_cached(void);

void storage_setMnemonicFromWords(const char (*words)[12], unsigned int num_words);
void storage_setMnemonic(const char *mnemonic);
bool storage_hasMnemonic(void);

const char *storage_getMnemonic(void);
const char *storage_getShadowMnemonic(void);

bool storage_getImported(void);

bool storage_hasNode(void);
StorageHDNode *storage_getNode(void);

Allocation get_storage_location(void);

bool storage_setPolicy(PolicyType *policy);
void storage_getPolicies(PolicyType *policies);
bool storage_isPolicyEnabled(char *policy_name);

#endif
