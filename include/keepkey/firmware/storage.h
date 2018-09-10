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

/// \brief Validate storage content and copy data to shadow memory.
void storage_init(void);

/// \brief Reset configuration UUID with random numbers.
void storage_resetUuid(void);
void storage_resetUuid_impl(ConfigFlash *cfg);

/// \brief Clear configuration.
void storage_reset(void);
void storage_reset_impl(ConfigFlash *cfg);

/// \brief Reset session states
/// \param clear_pin  Whether to clear the session pin.
void session_clear(bool clear_pin);

/// \brief Write content of configuration in shadow memory to storage partion
///        in flash.
void storage_commit(void);
void storage_commit_impl(ConfigFlash *cfg);

void storage_dumpNode(HDNodeType *dst, const StorageHDNode *src);

/// \brief Load configuration data from usb message to shadow memory
void storage_loadDevice(LoadDevice *msg);

/// \brief Get user private seed.
/// \returns NULL on error, otherwise \returns the private seed.
const uint8_t *storage_getSeed(const ConfigFlash *cfg, bool usePassphrase);

/// \brief Get the Root Node of the device.
/// \param node[out]  The Root Node.
/// \param curve[in]  ECDSA curve to use.
/// \param usePassphrase[in]  Whether the seed uses a passphrase.
/// \return true iff the root node was found.
bool storage_getRootNode(const char *curve, bool usePassphrase, HDNode *node);

/// \brief Set device label
void storage_setLabel(const char *label);

/// \brief Get device label
const char *storage_getLabel(void);

/// \brief Set device language.
void storage_setLanguage(const char *lang);

/// \brief Get device language.
const char *storage_getLanguage(void);

/// \brief Validate pin.
/// \return true iff the privided pin is correct.
bool storage_isPinCorrect(const char *pin);

bool storage_hasPin(void);
void storage_setPin(const char *pin);
void session_cachePin(const char *pin);
bool session_isPinCached(void);
void storage_resetPinFails(void);
void storage_increasePinFails(void);
uint32_t storage_getPinFails(void);

bool storage_isInitialized(void);

const char *storage_getUuidStr(void);

bool storage_getPassphraseProtected(void);
void storage_setPassphraseProtected(bool passphrase);
void session_cachePassphrase(const char *passphrase);
bool session_isPassphraseCached(void);

/// \brief Set config mnemonic in shadow memory from words.
void storage_setMnemonicFromWords(const char (*words)[12], unsigned int num_words);

/// \brief Set config mnemonic from a recovery sentence.
void storage_setMnemonic(const char *mnemonic);

/// \returns true iff the device has a mnemonic in storage.
bool storage_hasMnemonic(void);

/// \brief Get mnemonic from shadow memory
const char *storage_getShadowMnemonic(void);

/// \returns true iff the private key stored on device was imported.
bool storage_getImported(void);

/// \returns true iff the active storage has a HDNode.
bool storage_hasNode(void);

/// \brief Get active storage location..
Allocation storage_getLocation(void);

/// \brief Assign policy by name
bool storage_setPolicy(const PolicyType *policy);

/// \brief Copy out all the policies in storage
/// \param policies[out]  Where to write the policies.
void storage_getPolicies(PolicyType *policies);

/// \brief Status of policy in storage
bool storage_isPolicyEnabled(char *policy_name);

void storage_resetPolicies(ConfigFlash *cfg);
void storage_resetCache(ConfigFlash *cfg);

#ifdef DEBUG_LINK
const char *storage_getPin(void);
const char *storage_getMnemonic(void);
StorageHDNode *storage_getNode(void);
#endif

#endif
