/*
 * This file is part of the TREZOR project.
 *
 * Copyright (C) 2022 markrypto <cryptoakorn@gmail.com>
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

#include "hwcrypto/crypto/bip32.h"
#include "keepkey/board/memory.h"
#include "keepkey/firmware/authenticator.h"

#define STORAGE_VERSION \
  17 /* Must add case fallthrough in storage_fromFlash after increment*/
#define STORAGE_RETRIES 3

#define RANDOM_SALT_LEN 32

#define STORAGE_DEFAULT_SCREENSAVER_TIMEOUT (10U * 60U * 1000U) /* 10 minutes \
                                                                 */
#define STORAGE_MIN_SCREENSAVER_TIMEOUT (30U * 1000U)           /* 30 seconds */

/// \brief Validate storage content and copy data to shadow memory.
void storage_init(void);

/// \brief Reset configuration UUID with random numbers.
void storage_resetUuid(void);

/// \brief Clear configuration.
void storage_reset(void);

/// \brief Clear storage.
void storage_wipe(void);

/// \brief Clear storage key and storage key fingerprint.
void storage_clearKeys(void);

/// \brief Reset session states.
/// \param clear_pin whether to clear the pin as well.
void session_clear(bool clear_pin);

/// \brief Write content of configuration in shadow memory to storage partion
///        in flash.
void storage_commit(void);

/// \brief Load configuration data from usb message to shadow memory
typedef struct _LoadDevice LoadDevice;
void storage_loadDevice(LoadDevice *msg);

/// \brief Get the Root Node of the device.
/// \param node[out]  The Root Node.
/// \param curve[in]  ECDSA curve to use.
/// \param usePassphrase[in]  Whether the seed uses a passphrase.
/// \return true iff the root node was found.
bool storage_getRootNode(const char *curve, bool usePassphrase, HDNode *node);

/// \brief Fetch the node used for U2F signing.
/// \returns true iff retrieval was successful.
bool storage_getU2FRoot(HDNode *node);

/// \brief Increment and return the next value for the U2F counter.
uint32_t storage_nextU2FCounter(void);

/// \brief Assign a new value for the U2F Counter.
void storage_setU2FCounter(uint32_t u2f_counter);

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

/// \brief Validate wipe code.
/// \return true iff the privided wipe code is correct.
bool storage_isWipeCodeCorrect(const char *wipe_code);

bool storage_hasPin(void);
void storage_setPin(const char *pin);
void session_cachePin(const char *pin);
bool session_isPinCached(void);
bool storage_hasWipeCode(void);
void storage_setWipeCode(const char *wipe_code);
void storage_resetPinFails(void);
void storage_increasePinFails(void);
uint32_t storage_getPinFails(void);

bool storage_isInitialized(void);

bool storage_noBackup(void);
void storage_setNoBackup(void);

const char *storage_getUuidStr(void);

bool storage_getPassphraseProtected(void);
void storage_setPassphraseProtected(bool passphrase);
void session_cachePassphrase(const char *passphrase);
bool session_isPassphraseCached(void);

/// \brief Set config mnemonic in shadow memory from words.
void storage_setMnemonicFromWords(const char (*words)[12],
                                  unsigned int num_words);

/// \brief Set config mnemonic from a recovery sentence.
void storage_setMnemonic(const char *mnemonic);

/// \brief Get mnemonic from shadow memory
const char *storage_getShadowMnemonic(void);

/// \returns true iff storage is unlocked, and contains the provided mnemonic.
bool storage_containsMnemonic(const char *mnemonic);

/// \returns true iff the private key stored on device was imported.
bool storage_getImported(void);

/// \brief marks the private key stored on the device as imported/not.
void storage_setImported(bool val);

/// \brief Get active storage location..
Allocation storage_getLocation(void);

typedef struct _PolicyType PolicyType;

/// \brief Assign policy by name.
/// \returns true iff assignment was successful.
bool storage_setPolicy(const char *policy_name, bool enabled);

/// \brief Copy out all the policies in storage
/// \param policies[out]  Where to write the policies.
void storage_getPolicies(PolicyType *policies);

/// \brief Status of policy in storage
bool storage_isPolicyEnabled(const char *policy_name);

uint32_t storage_getAutoLockDelayMs(void);
void storage_setAutoLockDelayMs(uint32_t auto_lock_delay_ms);

bool storage_getAuthData(authType *returnData);
void storage_setAuthData(authType *setData);
void storage_wipeAuthData(void);

#ifdef DEBUG_LINK
typedef struct _HDNodeType HDNodeType;
typedef struct _StorageHDNode StorageHDNode;

/// \returns true iff the device has a mnemonic in storage.
bool storage_hasMnemonic(void);

/// \returns true iff the active storage has a HDNode.
bool storage_hasNode(void);

const char *storage_getPin(void);
const char *storage_getMnemonic(void);
HDNode *storage_getNode(void);
void storage_dumpNode(HDNodeType *dst, const HDNode *src);
#endif

#endif
