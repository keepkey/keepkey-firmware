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

/* === Includes ============================================================ */

#include <bip32.h>
#include <memory.h>
#include <types.pb.h>
#include <storage.pb.h>
#include <messages.pb.h>

/* === Defines ============================================================= */

#define STORAGE_VERSION 2
#define PBKDF2_HMAC_SHA512_SALT "TREZORHD"

#define STORAGE_RETRIES 3

/* === Functions =========================================================== */

void storage_init(void);
void storage_reset_uuid(void);
void storage_reset(void);
void session_clear(bool clear_pin);
void storage_commit(void);

void storage_load_device(LoadDevice *msg);

bool storage_get_root_node(HDNode *node);

void storage_set_label(const char *label);
const char *storage_get_label(void);

void storage_set_language(const char *lang);
const char *storage_get_language(void);

bool storage_is_pin_correct(const char *pin);
bool storage_has_pin(void);
void storage_set_pin(const char *pin);
const char *storage_get_pin(void);
void session_cache_pin(const char *pin);
bool session_is_pin_cached(void);
void storage_reset_pin_fails(void);
void storage_increase_pin_fails(void);
uint32_t storage_get_pin_fails(void);

bool storage_is_initialized(void);

const char *storage_get_uuid_str(void);

bool storage_get_passphrase_protected(void);
void storage_set_passphrase_protected(bool passphrase);
void session_cache_passphrase(const char *passphrase);
bool session_is_passphrase_cached(void);

void storage_set_mnemonic_from_words(const char (*words)[12], unsigned int num_words);
void storage_set_mnemonic(const char *mnemonic);
bool storage_has_mnemonic(void);

const char *storage_get_mnemonic(void);
const char *storage_get_shadow_mnemonic(void);

bool storage_get_imported(void);

bool storage_has_node(void);
HDNodeType *storage_get_node(void);

Allocation get_storage_location(void);

#endif
