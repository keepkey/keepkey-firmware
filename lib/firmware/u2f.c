/*
 * This file is part of the TREZOR project, https://trezor.io/
 *
 * Copyright (C) 2015 Mark Bryars <mbryars@google.com>
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

#include "keepkey/board/u2f.h"

#include "storage.h"
#include "u2f_knownapps.h"

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/timer.h"
#include "keepkey/board/u2f_hid.h"
#include "keepkey/board/u2f_keys.h"
#include "keepkey/board/u2f_types.h"
#include "keepkey/board/usb_driver.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/firmware/util.h"
#include "trezor/crypto/bip39.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/hmac.h"
#include "trezor/crypto/nist256p1.h"
#include "trezor/crypto/rand.h"

#include <stdio.h>
#include <string.h>

#define debugLog(L, B, T) do{}while(0)
#define debugInt(I) do{}while(0)

#define U2F_PUBKEY_LEN 65

typedef struct {
	uint8_t reserved;
	uint8_t appId[U2F_APPID_SIZE];
	uint8_t chal[U2F_CHAL_SIZE];
	uint8_t keyHandle[KEY_HANDLE_LEN];
	uint8_t pubKey[U2F_PUBKEY_LEN];
} U2F_REGISTER_SIG_STR;

typedef struct {
	uint8_t appId[U2F_APPID_SIZE];
	uint8_t flags;
	uint8_t ctr[4];
	uint8_t chal[U2F_CHAL_SIZE];
} U2F_AUTHENTICATE_SIG_STR;

const char *words_from_data(const uint8_t *data, int len)
{
	if (len > 32)
		return NULL;

	int mlen = len * 3 / 4;
	static char mnemo[24 * 10];

	const char *const *wordlist = mnemonic_wordlist();

	int i, j, idx;
	char *p = mnemo;
	for (i = 0; i < mlen; i++) {
		idx = 0;
		for (j = 0; j < 11; j++) {
			idx <<= 1;
			idx += (data[(i * 11 + j) / 8] & (1 << (7 - ((i * 11 + j) % 8)))) > 0;
		}
		strcpy(p, wordlist[idx]);
		p += strlen(wordlist[idx]);
		*p = (i < mlen - 1) ? ' ' : 0;
		p++;
	}

	return mnemo;
}

static bool getReadableAppId(const uint8_t appid[U2F_APPID_SIZE], const char **appname) {
	for (unsigned int i = 0; i < sizeof(u2f_well_known)/sizeof(U2FWellKnown); i++) {
		if (memcmp(appid, u2f_well_known[i].appid, U2F_APPID_SIZE) == 0) {
			*appname = u2f_well_known[i].appname;
			return true;
		}
	}

	// Otherwise use the mnemonic wordlist to invent some human-readable
	// identifier of the first 48 bits.
	*appname = words_from_data(appid, 6);
	return false;
}

static const HDNode *getDerivedNode(uint32_t *address_n, size_t address_n_count)
{
	static CONFIDENTIAL HDNode node;
	if (!storage_getU2FRoot(&node)) {
		layoutHome();
		debugLog(0, "", "ERR: Device not init");
		return 0;
	}
	if (!address_n || address_n_count == 0) {
		return &node;
	}
	for (size_t i = 0; i < address_n_count; i++) {
		if (hdnode_private_ckd(&node, address_n[i]) == 0) {
			layoutHome();
			debugLog(0, "", "ERR: Derive private failed");
			return 0;
		}
	}
	return &node;
}

static const HDNode *generateKeyHandle(const uint8_t app_id[], uint8_t key_handle[])
{
	uint8_t keybase[U2F_APPID_SIZE + KEY_PATH_LEN];

	// Derivation path is m/U2F'/r'/r'/r'/r'/r'/r'/r'/r'
	uint32_t key_path[KEY_PATH_ENTRIES];
	for (uint32_t i = 0; i < KEY_PATH_ENTRIES; i++) {
		// high bit for hardened keys
		key_path[i]= 0x80000000 | random32();
	}

	// First half of keyhandle is key_path
	memcpy(key_handle, key_path, KEY_PATH_LEN);

	// prepare keypair from /random data
	const HDNode *node = getDerivedNode(key_path, KEY_PATH_ENTRIES);
	if (!node)
		return NULL;

	// For second half of keyhandle
	// Signature of app_id and random data
	memcpy(&keybase[0], app_id, U2F_APPID_SIZE);
	memcpy(&keybase[U2F_APPID_SIZE], key_handle, KEY_PATH_LEN);
	hmac_sha256(node->private_key, sizeof(node->private_key),
	            keybase, sizeof(keybase), &key_handle[KEY_PATH_LEN]);

	// Done!
	return node;
}

static const HDNode *validateKeyHandle(const uint8_t app_id[], const uint8_t key_handle[])
{
	uint32_t key_path[KEY_PATH_ENTRIES];
	memcpy(key_path, key_handle, KEY_PATH_LEN);
	for (unsigned int i = 0; i < KEY_PATH_ENTRIES; i++) {
		// check high bit for hardened keys
		if (! (key_path[i] & 0x80000000)) {
			return NULL;
		}
	}

	const HDNode *node = getDerivedNode(key_path, KEY_PATH_ENTRIES);
	if (!node)
		return NULL;

	uint8_t keybase[U2F_APPID_SIZE + KEY_PATH_LEN];
	memcpy(&keybase[0], app_id, U2F_APPID_SIZE);
	memcpy(&keybase[U2F_APPID_SIZE], key_handle, KEY_PATH_LEN);


	uint8_t hmac[SHA256_DIGEST_LENGTH];
	hmac_sha256(node->private_key, sizeof(node->private_key),
	            keybase, sizeof(keybase), hmac);

	if (memcmp(&key_handle[KEY_PATH_LEN], hmac, SHA256_DIGEST_LENGTH) != 0)
		return NULL;

	// Done!
	return node;
}

void u2f_do_register(const U2F_REGISTER_REQ *req) {
	if (!storage_isInitialized()) {
		layout_warning_static("Cannot register u2f: not initialized");
		send_u2f_error(U2F_SW_CONDITIONS_NOT_SATISFIED);
		delay_ms(1000);
		return;
	}

	// TODO: dialog timeout
	if (0 == memcmp(req->appId, BOGUS_APPID, U2F_APPID_SIZE)) {
		(void)review_without_button_request("Register", "Another U2F device was used to register in this application.");
	} else {
		const char *appname = "";
		(void)review_without_button_request("Register",
		                                    getReadableAppId(req->appId, &appname)
		                                        ? "Enroll with %s?"
		                                        : "Do you want to enroll this U2F application?\n\n%s",
		                                    appname);
	}
	layoutHome();

	uint8_t data[sizeof(U2F_REGISTER_RESP) + 2];
	U2F_REGISTER_RESP *resp = (U2F_REGISTER_RESP *)&data;
	memset(data, 0, sizeof(data));

	resp->registerId = U2F_REGISTER_ID;
	resp->keyHandleLen = KEY_HANDLE_LEN;
	// Generate keypair for this appId
	const HDNode *node =
	    generateKeyHandle(req->appId, (uint8_t*)&resp->keyHandleCertSig);

	if (!node) {
		debugLog(0, "", "getDerivedNode Fail");
		send_u2f_error(U2F_SW_WRONG_DATA); // error:bad key handle
		return;
	}

	ecdsa_get_public_key65(node->curve->params, node->private_key,
	                       (uint8_t *)&resp->pubKey);

	memcpy(resp->keyHandleCertSig + resp->keyHandleLen,
	       U2F_ATT_CERT, sizeof(U2F_ATT_CERT));

	uint8_t sig[64];
	U2F_REGISTER_SIG_STR sig_base;
	sig_base.reserved = 0;
	memcpy(sig_base.appId, req->appId, U2F_APPID_SIZE);
	memcpy(sig_base.chal, req->chal, U2F_CHAL_SIZE);
	memcpy(sig_base.keyHandle, &resp->keyHandleCertSig, KEY_HANDLE_LEN);
	memcpy(sig_base.pubKey, &resp->pubKey, U2F_PUBKEY_LEN);
	if (ecdsa_sign(&nist256p1, HASHER_SHA2, U2F_ATT_PRIV_KEY, (uint8_t *)&sig_base, sizeof(sig_base), sig, NULL, NULL) != 0) {
		send_u2f_error(U2F_SW_WRONG_DATA);
		return;
	}

	// Where to write the signature in the response
	uint8_t *resp_sig = resp->keyHandleCertSig +
	    resp->keyHandleLen + sizeof(U2F_ATT_CERT);
	// Convert to der for the response
	const uint8_t sig_len = ecdsa_sig_to_der(sig, resp_sig);

	// Append success bytes
	memcpy(resp->keyHandleCertSig + resp->keyHandleLen +
	       sizeof(U2F_ATT_CERT) + sig_len,
	       "\x90\x00", 2);

	int l = 1 /* registerId */ + U2F_PUBKEY_LEN +
	    1 /* keyhandleLen */ + resp->keyHandleLen +
	    sizeof(U2F_ATT_CERT) + sig_len + 2;

	send_u2f_msg(data, l);
	return;
}

void u2f_do_auth(const U2F_AUTHENTICATE_REQ *req) {
	if (!storage_isInitialized()) {
		layout_warning_static("Cannot authenticate u2f: not initialized");
		send_u2f_error(U2F_SW_CONDITIONS_NOT_SATISFIED);
		delay_ms(1000);
		return;
	}

	const HDNode *node = validateKeyHandle(req->appId, req->keyHandle);

	if (!node) {
		debugLog(0, "", "u2f auth - bad keyhandle len");
		send_u2f_error(U2F_SW_WRONG_DATA); // error:bad key handle
		return;
	}

	// TODO: dialog timeout
	const char *appname = "";
	(void)review_without_button_request("Authenticate",
	                                    getReadableAppId(req->appId, &appname)
	                                        ? "Log in to %s?"
	                                        : "Do you want to log in?\n\n%s",
	                                    appname);
	layoutHome();

	uint8_t buf[sizeof(U2F_AUTHENTICATE_RESP) + 2];
	U2F_AUTHENTICATE_RESP *resp = (U2F_AUTHENTICATE_RESP *)&buf;

	const uint32_t ctr = storage_nextU2FCounter();
	resp->flags = U2F_AUTH_FLAG_TUP;
	resp->ctr[0] = ctr >> 24 & 0xff;
	resp->ctr[1] = ctr >> 16 & 0xff;
	resp->ctr[2] = ctr >> 8 & 0xff;
	resp->ctr[3] = ctr & 0xff;

	// Build and sign response
	U2F_AUTHENTICATE_SIG_STR sig_base;
	uint8_t sig[64];
	memcpy(sig_base.appId, req->appId, U2F_APPID_SIZE);
	sig_base.flags = resp->flags;
	memcpy(sig_base.ctr, resp->ctr, 4);
	memcpy(sig_base.chal, req->chal, U2F_CHAL_SIZE);
	if (ecdsa_sign(&nist256p1, HASHER_SHA2, node->private_key, (uint8_t *)&sig_base, sizeof(sig_base), sig, NULL, NULL) != 0) {
		send_u2f_error(U2F_SW_WRONG_DATA);
		return;
	}

	// Copy DER encoded signature into response
	const uint8_t sig_len = ecdsa_sig_to_der(sig, resp->sig);

	// Append OK
	memcpy(buf + sizeof(U2F_AUTHENTICATE_RESP) -
	       U2F_MAX_EC_SIG_SIZE + sig_len,
	       "\x90\x00", 2);
	send_u2f_msg(buf, sizeof(U2F_AUTHENTICATE_RESP) -
	             U2F_MAX_EC_SIG_SIZE + sig_len + 2);
}

