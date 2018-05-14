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
#include "crypto.h"
#include "sha2.h"
#include "pbkdf2.h"
#include "aes.h"
#include "hmac.h"
#include "bip32.h"
#include "layout.h"
#include "curves.h"
#include "secp256k1.h"
#include "coins.h"
#include "macros.h"

/* === Functions =========================================================== */

uint32_t ser_length(uint32_t len, uint8_t *out)
{
	if (len < 253) {
		out[0] = len & 0xFF;
		return 1;
	}
	if (len < 0x10000) {
		out[0] = 253;
		out[1] = len & 0xFF;
		out[2] = (len >> 8) & 0xFF;
		return 3;
	}
	out[0] = 254;
	out[1] = len & 0xFF;
	out[2] = (len >> 8) & 0xFF;
	out[3] = (len >> 16) & 0xFF;
	out[4] = (len >> 24) & 0xFF;
	return 5;
}

uint32_t ser_length_hash(SHA256_CTX *ctx, uint32_t len)
{
	if (len < 253) {
		sha256_Update(ctx, (const uint8_t *)&len, 1);
		return 1;
	}
	if (len < 0x10000) {
		uint8_t d = 253;
		sha256_Update(ctx, &d, 1);
		sha256_Update(ctx, (const uint8_t *)&len, 2);
		return 3;
	}
	uint8_t d = 254;
	sha256_Update(ctx, &d, 1);
	sha256_Update(ctx, (const uint8_t *)&len, 4);
	return 5;
}

uint32_t deser_length(const uint8_t *in, uint32_t *out)
{
	if (in[0] < 253) {
		*out = in[0];
		return 1;
	}
	if (in[0] == 253) {
		*out = in[1] + (in[2] << 8);
		return 1 + 2;
	}
	if (in[0] == 254) {
		*out = in[1] + (in[2] << 8) + (in[3] << 16) + ((uint32_t)in[4] << 24);
		return 1 + 4;
	}
	*out = 0; // ignore 64 bit
	return 1 + 8;
}

int sshMessageSign(HDNode *node, const uint8_t *message, size_t message_len, uint8_t *signature)
{
	signature[0] = 0; // prefix: pad with zero, so all signatures are 65 bytes
	return hdnode_sign(node, message, message_len, signature + 1, NULL);
}

int gpgMessageSign(HDNode *node, const uint8_t *message, size_t message_len, uint8_t *signature)
{
	// GPG should sign a SHA256 digest of the original message.
	if (message_len != 32) {
		return 1;
	}
	signature[0] = 0; // prefix: pad with zero, so all signatures are 65 bytes
	return hdnode_sign_digest(node, message, signature + 1, NULL);
}

int cryptoGetECDHSessionKey(const HDNode *node, const uint8_t *peer_public_key, uint8_t *session_key)
{
	curve_point point;
	const ecdsa_curve *curve = node->curve->params;
	if (!ecdsa_read_pubkey(curve, peer_public_key, &point)) {
		return 1;
	}
	bignum256 k;
	bn_read_be(node->private_key, &k);
	point_multiply(curve, &k, &point, &point);
	MEMSET_BZERO(&k, sizeof(k));

	session_key[0] = 0x04;
	bn_write_be(&point.x, session_key + 1);
	bn_write_be(&point.y, session_key + 33);
	MEMSET_BZERO(&point, sizeof(point));
	return 0;
}

int cryptoMessageSign(const CoinType *coin, HDNode *node, const uint8_t *message, size_t message_len, uint8_t *signature)
{
	SHA256_CTX ctx;
	sha256_Init(&ctx);
	sha256_Update(&ctx, (const uint8_t *)coin->signed_message_header, strlen(coin->signed_message_header));
	uint8_t varint[5];
	uint32_t l = ser_length(message_len, varint);
	sha256_Update(&ctx, varint, l);
	sha256_Update(&ctx, message, message_len);
	uint8_t hash[32];
	sha256_Final(&ctx, hash);
	sha256_Raw(hash, 32, hash);
	uint8_t pby;
	int result = hdnode_sign_digest(node, hash, signature + 1, &pby);
	if (result == 0) {
		signature[0] = 27 + pby + 4;
	}
	return result;
}

int cryptoMessageVerify(const CoinType *coin, const uint8_t *message, size_t message_len, const uint8_t *address_raw, const uint8_t *signature)
{
	SHA256_CTX ctx;
	uint8_t pubkey[65], addr_raw[21], hash[32];

	// calculate hash
	sha256_Init(&ctx);
	sha256_Update(&ctx, (const uint8_t *)coin->signed_message_header, strlen(coin->signed_message_header));
	uint8_t varint[5];
	uint32_t l = ser_length(message_len, varint);
	sha256_Update(&ctx, varint, l);
	sha256_Update(&ctx, message, message_len);
	sha256_Final(&ctx, hash);
	sha256_Raw(hash, 32, hash);

	uint8_t recid = signature[0] - 27;
	if (recid >= 8) {
		return 1;
	}
	bool compressed = (recid >= 4);
	recid &= 3;

	// check if signature verifies the digest and recover the public key
	if (ecdsa_verify_digest_recover(&secp256k1, pubkey, signature + 1, hash, recid) != 0) {
		return 3;
	}
	// convert public key to compressed pubkey if necessary
	if (compressed) {
		pubkey[0] = 0x02 | (pubkey[64] & 1);
	}
	// check if the address is correct
	ecdsa_get_address_raw(pubkey, address_raw[0], addr_raw);
	if (memcmp(addr_raw, address_raw, 21) != 0) {
		return 2;
	}
	return 0;
}

uint8_t *cryptoHDNodePathToPubkey(const HDNodePathType *hdnodepath)
{
	if (!hdnodepath->node.has_public_key || hdnodepath->node.public_key.size != 33) return 0;
	static HDNode node;
	if (hdnode_from_xpub(hdnodepath->node.depth, hdnodepath->node.child_num, hdnodepath->node.chain_code.bytes, hdnodepath->node.public_key.bytes, SECP256K1_NAME, &node) == 0) {
		return 0;
	}
	animating_progress_handler();
	uint32_t i;
	for (i = 0; i < hdnodepath->address_n_count; i++) {
		if (hdnode_public_ckd(&node, hdnodepath->address_n[i]) == 0) {
			return 0;
		}
		animating_progress_handler();
	}
	return node.public_key;
}

int cryptoMultisigPubkeyIndex(const MultisigRedeemScriptType *multisig, const uint8_t *pubkey)
{
	size_t i;
	for (i = 0; i < multisig->pubkeys_count; i++) {
		const uint8_t *node_pubkey = cryptoHDNodePathToPubkey(&(multisig->pubkeys[i]));
		if (node_pubkey && memcmp(node_pubkey, pubkey, 33) == 0) {
			return i;
		}
	}
	return -1;
}

int cryptoMultisigFingerprint(const MultisigRedeemScriptType *multisig, uint8_t *hash)
{
	static const HDNodePathType *ptr[15], *swap;
	const uint32_t n = multisig->pubkeys_count;
	if (n > 15) {
		return 0;
	}
	uint32_t i, j;
	// check sanity
	if (!multisig->has_m || multisig->m < 1 || multisig->m > 15) return 0;
	for (i = 0; i < n; i++) {
		ptr[i] = &(multisig->pubkeys[i]);
		if (!ptr[i]->node.has_public_key || ptr[i]->node.public_key.size != 33) return 0;
		if (ptr[i]->node.chain_code.size != 32) return 0;
	}
	// minsort according to pubkey
	for (i = 0; i < n - 1; i++) {
		for (j = n - 1; j > i; j--) {
			if (memcmp(ptr[i]->node.public_key.bytes, ptr[j]->node.public_key.bytes, 33) > 0) {
				swap = ptr[i];
				ptr[i] = ptr[j];
				ptr[j] = swap;
			}
		}
	}
	// hash sorted nodes
	SHA256_CTX ctx;
	sha256_Init(&ctx);
	sha256_Update(&ctx, (const uint8_t *)&(multisig->m), sizeof(uint32_t));
	for (i = 0; i < n; i++) {
		sha256_Update(&ctx, (const uint8_t *)&(ptr[i]->node.depth), sizeof(uint32_t));
		sha256_Update(&ctx, (const uint8_t *)&(ptr[i]->node.fingerprint), sizeof(uint32_t));
		sha256_Update(&ctx, (const uint8_t *)&(ptr[i]->node.child_num), sizeof(uint32_t));
		sha256_Update(&ctx, ptr[i]->node.chain_code.bytes, 32);
		sha256_Update(&ctx, ptr[i]->node.public_key.bytes, 33);
	}
	sha256_Update(&ctx, (const uint8_t *)&n, sizeof(uint32_t));
	sha256_Final(&ctx, hash);
	animating_progress_handler();
	return 1;
}

int cryptoIdentityFingerprint(const IdentityType *identity, uint8_t *hash)
{
	SHA256_CTX ctx;
	sha256_Init(&ctx);
	sha256_Update(&ctx, (const uint8_t *)&(identity->index), sizeof(uint32_t));
	if (identity->has_proto && identity->proto[0]) {
		sha256_Update(&ctx, (const uint8_t *)(identity->proto), strlen(identity->proto));
		sha256_Update(&ctx, (const uint8_t *)"://", 3);
	}
	if (identity->has_user && identity->user[0]) {
		sha256_Update(&ctx, (const uint8_t *)(identity->user), strlen(identity->user));
		sha256_Update(&ctx, (const uint8_t *)"@", 1);
	}
	if (identity->has_host && identity->host[0]) {
		sha256_Update(&ctx, (const uint8_t *)(identity->host), strlen(identity->host));
	}
	if (identity->has_port && identity->port[0]) {
		sha256_Update(&ctx, (const uint8_t *)":", 1);
		sha256_Update(&ctx, (const uint8_t *)(identity->port), strlen(identity->port));
	}
	if (identity->has_path && identity->path[0]) {
		sha256_Update(&ctx, (const uint8_t *)(identity->path), strlen(identity->path));
	}
	sha256_Final(&ctx, hash);
	return 1;
}
