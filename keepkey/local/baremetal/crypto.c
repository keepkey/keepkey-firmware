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
#include <sha2.h>
#include <pbkdf2.h>
#include <aes.h>
#include <hmac.h>
#include <secp256k1.h>
#include <nist256p1.h>
#include <bip32.h>
#include <layout.h>


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
		*out = in[1] + (in[2] << 8) + (in[3] << 16) + (in[4] << 24);
		return 1 + 4;
	}
	*out = 0; // ignore 64 bit
	return 1 + 8;
}

int sshMessageSign(const uint8_t *message, size_t message_len, const uint8_t *privkey, uint8_t *signature)
{
	signature[0] = 0; // prefix: pad with zero, so all signatures are 65 bytes
	return ecdsa_sign(&nist256p1, privkey, message, message_len, signature + 1, NULL);
}

int cryptoMessageSign(const uint8_t *message, size_t message_len, const uint8_t *privkey, uint8_t *signature)
{
	SHA256_CTX ctx;
	sha256_Init(&ctx);
	sha256_Update(&ctx, (const uint8_t *)"\x18" "Bitcoin Signed Message:" "\n", 25);
	uint8_t varint[5];
	uint32_t l = ser_length(message_len, varint);
	sha256_Update(&ctx, varint, l);
	sha256_Update(&ctx, message, message_len);
	uint8_t hash[32];
	sha256_Final(hash, &ctx);
	sha256_Raw(hash, 32, hash);
	uint8_t pby;
	int result = ecdsa_sign_digest(&secp256k1, privkey, hash, signature + 1, &pby);
	if (result == 0) {
		signature[0] = 27 + pby + 4;
	}
	return result;
}

int cryptoMessageVerify(const uint8_t *message, size_t message_len, const uint8_t *address_raw, const uint8_t *signature)
{
	bignum256 r, s, e;
	curve_point cp, cp2;
	SHA256_CTX ctx;
	uint8_t pubkey[65], addr_raw[21], hash[32];

	uint8_t nV = signature[0];
	if (nV < 27 || nV >= 35) {
		return 1;
	}
	bool compressed;
	compressed = (nV >= 31);
	if (compressed) {
		nV -= 4;
	}
	uint8_t recid = nV - 27;
	// read r and s
	bn_read_be(signature + 1, &r);
	bn_read_be(signature + 33, &s);
	// x = r
	memcpy(&cp.x, &r, sizeof(bignum256));
	// compute y from x
	uncompress_coords(&secp256k1, recid % 2, &cp.x, &cp.y);
	// calculate hash
	sha256_Init(&ctx);
	sha256_Update(&ctx, (const uint8_t *)"\x18" "Bitcoin Signed Message:" "\n", 25);
	uint8_t varint[5];
	uint32_t l = ser_length(message_len, varint);
	sha256_Update(&ctx, varint, l);
	sha256_Update(&ctx, message, message_len);
	sha256_Final(hash, &ctx);
	sha256_Raw(hash, 32, hash);
	// e = -hash
	bn_read_be(hash, &e);
	bn_subtract(&secp256k1.order, &e, &e);
	// r = r^-1
	bn_inverse(&r, &secp256k1.order);
	point_multiply(&secp256k1, &s, &cp, &cp);
	scalar_multiply(&secp256k1, &e, &cp2);
	point_add(&secp256k1, &cp2, &cp);
	point_multiply(&secp256k1, &r, &cp, &cp);
	pubkey[0] = 0x04;
	bn_write_be(&cp.x, pubkey + 1);
	bn_write_be(&cp.y, pubkey + 33);
	// check if the address is correct
	if (compressed) {
		pubkey[0] = 0x02 | (cp.y.val[0] & 0x01);
	}
	ecdsa_get_address_raw(pubkey, address_raw[0], addr_raw);
	if (memcmp(addr_raw, address_raw, 21) != 0) {
		return 2;
	}
	// check if signature verifies the digest
	if (ecdsa_verify_digest(&secp256k1, pubkey, signature + 1, hash) != 0) {
		return 3;
	}
	return 0;
}

int cryptoMessageEncrypt(curve_point *pubkey, const uint8_t *msg, size_t msg_size, bool display_only, uint8_t *nonce, size_t *nonce_len, uint8_t *payload, size_t *payload_len, uint8_t *hmac, size_t *hmac_len, const uint8_t *privkey, const uint8_t *address_raw)
{
	if (privkey && address_raw) { // signing == true
		payload[0] = display_only ? 0x81 : 0x01;
		uint32_t l = ser_length(msg_size, payload + 1);
		memcpy(payload + 1 + l, msg, msg_size);
		memcpy(payload + 1 + l + msg_size, address_raw, 21);
		if (cryptoMessageSign(msg, msg_size, privkey, payload + 1 + l + msg_size + 21) != 0) {
			return 1;
		}
		*payload_len = 1 + l + msg_size + 21 + 65;
	} else {
		payload[0] = display_only ? 0x80 : 0x00;
		uint32_t l = ser_length(msg_size, payload + 1);
		memcpy(payload + 1 + l, msg, msg_size);
		*payload_len = 1 + l + msg_size;
	}
	// generate random nonce
	curve_point R;
	bignum256 k;
	if (generate_k_random(&secp256k1, &k) != 0) {
		return 2;
	}
	// compute k*G
	scalar_multiply(&secp256k1, &k, &R);
	nonce[0] = 0x02 | (R.y.val[0] & 0x01);
	bn_write_be(&R.x, nonce + 1);
	*nonce_len = 33;
	// compute shared secret
	point_multiply(&secp256k1, &k, pubkey, &R);
	uint8_t shared_secret[33];
	shared_secret[0] = 0x02 | (R.y.val[0] & 0x01);
	bn_write_be(&R.x, shared_secret + 1);
	// generate keying bytes
	uint8_t keying_bytes[80];
	uint8_t salt[22 + 33 + 4];
	memcpy(salt, "Bitcoin Secure Message", 22);
	memcpy(salt + 22, nonce, 33);
	pbkdf2_hmac_sha256(shared_secret, 33, salt, 22 + 33, 2048, keying_bytes, 80, NULL);
	// encrypt payload
	aes_encrypt_ctx ctx;
	aes_encrypt_key256(keying_bytes, &ctx);
	aes_cfb_encrypt(payload, payload, *payload_len, keying_bytes + 64, &ctx);
	// compute hmac
	uint8_t out[32];
	hmac_sha256(keying_bytes + 32, 32, payload, *payload_len, out);
	memcpy(hmac, out, 8);
	*hmac_len = 8;

	return 0;
}

int cryptoMessageDecrypt(curve_point *nonce, uint8_t *payload, size_t payload_len, const uint8_t *hmac, size_t hmac_len, const uint8_t *privkey, uint8_t *msg, size_t *msg_len, bool *display_only, bool *signing, uint8_t *address_raw)
{
	if (hmac_len != 8) {
		return 1;
	}
	// compute shared secret
	curve_point R;
	bignum256 k;
	bn_read_be(privkey, &k);
	point_multiply(&secp256k1, &k, nonce, &R);
	uint8_t shared_secret[33];
	shared_secret[0] = 0x02 | (R.y.val[0] & 0x01);
	bn_write_be(&R.x, shared_secret + 1);
	// generate keying bytes
	uint8_t keying_bytes[80];
	uint8_t salt[22 + 33 + 4];
	memcpy(salt, "Bitcoin Secure Message", 22);
	salt[22] = 0x02 | (nonce->y.val[0] & 0x01);
	bn_write_be(&(nonce->x), salt + 23);
	pbkdf2_hmac_sha256(shared_secret, 33, salt, 22 + 33, 2048, keying_bytes, 80, NULL);
	// compute hmac
	uint8_t out[32];
	hmac_sha256(keying_bytes + 32, 32, payload, payload_len, out);
	if (memcmp(hmac, out, 8) != 0) {
		return 2;
	}
	// decrypt payload
	aes_encrypt_ctx ctx;
	aes_encrypt_key256(keying_bytes, &ctx);
	aes_cfb_decrypt(payload, payload, payload_len, keying_bytes + 64, &ctx);
	// check first byte
	if (payload[0] != 0x00 && payload[0] != 0x01 && payload[0] != 0x80 && payload[0] != 0x81) {
		return 3;
	}
	*signing = payload[0] & 0x01;
	*display_only = payload[0] & 0x80;
	uint32_t l, o;
	l = deser_length(payload + 1, &o);
	if (*signing) {
		if (1 + l + o + 21 + 65 != payload_len) {
			return 4;
		}
		if (cryptoMessageVerify(payload + 1 + l, o, payload + 1 + l + o, payload + 1 + l + o + 21) != 0) {
			return 5;
		}
		memcpy(address_raw, payload + 1 + l + o, 21);
	} else {
		if (1 + l + o != payload_len) {
			return 4;
		}
	}
	memcpy(msg, payload + 1 + l, o);
	*msg_len = o;
	return 0;
}

uint8_t *cryptoHDNodePathToPubkey(const HDNodePathType *hdnodepath)
{
	if (!hdnodepath->node.has_public_key || hdnodepath->node.public_key.size != 33) return 0;
	static HDNode node;
	if (hdnode_from_xpub(hdnodepath->node.depth, hdnodepath->node.fingerprint, hdnodepath->node.child_num, hdnodepath->node.chain_code.bytes, hdnodepath->node.public_key.bytes, &node) == 0) {
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
	sha256_Final(hash, &ctx);
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
	sha256_Final(hash, &ctx);
	return 1;
}
