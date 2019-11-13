#include "keepkey/firmware/cosmos.h"

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/storage.h"
#include "trezor/crypto/segwit_addr.h"
#include "trezor/crypto/ecdsa.h"
#include <stdbool.h>
#include <time.h>

/* This was inlined from the trezor firmware because it was not exported.
 * Forking the repository to expose this function is an option but we will
 * need guidance on the way you want to handle syncing the locked commit,
 * keepkey@HEAD, and the new commit.
 */
static int convert_bits(uint8_t *out, size_t *outlen, int outbits, const uint8_t *in, size_t inlen, int inbits, int pad)
{
    uint32_t val = 0;
    int bits = 0;
    uint32_t maxv = (((uint32_t)1) << outbits) - 1;
    while (inlen--)
    {
        val = (val << inbits) | *(in++);
        bits += inbits;
        while (bits >= outbits)
        {
            bits -= outbits;
            out[(*outlen)++] = (val >> bits) & maxv;
        }
    }
    if (pad)
    {
        if (bits)
        {
            out[(*outlen)++] = (val << (outbits - bits)) & maxv;
        }
    }
    else if (((val << (outbits - bits)) & maxv) || bits >= inbits)
    {
        return 0;
    }
    return 1;
}

/*
 * Gets the address
 *
 * public_key: 33 byte compressed secp256k1 key
 * address: output buffer
 *
 * returns true if successful
 */
bool cosmos_getAddress(const HDNode *node, char *address)
{
    hdnode_fill_public_key(node);

    uint8_t hash160Buf[RIPEMD160_DIGEST_LENGTH];
    ecdsa_get_pubkeyhash(node->public_key, HASHER_SHA2_RIPEMD, hash160Buf);

    uint8_t fiveBitExpanded[RIPEMD160_DIGEST_LENGTH * 8 / 5];
    size_t len = 0;
    convert_bits(fiveBitExpanded, &len, 5, hash160Buf, 20, 8, 1);
    // bech32encode
    return bech32_encode(address, "cosmos", fiveBitExpanded, len) == 1;
}

#define SIGNING_TEMPLATE "{\"account_number\":\"%" PRIu64 "\",\"chain_id\":\"%s\",\"fee\":{\"amount\":[{\"amount\":\"%" PRIu32 "\",\"denom\":\"uatom\"}],\"gas\":\"%" PRIu32 "\"},\"memo\":\"%s\",\"msgs\":[{\"type\":\"cosmos-sdk/MsgSend\",\"value\":{\"amount\":[{\"amount\":\"%" PRIu64 "\",\"denom\":\"uatom\"}],\"from_address\":\"%s\",\"to_address\":\"%s\"}}],\"sequence\":\"%" PRIu64 "\"}"

// 411 + memo + chain_id + NULL terminator
bool cosmos_signTx(const uint8_t *private_key,
                   const uint64_t account_number,
                   const char *chain_id,
                   const size_t chain_id_length,
                   const uint32_t fee_uatom_amount,
                   const uint32_t gas,
                   const char *memo,
                   const size_t memo_length,
                   const uint64_t amount,
                   const char *from_address,
                   const char *to_address,
                   const uint64_t sequence,
                   uint8_t *signature)
{
    size_t len = 412 + memo_length + chain_id_length;
    char signBytes[len];
    snprintf(signBytes, len, SIGNING_TEMPLATE, account_number, chain_id, fee_uatom_amount, gas, memo, amount, from_address, to_address, sequence);
    uint8_t hash[SHA256_DIGEST_LENGTH];
    sha256_Raw((uint8_t *)signBytes, strlen(signBytes), hash);
    return ecdsa_sign_digest(&secp256k1, private_key, hash, signature, NULL, NULL) == 0;
}
