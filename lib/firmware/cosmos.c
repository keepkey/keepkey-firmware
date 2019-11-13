#include "keepkey/firmware/cosmos.h"

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/storage.h"
#include "trezor/crypto/segwit_addr.h"
#include "trezor/crypto/ecdsa.h"
#include <stdbool.h>
#include <time.h>

bool cosmos_path_mismatched(const CoinType *_coin,
                            const uint32_t *address_n,
                            const uint32_t address_n_count)
{
    // m/44' : BIP44-like path
    // m / purpose' / bip44_account_path' / account' / x / y
    bool mismatch = false;
    mismatch |= address_n_count != 5;
    mismatch |= address_n_count > 0 && (address_n[0] != (0x80000000 + 44));
    mismatch |= address_n_count > 1 && (address_n[1] != _coin->bip44_account_path);
    mismatch |= address_n_count > 2 && (address_n[2] & 0x80000000) == 0;
    mismatch |= address_n_count > 3 && (address_n[3] & 0x80000000) != 0;
    mismatch |= address_n_count > 4 && (address_n[4] & 0x80000000) != 0;
    return mismatch;
}

/* This was inlined from the trezor firmware because it was not exported.
 * Forking the repository to expose this function is an option but we will
 * need guidance on the way you want to handle syncing the locked commit,
 * keepkey@HEAD, and the new commit.
 */
// static int convert_bits(uint8_t *out, size_t *outlen, int outbits, const uint8_t *in, size_t inlen, int inbits, int pad)
// {
//     uint32_t val = 0;
//     int bits = 0;
//     uint32_t maxv = (((uint32_t)1) << outbits) - 1;
//     while (inlen--)
//     {
//         val = (val << inbits) | *(in++);
//         bits += inbits;
//         while (bits >= outbits)
//         {
//             bits -= outbits;
//             out[(*outlen)++] = (val >> bits) & maxv;
//         }
//     }
//     if (pad)
//     {
//         if (bits)
//         {
//             out[(*outlen)++] = (val << (outbits - bits)) & maxv;
//         }
//     }
//     else if (((val << (outbits - bits)) & maxv) || bits >= inbits)
//     {
//         return 0;
//     }
//     return 1;
// }

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
    uint8_t hash160Buf[RIPEMD160_DIGEST_LENGTH];
    ecdsa_get_pubkeyhash(node->public_key, HASHER_SHA2_RIPEMD, hash160Buf);

    uint8_t fiveBitExpanded[RIPEMD160_DIGEST_LENGTH * 8 / 5];
    size_t len = 0;
    convert_bits(fiveBitExpanded, &len, 5, hash160Buf, 20, 8, 1);
    // bech32encode
    return bech32_encode(address, "cosmos", fiveBitExpanded, len) == 1;
}

// Each segment guaranteed to be less than 64 bytes
// 19 + ^20 + 14 = ^53
#define SIGNING_TEMPLATE_SEG1 "{\"account_number\":\"%" PRIu64 "\",\"chain_id\":\""
// <escape chain_id>
// 30 + ^10 + 24 = ^64
#define SIGNING_TEMPLATE_SEG2 "\",\"fee\":{\"amount\":[{\"amount\":\"%" PRIu32 "\",\"denom\":\"uatom\"}],\"gas"
// 3 + ^10 + 11 = ^23
#define SIGNING_TEMPLATE_SEG3 "\":\"%" PRIu32 "\"},\"memo\":\""
// <escape memo>
// 64
#define SIGNING_TEMPLATE_SEG4 "\",\"msgs\":[{\"type\":\"cosmos-sdk/MsgSend\",\"value\":{\"amount\":[{\"amou"
// 5 + ^20 + 36 = ^61
#define SIGNING_TEMPLATE_SEG5 "nt\":\"%" PRIu64 "\",\"denom\":\"uatom\"}],\"from_address\":\""
// 45 + 16 = 61
#define SIGNING_TEMPLATE_SEG6 "%s\",\"to_address\":\""
// 45 + 17 = 62
#define SIGNING_TEMPLATE_SEG7 "%s\"}}],\"sequence\":\""
// ^20 + 2 = ^22
#define SIGNING_TEMPLATE_SEG8 "%" PRIu64 "\"}"

void sha256UpdateEscaped(SHA256_CTX *ctx, const char *s, size_t len)
{
    while (len > 0)
    {
        if (s[0] == '"')
        {
            sha256_Update(ctx, (uint8_t *)"\\\"", 2);
        }
        else if (s[0] == '\\')
        {
            sha256_Update(ctx, (uint8_t *)"\\\\", 2);
        }
        else
        {
            sha256_Update(ctx, (uint8_t *)&s[0], 1);
        }
        s = &s[1];
        len--;
    }
}

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
    SHA256_CTX ctx;
    int n;
    sha256_Init(&ctx);
    char buffer[SHA256_BLOCK_LENGTH + 1]; // NULL TERMINATOR NOT PART OF HASH
    n = snprintf(buffer, SHA256_BLOCK_LENGTH + 1, SIGNING_TEMPLATE_SEG1, account_number);
    if (n < 0)
    {
        return false;
    }
    sha256_Update(&ctx, (uint8_t *)buffer, n);
    sha256UpdateEscaped(&ctx, chain_id, chain_id_length);
    n = snprintf(buffer, SHA256_BLOCK_LENGTH + 1, SIGNING_TEMPLATE_SEG2, fee_uatom_amount);
    if (n < 0)
    {
        return false;
    }
    sha256_Update(&ctx, (uint8_t *)buffer, n);
    n = snprintf(buffer, SHA256_BLOCK_LENGTH + 1, SIGNING_TEMPLATE_SEG3, gas);
    if (n < 0)
    {
        return false;
    }
    sha256_Update(&ctx, (uint8_t *)buffer, n);
    sha256UpdateEscaped(&ctx, memo, memo_length);
    sha256_Update(&ctx, (uint8_t *)SIGNING_TEMPLATE_SEG4, 64); // no interpolation needed
    n = snprintf(buffer, SHA256_BLOCK_LENGTH + 1, SIGNING_TEMPLATE_SEG5, amount);
    if (n < 0)
    {
        return false;
    }
    sha256_Update(&ctx, (uint8_t *)buffer, n);
    n = snprintf(buffer, SHA256_BLOCK_LENGTH + 1, SIGNING_TEMPLATE_SEG6, from_address);
    if (n < 0)
    {
        return false;
    }
    sha256_Update(&ctx, (uint8_t *)buffer, n);
    n = snprintf(buffer, SHA256_BLOCK_LENGTH + 1, SIGNING_TEMPLATE_SEG7, to_address);
    if (n < 0)
    {
        return false;
    }
    sha256_Update(&ctx, (uint8_t *)buffer, n);
    n = snprintf(buffer, SHA256_BLOCK_LENGTH + 1, SIGNING_TEMPLATE_SEG8, sequence);
    if (n < 0)
    {
        return false;
    }
    sha256_Update(&ctx, (uint8_t *)buffer, n);

    uint8_t hash[SHA256_DIGEST_LENGTH];
    sha256_Final(&ctx, hash);
    return ecdsa_sign_digest(&secp256k1, private_key, hash, signature, NULL, NULL) == 0;
}
