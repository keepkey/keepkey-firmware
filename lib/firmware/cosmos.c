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
