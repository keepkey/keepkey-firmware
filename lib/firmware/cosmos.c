#include "keepkey/firmware/cosmos.h"

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/storage.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/segwit_addr.h"
#include <stdbool.h>
#include <time.h>

static CONFIDENTIAL HDNode node;
static SHA256_CTX ctx;
static bool has_message;
static bool initialized;
static uint32_t address_n[8];
static size_t address_n_count;
static uint32_t msgs_remaining;
static uint64_t sequence;

bool cosmos_path_mismatched(const CoinType *_coin,
                            const uint32_t *_address_n,
                            const uint32_t _address_n_count)
{
    // m/44' : BIP44-like path
    // m / purpose' / bip44_account_path' / account' / x / y
    bool mismatch = false;
    mismatch |= _address_n_count != 5;
    mismatch |= _address_n_count > 0 && (_address_n[0] != (0x80000000 + 44));
    mismatch |= _address_n_count > 1 && (_address_n[1] != _coin->bip44_account_path);
    mismatch |= _address_n_count > 2 && (_address_n[2] & 0x80000000) == 0;
    mismatch |= _address_n_count > 3 && _address_n[3] != 0;
    mismatch |= _address_n_count > 4 && (_address_n[4] & 0x80000000) != 0;
    return mismatch;
}

/*
 * Gets the address
 *
 * _node: HDNode from which the address is to be derived
 * address: output buffer
 *
 * returns true if successful
 */
bool cosmos_getAddress(const HDNode *_node, char *address)
{
    uint8_t hash160Buf[RIPEMD160_DIGEST_LENGTH];
    ecdsa_get_pubkeyhash(_node->public_key, HASHER_SHA2_RIPEMD, hash160Buf);

    uint8_t fiveBitExpanded[RIPEMD160_DIGEST_LENGTH * 8 / 5];
    size_t len = 0;
    convert_bits(fiveBitExpanded, &len, 5, hash160Buf, 20, 8, 1);
    return bech32_encode(address, "cosmos", fiveBitExpanded, len) == 1;
}

void sha256UpdateEscaped(SHA256_CTX *_ctx, const char *s, size_t len)
{
    while (len > 0)
    {
        if (s[0] == '"')
        {
            sha256_Update(_ctx, (uint8_t *)"\\\"", 2);
        }
        else if (s[0] == '\\')
        {
            sha256_Update(_ctx, (uint8_t *)"\\\\", 2);
        }
        else
        {
            sha256_Update(_ctx, (uint8_t *)&s[0], 1);
        }
        s = &s[1];
        len--;
    }
}

bool cosmos_signTxInit(const HDNode* _node,
                       const uint32_t* _address_n,
                       const size_t _address_n_count,
                       const uint64_t account_number,
                       const char *chain_id,
                       const size_t chain_id_length,
                       const uint32_t fee_uatom_amount,
                       const uint32_t gas,
                       const char *memo,
                       const size_t memo_length,
                       const uint64_t _sequence,
                       const uint32_t msg_count)
{

    initialized = true;
    msgs_remaining = msg_count;
    has_message = false;
    sequence = _sequence;

    memzero(&node, sizeof(node));
    memcpy(&node, _node, sizeof(node));
    memzero(address_n, sizeof(address_n));
    memcpy(address_n, _address_n, sizeof(address_n));
    address_n_count = _address_n_count;

    int n;
    sha256_Init(&ctx);
    char buffer[SHA256_BLOCK_LENGTH + 1]; // NULL TERMINATOR NOT PART OF HASH

    // Each segment guaranteed to be less than or equal to 64 bytes
    // 19 + ^20 + 14 = ^53
    n = snprintf(buffer, SHA256_BLOCK_LENGTH + 1, "{\"account_number\":\"%" PRIu64 "\",\"chain_id\":\"", account_number);
    if (n < 0) { return false; }
    sha256_Update(&ctx, (uint8_t *)buffer, n);

    // <escape chain_id>
    sha256UpdateEscaped(&ctx, chain_id, chain_id_length);

    // 30 + ^10 + 24 = ^64
    n = snprintf(buffer, SHA256_BLOCK_LENGTH + 1, "\",\"fee\":{\"amount\":[{\"amount\":\"%" PRIu32 "\",\"denom\":\"uatom\"}],\"gas", fee_uatom_amount);
    if (n < 0) { return false; }
    sha256_Update(&ctx, (uint8_t *)buffer, n);

    // 3 + ^10 + 11 = ^23
    n = snprintf(buffer, SHA256_BLOCK_LENGTH + 1, "\":\"%" PRIu32 "\"},\"memo\":\"", gas);
    if (n < 0) { return false; }
    sha256_Update(&ctx, (uint8_t *)buffer, n);

    // <escape memo>
    sha256UpdateEscaped(&ctx, memo, memo_length);

    // 10
    sha256_Update(&ctx, (uint8_t *)"\",\"msgs\":[", 10);

    return true;
}

bool cosmos_signTxUpdateMsgSend(const uint64_t amount,
                                const char *to_address)
{
    int n;
    char buffer[SHA256_BLOCK_LENGTH + 1]; // NULL TERMINATOR NOT PART OF HASH

    size_t decoded_len;
    char hrp[45];
    uint8_t decoded[38];
    if (!bech32_decode(hrp, decoded, &decoded_len, to_address)) { return false; }
    char from_address[46];
    if (!cosmos_getAddress(&node, from_address)) { return false; }

    if (has_message) {
        sha256_Update(&ctx, (uint8_t*)",", 1);
    }

    // 59
    n = snprintf(buffer, SHA256_BLOCK_LENGTH + 1, "{\"type\":\"cosmos-sdk/MsgSend\",\"value\":{\"amount\":[{\"amount\":\"");
    if (n < 0) { return false; }
    sha256_Update(&ctx, (uint8_t *)buffer, n);


    // ^20 + 36 = ^56
    n = snprintf(buffer, SHA256_BLOCK_LENGTH + 1, "%" PRIu64 "\",\"denom\":\"uatom\"}],\"from_address\":\"", amount);
    if (n < 0) { return false; }
    sha256_Update(&ctx, (uint8_t*)buffer, n);

    // 45 + 16 = 61
    n = snprintf(buffer, SHA256_BLOCK_LENGTH + 1, "%s\",\"to_address\":\"", from_address);
    if (n < 0) { return false; }
    sha256_Update(&ctx, (uint8_t*)buffer, n);

    // 45 + 3 = 48
    n = snprintf(buffer, SHA256_BLOCK_LENGTH + 1, "%s\"}}", to_address);
    if (n < 0) { return false; }
    sha256_Update(&ctx, (uint8_t*)buffer, n);

    has_message = true;
    msgs_remaining--;
    return true;
}

bool cosmos_signTxFinalize(uint8_t* public_key, uint8_t* signature)
{
    int n;
    char buffer[SHA256_DIGEST_LENGTH + 1]; // NULL TERMINATOR NOT PART OF HASH

    // 16 + ^20 = ^36
    n = snprintf(buffer, SHA256_DIGEST_LENGTH + 1, "],\"sequence\":\"%" PRIu64 "\"}", sequence);
    if (n < 0) { return false; }
    sha256_Update(&ctx, (uint8_t*)buffer, n);

    hdnode_fill_public_key(&node);
    memcpy(public_key, node.public_key, 33);

    uint8_t hash[SHA256_DIGEST_LENGTH];
    sha256_Final(&ctx, hash);
    return ecdsa_sign_digest(&secp256k1, node.private_key, hash, signature, NULL, NULL) == 0;
}

bool cosmos_signingIsInited(void) {
    return initialized;
}

bool cosmos_signingIsFinished(void) {
    return msgs_remaining == 0;
}

void cosmos_signAbort(void) {
    initialized = false;
    has_message = false;
    memzero(&ctx, sizeof(ctx));
    memzero(&node, sizeof(node));
    memzero(&sequence, sizeof(sequence));
    msgs_remaining = 0;
    sequence = 0;
}

size_t cosmos_getAddressNCount(void) {
    return address_n_count;
}

bool cosmos_getAddressN(uint32_t* _address_n, size_t _address_n_count)
{
    if (_address_n_count < address_n_count) {
        return false;
    }
    memcpy(_address_n, address_n, sizeof(uint32_t) * address_n_count);
    return true;
}
