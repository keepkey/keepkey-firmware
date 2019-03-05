#include "keepkey/firmware/nano.h"

#include "keepkey/board/confirm_sm.h"
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/home_sm.h"
#include "trezor/crypto/blake2b.h"
#include "trezor/crypto/memzero.h"

#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#ifdef EMULATOR
#  include <assert.h>
#endif

static ed25519_public_key account_pk;
static bignum256 parent_balance;
static bignum256 balance;
static bignum256 balance_delta;
static uint8_t block_hash[32];
static uint8_t parent_hash[32];
static uint8_t link[32];
static ed25519_public_key representative_pk;
static uint8_t balance_be[16];
static bool is_send = true;
static char representative_address[MAX_NANO_ADDR_SIZE];
static char recipient_address[MAX_NANO_ADDR_SIZE];
static const CoinType *coin = NULL;

static uint8_t const NANO_BLOCK_HASH_PREAMBLE[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
};

bool nano_path_mismatched(const CoinType *_coin,
                          const uint32_t *address_n,
                          const uint32_t address_n_count)
{
    // m/44' : BIP44-like path
    // m / purpose' / bip44_account_path' / account'
    bool mismatch = false;
    mismatch |= address_n_count != 3;
    mismatch |= address_n_count > 0 && (address_n[0] != (0x80000000 + 44));
    mismatch |= address_n_count > 1 && (address_n[1] != _coin->bip44_account_path);
    mismatch |= address_n_count > 2 && (address_n[2] & 0x80000000) == 0;
    return mismatch;
}

bool nano_bip32_to_string(char *node_str, size_t len,
                          const CoinType *_coin,
                          const uint32_t *address_n,
                          const size_t address_n_count)
{
    if (address_n_count != 3)
        return false;

    if (nano_path_mismatched(_coin, address_n, address_n_count))
        return false;

    snprintf(node_str, len, "%s Account #%" PRIu32, _coin->coin_name,
             address_n[2] & 0x7ffffff);
    return true;
}

void nano_hash_block_data(const uint8_t _account_pk[32],
                          const uint8_t _parent_hash[32],
                          const uint8_t _link[32],
                          const uint8_t _representative_pk[32],
                          const uint8_t _balance[16],
                          uint8_t _out_hash[32])
{
    blake2b_state ctx;
    blake2b_Init(&ctx, 32);

    blake2b_Update(&ctx, NANO_BLOCK_HASH_PREAMBLE, sizeof(NANO_BLOCK_HASH_PREAMBLE));
    blake2b_Update(&ctx, _account_pk, 32);
    blake2b_Update(&ctx, _parent_hash, 32);
    blake2b_Update(&ctx, _representative_pk, 32);
    blake2b_Update(&ctx, _balance, 16);
    blake2b_Update(&ctx, _link, 32);

    blake2b_Final(&ctx, _out_hash, 32);
}

void nano_signingAbort(void)
{
    bn_zero(&parent_balance);
    bn_zero(&balance);
    bn_zero(&balance_delta);

    memset(block_hash, 0, sizeof(block_hash));
    memset(parent_hash, 0, sizeof(parent_hash));
    memset(link, 0, sizeof(link));
    memset(representative_pk, 0, sizeof(representative_pk));
    memset(balance_be, 0, sizeof(balance_be));

    memset(recipient_address, 0, sizeof(recipient_address));
    memset(representative_address, 0, sizeof(representative_address));

    is_send = true;
}

bool nano_signingInit(const NanoSignTx *msg, const HDNode *node, const CoinType *_coin)
{
    nano_signingAbort();

    memcpy(account_pk, &node->public_key[1], sizeof(account_pk));
    coin = _coin;

    // Validate input data
    bool invalid = false;
    if (msg->has_parent_block) {
        invalid |= msg->parent_block.has_parent_hash
            && msg->parent_block.parent_hash.size != 32;
        invalid |= msg->parent_block.has_link
            && msg->parent_block.link.size != 32;
        invalid |= !msg->parent_block.has_representative;
        invalid |= !msg->parent_block.has_balance
            || msg->parent_block.balance.size != 16;
    }
    if (!msg->has_parent_block) {
        invalid |= !msg->has_link_hash; // first block must be a receive block
    }
    invalid |= (int)msg->has_link_hash + (int)msg->has_link_recipient + (int)(msg->link_recipient_n_count != 0) > 1;
    invalid |= msg->has_link_hash && msg->link_hash.size != 32;
    invalid |= !msg->has_representative;
    invalid |= !msg->has_balance || msg->balance.size != 16;

    return !invalid;
}

bool nano_parentHash(const NanoSignTx *msg)
{
    if (!msg->has_parent_block)
        return true;

    if (msg->parent_block.has_parent_hash) {
        memcpy(parent_hash, msg->parent_block.parent_hash.bytes, sizeof(parent_hash));
    }
    memcpy(link, msg->parent_block.link.bytes, sizeof(link));

    if (!nano_validate_address(coin->nanoaddr_prefix,
                               strlen(coin->nanoaddr_prefix),
                               msg->parent_block.representative,
                               strlen(msg->parent_block.representative),
                               representative_pk))
        return false;

    memcpy(balance_be, msg->parent_block.balance.bytes, sizeof(balance_be));
    bn_from_bytes(balance_be, sizeof(balance_be), &parent_balance);

    nano_hash_block_data(account_pk, parent_hash, link,
                         representative_pk, balance_be,
                         block_hash);

    memcpy(parent_hash, block_hash, sizeof(parent_hash));
    memset(block_hash, 0, sizeof(parent_hash));
    memset(link, 0, sizeof(link));
    memset(representative_pk, 0, sizeof(representative_pk));
    memset(balance_be, 0, sizeof(balance_be));

    return true;
}

bool nano_currentHash(const NanoSignTx *msg, const HDNode *recip)
{
    if (msg->has_link_hash) {
        memcpy(link, msg->link_hash.bytes, sizeof(link));
    } else if (msg->link_recipient_n_count > 0) {
        if (!recip)
            return false;
        memcpy(link, &recip->public_key[1], sizeof(link));
    } else if (msg->has_link_recipient) {
        memcpy(link, msg->link_recipient, sizeof(link));
        if (!nano_validate_address(coin->nanoaddr_prefix,
                                   strlen(coin->nanoaddr_prefix),
                                   msg->link_recipient,
                                   strlen(msg->link_recipient),
                                   link))
            return false;
    }

    if (!nano_validate_address(coin->nanoaddr_prefix,
                               strlen(coin->nanoaddr_prefix),
                               msg->representative,
                               strlen(msg->representative),
                               representative_pk))
        return false;

    memcpy(balance_be, msg->balance.bytes, sizeof(balance_be));
    bn_from_bytes(balance_be, sizeof(balance_be), &balance);

    nano_hash_block_data(account_pk, parent_hash, link,
                         representative_pk, balance_be,
                         block_hash);

    return true;
}

/// Some additional sanity checks now that balance values are known
bool nano_sanityCheck(const NanoSignTx *msg)
{
    memset(recipient_address, 0, sizeof(recipient_address));

    strlcpy(representative_address, msg->representative, sizeof(representative_address));
    if (msg->has_parent_block) {
        if (!strncmp(representative_address,
                     msg->parent_block.representative,
                     sizeof(representative_address))) {
            // Representative hasn't changed, zero it out
            memset(representative_address, 0, sizeof(representative_address));
        }
    }

    if (bn_is_less(&balance, &parent_balance)) {
        is_send = true;
        bn_subtract(&parent_balance, &balance, &balance_delta);
    } else {
        is_send = false;
        bn_subtract(&balance, &parent_balance, &balance_delta);
    }

    bool invalid = false;
    if (bn_is_zero(&balance_delta)) {
        // Balance can only remain unchanged when the account exists already
        invalid |= !msg->has_parent_block;
    } else if (is_send) {
        // For sends make fill out the link_recipient (or generate it from link bytes)
        if (msg->has_link_recipient) {
            strlcpy(recipient_address, msg->link_recipient, sizeof(recipient_address));
        } else {
            nano_get_address(link, coin->nanoaddr_prefix,
                             strlen(coin->nanoaddr_prefix),
                             recipient_address, sizeof(recipient_address));
        }
    } else {
        // For receives make sure that the link_hash was specified and that it's
        invalid |= !msg->has_link_hash;
        uint8_t link_empty[sizeof(link)];
        memset(link_empty, 0, sizeof(link_empty));
        invalid |= !memcmp(link_empty, link, sizeof(link));
    }

    return !invalid;
}

bool nano_signTx(const NanoSignTx *msg, HDNode *node, NanoSignedTx *resp)
{
    // Determine what type of prompt to display
    bool needs_confirm = true;
    bool is_transfer = false;
    if (strlen(representative_address) > 0) {
        // always confirm representative change
    } else if (!is_send) {
        // don't bother confirming pure receives
        needs_confirm = false;
    } else if (msg->link_recipient_n_count > 0 &&
               !nano_path_mismatched(coin, msg->link_recipient_n,
                                     msg->link_recipient_n_count)) {
        is_transfer = true;
    }

    if (needs_confirm) {
        if (strlen(representative_address) > 0) {
            if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                         "Representative", "Set account representative to %s?",
                         representative_address)) {
                fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled");
                layoutHome();
                return false;
            }
        }

        char amount_string[60];
        memset(amount_string, 0, sizeof(amount_string));
        bn_format(&balance_delta,
                  NULL, NULL,
                  coin->decimals, 0, false,
                  amount_string, sizeof(amount_string));

        if (is_transfer) {
            // Confirm transfer between own accounts
            char account_str[NODE_STRING_LENGTH];
            if (!nano_bip32_to_string(account_str, sizeof(account_str), coin, msg->link_recipient_n,
                                      msg->link_recipient_n_count) &&
                !bip32_path_to_string(account_str, sizeof(account_str),
                                      msg->link_recipient_n, msg->link_recipient_n_count)) {
                strlcpy(account_str, recipient_address, sizeof(account_str));
            }

            if (!confirm(ButtonRequestType_ButtonRequest_SignTx,
                         "Transfer", "Send %s %s to %s?",
                         amount_string,
                         coin->coin_shortcut,
                         account_str)) {
                fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled");
                layoutHome();
                return false;
            }
        } else if (is_send) {
            // Regular transfer
            if (!confirm(ButtonRequestType_ButtonRequest_SignTx,
                         "Send", "Send %s %s to %s?",
                         amount_string,
                         coin->coin_shortcut,
                         recipient_address)) {
                fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled");
                layoutHome();
                return false;
            }
        }
    }

    resp->has_signature = true;
    resp->signature.size = 64;
    hdnode_sign_digest(node, block_hash, resp->signature.bytes, NULL, NULL);

    resp->has_block_hash = true;
    resp->block_hash.size = sizeof(block_hash);
    memcpy(resp->block_hash.bytes, block_hash, sizeof(block_hash));
    return true;
}

