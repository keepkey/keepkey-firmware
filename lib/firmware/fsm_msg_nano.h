#include "keepkey/firmware/nano.h"

void fsm_msgNanoGetAddress(NanoGetAddress *msg)
{
    RESP_INIT(NanoAddress);

    CHECK_INITIALIZED

    CHECK_PIN

    const char *coin_name = msg->has_coin_name ? msg->coin_name : "Nano";
    const CoinType *coin = fsm_getCoin(true, coin_name);
    if (!coin) return;
    HDNode *node = fsm_getDerivedNode(coin->curve_name, msg->address_n, msg->address_n_count, NULL);
    if (!node) return;
    hdnode_fill_public_key(node);

    char address[MAX_NANO_ADDR_SIZE];
    if (!nano_get_address(
        &node->public_key[1],
        coin->nanoaddr_prefix, strlen(coin->nanoaddr_prefix),
        address, sizeof(address))) {
        fsm_sendFailure(FailureType_Failure_Other, _("Can't encode address"));
        layoutHome();
        return;
    }

    if (msg->has_show_display && msg->show_display) {
        char node_str[NODE_STRING_LENGTH];
        if (!nano_bip32_to_string(node_str, sizeof(node_str), coin, msg->address_n,
                                  msg->address_n_count) &&
            !bip32_path_to_string(node_str, sizeof(node_str),
                                  msg->address_n, msg->address_n_count)) {
            memset(node_str, 0, sizeof(node_str));
        }

        bool mismatch = nano_path_mismatched(coin, msg->address_n, msg->address_n_count);

        if (mismatch) {
            if (!confirm(ButtonRequestType_ButtonRequest_Other, "WARNING", "Wrong address path for selected coin. Continue at your own risk!")) {
                fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
                layoutHome();
                return;
            }
        }

        if(!confirm_nano_address(node_str, address)) {
            fsm_sendFailure(FailureType_Failure_ActionCancelled, "Show address cancelled");
            layoutHome();
            return;
        }
    }

    resp->has_address = true;
    strlcpy(resp->address, address, sizeof(resp->address));
    msg_write(MessageType_MessageType_NanoAddress, resp);
    layoutHome();
}

void fsm_msgNanoSignTx(NanoSignTx *msg)
{
    RESP_INIT(NanoSignedTx);

    CHECK_INITIALIZED

    CHECK_PIN_TXSIGN

    const char *coin_name = msg->has_coin_name ? msg->coin_name : "Nano";
    const CoinType *coin = fsm_getCoin(true, coin_name);
    if (!coin) return;

    // Extract account public key for hash calculations
    ed25519_public_key account_pk;
    HDNode *node = fsm_getDerivedNode(coin->curve_name, msg->address_n, msg->address_n_count, NULL);
    if (!node) return;
    hdnode_fill_public_key(node);
    memcpy(account_pk, &node->public_key[1], sizeof(account_pk));
    memzero(node, sizeof(*node));
    node = NULL;

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
    if (invalid) {
        fsm_sendFailure(FailureType_Failure_Other, _("Block data invalid"));
        layoutHome();
        return;
    }

    bignum256 parent_balance;
    bignum256 balance;
    bignum256 balance_delta;
    bn_zero(&parent_balance);
    bn_zero(&balance);
    bn_zero(&balance_delta);

    uint8_t block_hash[32];
    uint8_t parent_hash[32];
    uint8_t link[32];
    ed25519_public_key representative_pk;
    uint8_t balance_be[16];

    memset(block_hash, 0, sizeof(block_hash));
    memset(parent_hash, 0, sizeof(parent_hash));
    memset(link, 0, sizeof(link));
    memset(representative_pk, 0, sizeof(representative_pk));
    memset(balance_be, 0, sizeof(balance_be));

    // Calculate parent hash
    if (msg->has_parent_block) {
        if (msg->parent_block.has_parent_hash) {
            memcpy(parent_hash, msg->parent_block.parent_hash.bytes, sizeof(parent_hash));
        }
        memcpy(link, msg->parent_block.link.bytes, sizeof(link));
        invalid |= !nano_validate_address(
            coin->nanoaddr_prefix, strlen(coin->nanoaddr_prefix),
            msg->parent_block.representative, strlen(msg->parent_block.representative),
            representative_pk);
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
    }

    // Calculate current hash
    if (msg->has_link_hash) {
        memcpy(link, msg->link_hash.bytes, sizeof(link));
    } else if (msg->link_recipient_n_count > 0) {
        node = fsm_getDerivedNode(coin->curve_name, msg->link_recipient_n, msg->link_recipient_n_count, NULL);
        if (!node) return;
        hdnode_fill_public_key(node);
        memcpy(link, &node->public_key[1], sizeof(link));
        memzero(node, sizeof(*node));
        node = NULL;
    } else if (msg->has_link_recipient) {
        invalid |= !nano_validate_address(
            coin->nanoaddr_prefix, strlen(coin->nanoaddr_prefix),
            msg->link_recipient, strlen(msg->link_recipient),
            link);
    }
    invalid |= !nano_validate_address(
        coin->nanoaddr_prefix, strlen(coin->nanoaddr_prefix),
        msg->representative, strlen(msg->representative),
        representative_pk);
    memcpy(balance_be, msg->balance.bytes, sizeof(balance_be));
    bn_from_bytes(balance_be, sizeof(balance_be), &balance);

    nano_hash_block_data(account_pk, parent_hash, link,
                         representative_pk, balance_be,
                         block_hash);

    if (invalid) {
        fsm_sendFailure(FailureType_Failure_Other, _("Block data invalid"));
        layoutHome();
        return;
    }

    // Some additional sanity checks now that balance values are known
    char recipient_address[MAX_NANO_ADDR_SIZE];
    memset(recipient_address, 0, sizeof(recipient_address));

    char representative_address[MAX_NANO_ADDR_SIZE];
    strlcpy(representative_address, msg->representative, sizeof(representative_address));
    if (msg->has_parent_block) {
        if (!strncmp(representative_address,
                     msg->parent_block.representative,
                     sizeof(representative_address))) {
            // Representative hasn't changed, zero it out
            memset(representative_address, 0, sizeof(representative_address));
        }
    }
    if (strlen(representative_address) > 0) {
        nano_truncate_address(coin, representative_address);
    }

    bool is_send = false;
    if (bn_is_less(&balance, &parent_balance)) {
        is_send = true;
        bn_subtract(&parent_balance, &balance, &balance_delta);
    } else {
        bn_subtract(&balance, &parent_balance, &balance_delta);
    }

    if (bn_is_zero(&balance_delta)) {
        // Balance can only remain unchanged when the account exists already
        invalid |= !msg->has_parent_block;
    } else if (is_send) {
        // For sends make fill out the link_recipient (or generate it from link bytes)
        if (msg->has_link_recipient) {
            strlcpy(recipient_address, msg->link_recipient, sizeof(recipient_address));
        } else {
            nano_get_address(link,
                coin->nanoaddr_prefix, strlen(coin->nanoaddr_prefix),
                recipient_address, sizeof(recipient_address));
        }
        nano_truncate_address(coin, recipient_address);
    } else {
        // For receives make sure that the link_hash was specified and that it's
        invalid |= !msg->has_link_hash;
        uint8_t link_empty[sizeof(link)];
        memset(link_empty, 0, sizeof(link_empty));
        invalid |= !memcmp(link_empty, link, sizeof(link));
    }

    if (invalid) {
        fsm_sendFailure(FailureType_Failure_Other, _("Block data invalid"));
        layoutHome();
        return;
    }

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
                return;
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
                return;
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
                return;
            }
        }
    }

    // Sign hash and return the signature
    node = fsm_getDerivedNode(coin->curve_name, msg->address_n, msg->address_n_count, NULL);
    if (!node) return;

    memset(resp->signature.bytes, 0, sizeof(resp->signature.bytes));
    _Static_assert(sizeof(resp->signature.bytes) >= 64, "Signature field not large enough");
    resp->has_signature = true;
    resp->signature.size = 64;
    hdnode_sign_digest(node, block_hash, resp->signature.bytes, NULL, NULL);
    memzero(node, sizeof(*node));
    node = NULL;
    
    _Static_assert(sizeof(resp->block_hash.bytes) >= 32, "Block hash field not large enough");
    resp->has_block_hash = true;
    resp->block_hash.size = sizeof(block_hash);
    memcpy(resp->block_hash.bytes, block_hash, sizeof(block_hash));

    msg_write(MessageType_MessageType_NanoSignedTx, resp);
    layoutHome();
}
