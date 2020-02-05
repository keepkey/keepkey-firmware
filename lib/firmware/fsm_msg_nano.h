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
        memzero(node, sizeof(*node));
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
                memzero(node, sizeof(*node));
                fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
                layoutHome();
                return;
            }
        }

        if(!confirm_nano_address(node_str, address)) {
            memzero(node, sizeof(*node));
            fsm_sendFailure(FailureType_Failure_ActionCancelled, "Show address cancelled");
            layoutHome();
            return;
        }
    }

    resp->has_address = true;
    strlcpy(resp->address, address, sizeof(resp->address));
    memzero(node, sizeof(*node));
    msg_write(MessageType_MessageType_NanoAddress, resp);
    layoutHome();
}

void fsm_msgNanoSignTx(NanoSignTx *msg)
{
    CHECK_INITIALIZED

    CHECK_PIN

    const char *coin_name = msg->has_coin_name ? msg->coin_name : "Nano";
    const CoinType *coin = fsm_getCoin(true, coin_name);
    if (!coin) return;

    HDNode *node = fsm_getDerivedNode(coin->curve_name, msg->address_n,
                                      msg->address_n_count, NULL);
    if (!node) return;
    hdnode_fill_public_key(node);

    if (!nano_signingInit(msg, node, coin)) {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_Other, _("Block data invalid"));
        layoutHome();
        return;
    }

    memzero(node, sizeof(*node));

    if (!nano_parentHash(msg)) {
        nano_signingAbort();
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_Other, _("Parent block data invalid"));
        layoutHome();
        return;
    }

    HDNode *recip = NULL;
    if (msg->link_recipient_n_count > 0) {
        recip = fsm_getDerivedNode(coin->curve_name,
                                   msg->link_recipient_n,
                                   msg->link_recipient_n_count,
                                   NULL);
        if (!recip) {
            nano_signingAbort();
            memzero(node, sizeof(*node));
            fsm_sendFailure(FailureType_Failure_Other, _("Could not derive node"));
            layoutHome();
            return;
        }
        hdnode_fill_public_key(recip);
    }

    if (!nano_currentHash(msg, recip)) {
        nano_signingAbort();
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_Other, _("Current block data invalid"));
        layoutHome();
        return;
    }

    if (recip) {
        memzero(recip, sizeof(*recip));
        recip = NULL;
    }

    if (!nano_sanityCheck(msg)) {
        nano_signingAbort();
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_Other, _("Failed sanity check"));
        layoutHome();
        return;
    }

    RESP_INIT(NanoSignedTx);

    memset(resp->signature.bytes, 0, sizeof(resp->signature.bytes));
    _Static_assert(sizeof(resp->signature.bytes) >= 64, "Signature field not large enough");
    _Static_assert(sizeof(resp->block_hash.bytes) >= 32, "Block hash field not large enough");

    // Sign hash and return the signature
    node = fsm_getDerivedNode(coin->curve_name, msg->address_n, msg->address_n_count, NULL);
    if (!node) {
        nano_signingAbort();
        fsm_sendFailure(FailureType_Failure_Other, _("Could not derive node"));
        layoutHome();
        return;
    }

    if (!nano_signTx(msg, node, resp)) {
        memzero(node, sizeof(*node));
        return;
    }

    memzero(node, sizeof(*node));

    msg_write(MessageType_MessageType_NanoSignedTx, resp);
    layoutHome();
}
