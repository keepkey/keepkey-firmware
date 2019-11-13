
void fsm_msgCosmosGetAddress(const CosmosGetAddress *msg)
{
    RESP_INIT(CosmosAddress);

    CHECK_INITIALIZED

    CHECK_PIN

    const char *coin_name = "Cosmos";
    const CoinType *coin = fsm_getCoin(true, coin_name);
    if (!coin) { return; }
    HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n, msg->address_n_count, NULL);
    if (!node) { return; }

    hdnode_fill_public_key(node);

    if (!cosmos_getAddress(node, resp->address)) {
        fsm_sendFailure(FailureType_Failure_Other, _("Can't encode address"));
        layoutHome();
        return;
    }

    if (msg->has_show_display && msg->show_display) {
        char node_str[NODE_STRING_LENGTH];
        if (!bip32_node_to_string(node_str, sizeof(node_str), coin, msg->address_n,
                                  msg->address_n_count, /*whole_account=*/false,
                                  /*show_addridx=*/true) &&
            !bip32_path_to_string(node_str, sizeof(node_str),
                                  msg->address_n, msg->address_n_count)) {
            memset(node_str, 0, sizeof(node_str));
        }
        bool mismatch = cosmos_path_mismatched(coin, msg->address_n, msg->address_n_count);

        if (mismatch) {
            if (!confirm(ButtonRequestType_ButtonRequest_Other, "WARNING", "Wrong address path for selected coin. Continue at your own risk!")) {
                fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
                layoutHome();
                return;
            }
        }

        if(!confirm_address(node_str, resp->address)) {
            fsm_sendFailure(FailureType_Failure_ActionCancelled, "Show address cancelled");
            layoutHome();
            return;
        }
    }

    resp->has_address = true;

    layoutHome();
    msg_write(MessageType_MessageType_CosmosAddress, resp);
}

void fsm_msgCosmosSignTx(const CosmosSignTx *msg)
{
    CHECK_INITIALIZED
    CHECK_PIN

    const char *coin_name = "Cosmos";
    const CoinType *coin = fsm_getCoin(true, coin_name);
    if (!coin) { return; }
    HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n, msg->address_n_count, NULL);
    if (!node)
    {
        return;
    }
    hdnode_fill_public_key(node);

    char node_str[NODE_STRING_LENGTH];
    if (!bip32_node_to_string(node_str, sizeof(node_str), coin, msg->address_n,
                              msg->address_n_count, /*whole_account=*/false,
                              /*show_addridx=*/true) &&
        !bip32_path_to_string(node_str, sizeof(node_str),
                              msg->address_n, msg->address_n_count)) {
        memset(node_str, 0, sizeof(node_str));
    }

    // Confirm transaction basics
    if (!confirm(ButtonRequestType_ButtonRequest_ProtectCall, _("Confirm Main Details"), "From: %s\nTo: %s\nAmount: %f ATOM", node_str, msg->to_address, (float)msg->amount * 1E-6))
    {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        layoutHome();
        return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_ProtectCall, _("Confirm Fee Details"), "Fee: %" PRIu32 " uATOM\nGas: %" PRIu32 "", msg->fee_amount, msg->gas))
    {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        layoutHome();
        return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_ProtectCall, _("Confirm Aux Details"), "Memo: \"%s\"\nChain ID: %s\nAccount #: %" PRIu64 "", msg->memo, msg->chain_id, msg->account_number))
    {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        layoutHome();
        return;
    }

    RESP_INIT(CosmosSignedTx);

    if (!cosmos_signTx(node->private_key,
                       msg->account_number,
                       msg->chain_id,
                       strlen(msg->chain_id),
                       msg->fee_amount,
                       msg->gas,
                       msg->memo,
                       strlen(msg->memo),
                       msg->amount,
                       msg->from_address,
                       msg->to_address,
                       msg->sequence,
                       resp->signature.bytes))
    {
        fsm_sendFailure(FailureType_Failure_FirmwareError,
                        _("Failed to sign transaction"));
        layoutHome();
        return;
    }
    resp->signature.size = 64;
    resp->has_signature = true;

    memcpy(resp->public_key.bytes, node->public_key, 33);
    resp->public_key.size = 33;
    resp->has_public_key = true;

    layoutHome();
    msg_write(MessageType_MessageType_CosmosSignedTx, resp);
}
