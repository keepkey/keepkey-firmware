
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
        fsm_sendFailure(FailureType_Failure_FirmwareError, _("Can't encode address"));
        layoutHome();
        return;
    }

    if (msg->has_show_display && msg->show_display) {
        char node_str[NODE_STRING_LENGTH];
        if (!bip32_node_to_string(node_str, sizeof(node_str), coin, msg->address_n,
                                  msg->address_n_count, /*whole_account=*/true,
                                  /*show_addridx=*/false) &&
            !bip32_path_to_string(node_str, sizeof(node_str),
                                  msg->address_n, msg->address_n_count)) {
            memset(node_str, 0, sizeof(node_str));
            fsm_sendFailure(FailureType_Failure_FirmwareError, _("Can't create Bip32 Path String"));
            layoutHome();
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

    if (!msg->has_account_number ||
        !msg->has_chain_id ||
        !msg->has_fee_amount ||
        !msg->has_gas ||
        !msg->has_sequence) {
        fsm_sendFailure(FailureType_Failure_SyntaxError, "Missing Fields On Message");
        layoutHome();
        return;
    }

    HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n, msg->address_n_count, NULL);
    if (!node) { return; }

    hdnode_fill_public_key(node);

    if (!confirm(ButtonRequestType_ButtonRequest_ProtectCall, _("Confirm Fee Details"), "Fee: %" PRIu32 " uATOM\nGas: %" PRIu32 "", msg->fee_amount, msg->gas))
    {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        layoutHome();
        return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_ProtectCall, _("Confirm Aux Details"), "Memo: \"%s\"\nChain ID: %s", msg->memo, msg->chain_id))
    {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        layoutHome();
        return;
    }

    RESP_INIT(CosmosMsgRequest);

    if (!cosmos_signTxInit(node,
                           msg->address_n,
                           msg->address_n_count,
                           msg->account_number,
                           msg->chain_id,
                           strlen(msg->chain_id),
                           msg->fee_amount,
                           msg->gas,
                           msg->has_memo ? msg->memo : "",
                           msg->has_memo ? strlen(msg->memo) : 0,
                           msg->sequence,
                           msg->msg_count))
    {
        fsm_sendFailure(FailureType_Failure_FirmwareError,
                        _("Failed to initialize transaction signing"));
        layoutHome();
        return;
    }



    layoutHome();
    msg_write(MessageType_MessageType_CosmosMsgRequest, resp);
}

void fsm_msgCosmosMsgAck(const CosmosMsgAck* msg) {
    // Confirm transaction basics
    CHECK_PARAM(cosmos_signingIsInited(), "Must call CosmosSignTx to initiate signing");
    if (!msg->has_send || !msg->send.has_from_address || !msg->send.has_to_address || !msg->send.has_amount) {
        cosmos_signAbort();
        fsm_sendFailure(FailureType_Failure_FirmwareError,
                        _("Invalid Cosmos Message Type"));
        layoutHome();
        return;
    }

    const char *coin_name = "Cosmos";
    const CoinType *coin = fsm_getCoin(true, coin_name);
    if (!coin) { return; }

    uint32_t address_n[8];
    if(!cosmos_getAddressN(address_n, 8)) {
        cosmos_signAbort();
        fsm_sendFailure(FailureType_Failure_FirmwareError, "Failed to get derivation path");
        return;
    }
    size_t address_n_count = cosmos_getAddressNCount();
    char node_str[NODE_STRING_LENGTH];
    if (!bip32_node_to_string(node_str, sizeof(node_str), coin, address_n,
                              address_n_count, /*whole_account=*/false,
                              /*show_addridx=*/true) &&
        !bip32_path_to_string(node_str, sizeof(node_str),
                              address_n, address_n_count)) {
        memset(node_str, 0, sizeof(node_str));
    }

    if (!confirm(ButtonRequestType_ButtonRequest_ProtectCall, _("Confirm Send Details"), "From: %s\nTo: %s\nAmount: %f ATOM", node_str, msg->send.to_address, (float)msg->send.amount * 1E-6))
    {
        cosmos_signAbort();
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        layoutHome();
        return;
    }

    if(!cosmos_signTxUpdateMsgSend(msg->send.amount, msg->send.from_address, msg->send.to_address)) {
        cosmos_signAbort();
        fsm_sendFailure(FailureType_Failure_FirmwareError, "Failed to include send message in transaction");
        return;
    }

    if (!cosmos_signingIsFinished()) {
        RESP_INIT(CosmosMsgRequest);
        msg_write(MessageType_MessageType_CosmosMsgRequest, resp);
        return;
    }

    RESP_INIT(CosmosSignedTx);

    if(!cosmos_signTxFinalize(resp->public_key.bytes, resp->signature.bytes)) {
        fsm_sendFailure(FailureType_Failure_FirmwareError, "Failed to finalize signature");
        layoutHome();
        return;
    }

    resp->public_key.size = 33;
    resp->has_public_key = true;
    resp->signature.size = 64;
    resp->has_signature = true;
    layoutHome();
    msg_write(MessageType_MessageType_CosmosSignedTx, resp);
}