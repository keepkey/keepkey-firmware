
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
                                  msg->address_n_count, /*whole_account=*/false,
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
        cosmos_signAbort();
        fsm_sendFailure(FailureType_Failure_SyntaxError, "Missing Fields On Message");
        layoutHome();
        return;
    }

    HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n, msg->address_n_count, NULL);
    if (!node) { return; }

    hdnode_fill_public_key(node);



    RESP_INIT(CosmosMsgRequest);

    if (!cosmos_signTxInit(node, msg))
    {
        cosmos_signAbort();
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
    if (!msg->has_send || !msg->send.has_to_address || !msg->send.has_amount) {
        cosmos_signAbort();
        fsm_sendFailure(FailureType_Failure_FirmwareError,
                        _("Invalid Cosmos Message Type"));
        layoutHome();
        return;
    }

    const char *coin_name = "Cosmos";
    const CoinType *coin = fsm_getCoin(true, coin_name);
    if (!coin) { return; }

    const CosmosSignTx *sign_tx = cosmos_getCosmosSignTx();

    char amount_str[32];
    bn_format_uint64(msg->send.amount, NULL, " ATOM", 6, 0, false, amount_str, sizeof(amount_str));
    if (!confirm_transaction_output(
            ButtonRequestType_ButtonRequest_ConfirmOutput,
            amount_str, msg->send.to_address)) {
        cosmos_signAbort();
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        layoutHome();
        return;
    }

    if(!cosmos_signTxUpdateMsgSend(msg->send.amount, msg->send.to_address)) {
        cosmos_signAbort();
        fsm_sendFailure(FailureType_Failure_SyntaxError, "Failed to include send message in transaction");
        layoutHome();
        return;
    }

    if (!cosmos_signingIsFinished()) {
        RESP_INIT(CosmosMsgRequest);
        msg_write(MessageType_MessageType_CosmosMsgRequest, resp);
        return;
    }

    if (sign_tx->has_memo && !confirm(ButtonRequestType_ButtonRequest_ConfirmMemo, _("Memo"), "%s", sign_tx->memo))
    {
        cosmos_signAbort();
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        layoutHome();
        return;
    }

    char node_str[NODE_STRING_LENGTH];
    if (!bip32_node_to_string(node_str, sizeof(node_str), coin, sign_tx->address_n,
                              sign_tx->address_n_count, /*whole_account=*/false,
                              /*show_addridx=*/false) &&
        !bip32_path_to_string(node_str, sizeof(node_str),
                              sign_tx->address_n, sign_tx->address_n_count)) {
        memset(node_str, 0, sizeof(node_str));
    }

    if (!confirm(ButtonRequestType_ButtonRequest_SignTx, node_str,
                 "Sign this Cosmos transaction on %s? "
                 "It includes a fee of %" PRIu32 " uATOM and %" PRIu32 " gas.",
                 sign_tx->chain_id, sign_tx->fee_amount, sign_tx->gas))
    {
        cosmos_signAbort();
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        layoutHome();
        return;
    }

    RESP_INIT(CosmosSignedTx);

    if(!cosmos_signTxFinalize(resp->public_key.bytes, resp->signature.bytes)) {
        cosmos_signAbort();
        fsm_sendFailure(FailureType_Failure_SyntaxError, "Failed to finalize signature");
        layoutHome();
        return;
    }

    resp->public_key.size = 33;
    resp->has_public_key = true;
    resp->signature.size = 64;
    resp->has_signature = true;
    cosmos_signAbort();
    layoutHome();
    msg_write(MessageType_MessageType_CosmosSignedTx, resp);
}
