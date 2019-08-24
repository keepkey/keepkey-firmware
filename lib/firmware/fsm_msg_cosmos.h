

//void fsm_msgCosmosSignTx(CosmosSignTx *msg)
//{
//    CHECK_INITIALIZED
//
//            CHECK_PIN
//
//    bool needs_confirm = true;
//    int msg_result = process_cosmos_msg(msg, &needs_confirm);
//
//    if (msg_result < TXOUT_OK) {
//        cosmos_signing_abort();
//        send_fsm_co_error_message(msg_result);
//        layoutHome();
//        return;
//    }
//
//    const HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n, msg->address_n_count, NULL);
//    if (!node) return;
//
//    cosmos_signing_init(msg, node, needs_confirm);
//}

//void fsm_msgCosmosTxAck(CosmosTxAck *msg)
//{
//    cosmos_signing_txack(msg);
//}

//void fsm_msgCosmosGetAddress(CosmosGetAddress *msg)
//{
//    RESP_INIT(Address);
//
//    CHECK_INITIALIZED
//
//            CHECK_PIN
//
//    const CoinType *coin = fsm_getCoin(msg->has_coin_name, msg->coin_name);
//    if (!coin) return;
//    HDNode *node = fsm_getDerivedNode(coin->curve_name, msg->address_n, msg->address_n_count, NULL);
//    if (!node) return;
//    hdnode_fill_public_key(node);
//
//    char address[MAX_ADDR_SIZE];
//    if (!compute_address(coin, msg->script_type, node, msg->has_multisig, &msg->multisig, address)) {
//        fsm_sendFailure(FailureType_Failure_Other, _("Can't encode address"));
//        layoutHome();
//        return;
//    }
//
//    if (msg->has_show_display && msg->show_display) {
//        char node_str[NODE_STRING_LENGTH];
//        if (msg->has_multisig) {
//            snprintf(node_str, sizeof(node_str), "Multisig (%" PRIu32 " of %" PRIu32 ")",
//                    msg->multisig.m, (uint32_t)msg->multisig.pubkeys_count);
//        } else {
//            if (!bip32_node_to_string(node_str, sizeof(node_str), coin, msg->address_n,
//                                      msg->address_n_count, /*whole_account=*/false,
//                    /*show_addridx=*/true) &&
//                !bip32_path_to_string(node_str, sizeof(node_str),
//                                      msg->address_n, msg->address_n_count)) {
//                memset(node_str, 0, sizeof(node_str));
//            }
//        }
//
//        bool mismatch = path_mismatched(coin, msg);
//
//        size_t prefix_len = coin->has_cashaddr_prefix
//                            ? strlen(coin->cashaddr_prefix) + 1
//                            : 0;
//
//        if(!confirm_address(node_str, address + prefix_len))
//        {
//            fsm_sendFailure(FailureType_Failure_ActionCancelled, "Show address cancelled");
//            layoutHome();
//            return;
//        }
//    }
//
//    strlcpy(resp->address, address, sizeof(resp->address));
//    msg_write(MessageType_MessageType_Address, resp);
//    layoutHome();
//}


