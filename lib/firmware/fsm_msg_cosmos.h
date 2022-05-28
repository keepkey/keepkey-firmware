
void fsm_msgCosmosGetAddress(const CosmosGetAddress *msg) {
  RESP_INIT(CosmosAddress);

  CHECK_INITIALIZED

  CHECK_PIN

  const CoinType *coin = fsm_getCoin(true, "Cosmos");
  if (!coin) {
    return;
  }
  HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) {
    return;
  }

  hdnode_fill_public_key(node);

  if (!tendermint_getAddress(node, "cosmos", resp->address)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Can't encode address"));
    layoutHome();
    return;
  }

  if (msg->has_show_display && msg->show_display) {
    char node_str[NODE_STRING_LENGTH];
    if (!bip32_node_to_string(node_str, sizeof(node_str), coin, msg->address_n,
                              msg->address_n_count, /*whole_account=*/false,
                              /*show_addridx=*/false) &&
        !bip32_path_to_string(node_str, sizeof(node_str), msg->address_n,
                              msg->address_n_count)) {
      memset(node_str, 0, sizeof(node_str));
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_FirmwareError,
                      _("Can't create Bip32 Path String"));
      layoutHome();
    }

    bool mismatch =
        tendermint_pathMismatched(coin, msg->address_n, msg->address_n_count);
    if (mismatch) {
      if (!confirm(ButtonRequestType_ButtonRequest_Other, "WARNING",
                   "Wrong address path for selected coin. Continue at your own "
                   "risk!")) {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        layoutHome();
        return;
      }
    }

    if (!confirm_ethereum_address(node_str, resp->address)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      "Show address cancelled");
      layoutHome();
      return;
    }
  }

  resp->has_address = true;

  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_CosmosAddress, resp);
  layoutHome();
}

void fsm_msgCosmosSignTx(const CosmosSignTx *msg) {
  CHECK_INITIALIZED
  CHECK_PIN

  if (!msg->has_account_number || !msg->has_chain_id || !msg->has_fee_amount ||
      !msg->has_gas || !msg->has_sequence) {
    tendermint_signAbort();
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    "Missing Fields On Message");
    layoutHome();
    return;
  }

  HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) {
    return;
  }

  hdnode_fill_public_key(node);

  RESP_INIT(CosmosMsgRequest);

  if (!tendermint_signTxInit(node, (void *)msg, sizeof(CosmosSignTx),
                             "uatom")) {
    tendermint_signAbort();
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Failed to initialize transaction signing"));
    layoutHome();
    return;
  }

  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_CosmosMsgRequest, resp);
  layoutHome();
}

void fsm_msgCosmosMsgAck(const CosmosMsgAck *msg) {
  // Confirm transaction basics
  CHECK_PARAM(tendermint_signingIsInited(), "Signing not in progress");

  const CoinType *coin = fsm_getCoin(true, "Cosmos");
  if (!coin) {
    return;
  }

  const CosmosSignTx *sign_tx = (CosmosSignTx *)tendermint_getSignTx();

  if (msg->has_send) {
    if (!msg->send.has_to_address || !msg->send.has_amount) {
      tendermint_signAbort();
      fsm_sendFailure(FailureType_Failure_FirmwareError,
                      _("Message is missing required parameters"));
      layoutHome();
      return;
    }
    switch (msg->send.address_type) {
      case OutputAddressType_EXCHANGE: {
        HDNode *root_node = fsm_getDerivedNode(SECP256K1_NAME, 0, 0, NULL);
        if (!root_node) {
          tendermint_signAbort();
          fsm_sendFailure(FailureType_Failure_FirmwareError, NULL);
          layoutHome();
          return;
        }

        int ret = run_policy_compile_output(coin, root_node, (void *)&msg->send,
                                            (void *)NULL, true);
        if (ret < TXOUT_OK) {
          memzero((void *)root_node, sizeof(*root_node));
          tendermint_signAbort();
          send_fsm_co_error_message(ret);
          layoutHome();
          return;
        }

        break;
      }
      case OutputAddressType_TRANSFER:
      default: {
        char amount_str[32];
        bn_format_uint64(msg->send.amount, NULL, " ATOM", 6, 0, false,
                         amount_str, sizeof(amount_str));
        if (!confirm_transaction_output(
                ButtonRequestType_ButtonRequest_ConfirmOutput, amount_str,
                msg->send.to_address)) {
          tendermint_signAbort();
          fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
          layoutHome();
          return;
        }

        break;
      }
    }

    if (!tendermint_signTxUpdateMsgSend(msg->send.amount, msg->send.to_address,
                                        "cosmos", "uatom", "cosmos-sdk")) {
      tendermint_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Failed to include send message in transaction");
      layoutHome();
      return;
    }
  } else if (msg->has_delegate) {
    /** Confirm required transaction parameters exist */
    if (!msg->delegate.has_delegator_address ||
        !msg->delegate.has_validator_address || !msg->delegate.has_amount) {
      tendermint_signAbort();
      fsm_sendFailure(FailureType_Failure_FirmwareError,
                      _("Message is missing required parameters"));
      layoutHome();
      return;
    }
    /** Confirm transaction parameters on-screen */
    char amount_str[32];
    bn_format_uint64(msg->delegate.amount, NULL, " ATOM", 6, 0, false,
                     amount_str, sizeof(amount_str));

    if (!confirm_cosmos_address("Confirm delegator address",
                                msg->delegate.delegator_address)) {
      tendermint_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm_cosmos_address("Confirm validator address",
                                msg->delegate.validator_address)) {
      tendermint_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm_with_custom_layout(
            &layout_notification_no_title_bold,
            ButtonRequestType_ButtonRequest_ConfirmOutput, "", "Delegate %s?",
            amount_str)) {
      tendermint_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!tendermint_signTxUpdateMsgDelegate(
            msg->delegate.amount, msg->delegate.delegator_address,
            msg->delegate.validator_address, "cosmos", "uatom", "cosmos-sdk")) {
      tendermint_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Failed to include delegate message in transaction");
      layoutHome();
      return;
    }
  } else if (msg->has_undelegate) {
    /** Confirm required transaction parameters exist */
    if (!msg->undelegate.has_delegator_address ||
        !msg->undelegate.has_validator_address || !msg->undelegate.has_amount) {
      tendermint_signAbort();
      fsm_sendFailure(FailureType_Failure_FirmwareError,
                      _("Message is missing required parameters"));
      layoutHome();
      return;
    }
    /** Confirm transaction parameters on-screen */
    char amount_str[32];
    bn_format_uint64(msg->undelegate.amount, NULL, " ATOM", 6, 0, false,
                     amount_str, sizeof(amount_str));

    if (!confirm_cosmos_address("Confirm delegator address",
                                msg->undelegate.delegator_address)) {
      tendermint_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm_cosmos_address("Confirm validator address",
                                msg->undelegate.validator_address)) {
      tendermint_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm_with_custom_layout(
            &layout_notification_no_title_bold,
            ButtonRequestType_ButtonRequest_ConfirmOutput, "", "Undelegate %s?",
            amount_str)) {
      tendermint_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!tendermint_signTxUpdateMsgUndelegate(
            msg->undelegate.amount, msg->undelegate.delegator_address,
            msg->undelegate.validator_address, "cosmos", "uatom",
            "cosmos-sdk")) {
      tendermint_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Failed to include undelegate message in transaction");
      layoutHome();
      return;
    }
  } else if (msg->has_redelegate) {
    /** Confirm required transaction parameters exist */
    if (!msg->redelegate.has_delegator_address ||
        !msg->redelegate.has_validator_src_address ||
        !msg->redelegate.has_validator_dst_address ||
        !msg->redelegate.has_amount) {
      tendermint_signAbort();
      fsm_sendFailure(FailureType_Failure_FirmwareError,
                      _("Message is missing required parameters"));
      layoutHome();
      return;
    }
    /** Confirm transaction parameters on-screen */
    char amount_str[32];
    bn_format_uint64(msg->redelegate.amount, NULL, " ATOM", 6, 0, false,
                     amount_str, sizeof(amount_str));

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Redelegate",
                 "Redelegate %s?", amount_str)) {
      tendermint_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm_cosmos_address("Delegator address",
                                msg->redelegate.delegator_address)) {
      tendermint_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm_cosmos_address("Validator source address",
                                msg->redelegate.validator_src_address)) {
      tendermint_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm_cosmos_address("Validator dest. address",
                                msg->redelegate.validator_dst_address)) {
      tendermint_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!tendermint_signTxUpdateMsgRedelegate(
            msg->redelegate.amount, msg->redelegate.delegator_address,
            msg->redelegate.validator_src_address,
            msg->redelegate.validator_dst_address, "cosmos", "uatom",
            "cosmos-sdk")) {
      tendermint_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Failed to include redelegate message in transaction");
      layoutHome();
      return;
    }
  } else if (msg->has_rewards) {
    /** Confirm required transaction parameters exist */
    if (!msg->rewards.has_delegator_address ||
        !msg->rewards.has_validator_address) {
      tendermint_signAbort();
      fsm_sendFailure(FailureType_Failure_FirmwareError,
                      _("Message is missing required parameters"));
      layoutHome();
      return;
    }

    if (msg->rewards.has_amount) {
      /** Confirm transaction parameters on-screen */
      char amount_str[32];
      bn_format_uint64(msg->rewards.amount, NULL, " ATOM", 6, 0, false,
                      amount_str, sizeof(amount_str));

      if (!confirm(ButtonRequestType_ButtonRequest_Other, "Claim Rewards",
                  "Claim %s?", amount_str)) {
        tendermint_signAbort();
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        layoutHome();
        return;
      }
    } else {
      if (!confirm(ButtonRequestType_ButtonRequest_Other, "Claim Rewards",
                  "Claim all available rewards?")) {
        tendermint_signAbort();
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        layoutHome();
        return;
      }
    }

    if (!confirm_cosmos_address("Confirm delegator address",
                                msg->rewards.delegator_address)) {
      tendermint_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm_cosmos_address("Confirm validator address",
                                msg->rewards.validator_address)) {
      tendermint_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!tendermint_signTxUpdateMsgRewards(
            msg->rewards.has_amount ? &msg->rewards.amount : NULL,
            msg->rewards.delegator_address, msg->rewards.validator_address,
            "cosmos", "uatom", "cosmos-sdk")) {
      tendermint_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Failed to include rewards message in transaction");
      layoutHome();
      return;
    }
  } else if (msg->has_ibc_transfer) {
    /** Confirm required transaction parameters exist */
    if (!msg->ibc_transfer.has_sender ||
        !msg->ibc_transfer.has_source_channel ||
        !msg->ibc_transfer.has_source_port ||
        !msg->ibc_transfer.has_revision_height ||
        !msg->ibc_transfer.has_revision_number ||
        !msg->ibc_transfer.has_denom) {
      tendermint_signAbort();
      fsm_sendFailure(FailureType_Failure_FirmwareError,
                      _("Message is missing required parameters"));
      layoutHome();
      return;
    }
    /** Confirm transaction parameters on-screen */
    char amount_str[32];
    bn_format_uint64(msg->ibc_transfer.amount, NULL, " ATOM", 6, 0, false,
                     amount_str, sizeof(amount_str));

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "IBC Transfer",
                 "Transfer %s to %s?", amount_str, msg->ibc_transfer.sender)) {
      tendermint_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other,
                 "Confirm Source Channel", "%s",
                 msg->ibc_transfer.source_channel)) {
      tendermint_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Confirm Source Port",
                 "%s", msg->ibc_transfer.source_port)) {
      tendermint_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other,
                 "Confirm Revision Height", "%s",
                 msg->ibc_transfer.revision_height)) {
      tendermint_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other,
                 "Confirm Revision Number", "%s",
                 msg->ibc_transfer.revision_number)) {
      tendermint_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!tendermint_signTxUpdateMsgIBCTransfer(
            msg->ibc_transfer.amount, msg->ibc_transfer.sender,
            msg->ibc_transfer.receiver, msg->ibc_transfer.source_channel,
            msg->ibc_transfer.source_port, msg->ibc_transfer.revision_number,
            msg->ibc_transfer.revision_height, "cosmos", "uatom",
            "cosmos-sdk")) {
      tendermint_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Failed to include send message in transaction");
      layoutHome();
      return;
    }
  } else {
    tendermint_signAbort();
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Invalid Cosmos message type"));
    layoutHome();
    return;
  }

  if (!tendermint_signingIsFinished()) {
    RESP_INIT(CosmosMsgRequest);
    msg_write(MessageType_MessageType_CosmosMsgRequest, resp);
    return;
  }

  if (sign_tx->has_memo && (strlen(sign_tx->memo) > 0)) {
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmMemo, _("Memo"), "%s",
                 sign_tx->memo)) {
      tendermint_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
  }

  char node_str[NODE_STRING_LENGTH];
  if (!bip32_node_to_string(node_str, sizeof(node_str), coin,
                            sign_tx->address_n, sign_tx->address_n_count,
                            /*whole_account=*/false,
                            /*show_addridx=*/false) &&
      !bip32_path_to_string(node_str, sizeof(node_str), sign_tx->address_n,
                            sign_tx->address_n_count)) {
    memset(node_str, 0, sizeof(node_str));
  }

  if (!confirm(ButtonRequestType_ButtonRequest_SignTx, node_str,
               "Sign this Cosmos transaction on %s? "
               "It includes a fee of %" PRIu32 " uATOM and %" PRIu32 " gas.",
               sign_tx->chain_id, sign_tx->fee_amount, sign_tx->gas)) {
    tendermint_signAbort();
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  RESP_INIT(CosmosSignedTx);

  if (!tendermint_signTxFinalize(resp->public_key.bytes,
                                 resp->signature.bytes)) {
    tendermint_signAbort();
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    "Failed to finalize signature");
    layoutHome();
    return;
  }

  resp->public_key.size = 33;
  resp->has_public_key = true;
  resp->signature.size = 64;
  resp->has_signature = true;
  tendermint_signAbort();
  layoutHome();
  msg_write(MessageType_MessageType_CosmosSignedTx, resp);
}