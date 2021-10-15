
void fsm_msgOsmosisGetAddress(const OsmosisGetAddress *msg) {
  RESP_INIT(OsmosisAddress);

  CHECK_INITIALIZED

  CHECK_PIN

  const CoinType *coin = fsm_getCoin(true, "Osmosis");
  if (!coin) {
    return;
  }
  HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  char mainnet[] = "osmo";
  char testnet[] = "tosmo";
  char *pfix;

  if (!node) {
    return;
  }

  hdnode_fill_public_key(node);

  pfix = mainnet;
  if (msg->has_testnet && msg->testnet) {
    pfix = testnet;
  }

  if (!tendermint_getAddress(node, pfix, resp->address)) {
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
  msg_write(MessageType_MessageType_OsmosisAddress, resp);
  layoutHome();
}

void fsm_msgOsmosisSignTx(const OsmosisSignTx *msg) {
  CHECK_INITIALIZED
  CHECK_PIN

  if (!msg->has_account_number || !msg->has_chain_id || !msg->has_fee_amount ||
      !msg->has_gas || !msg->has_sequence) {
    osmosis_signAbort();
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

  RESP_INIT(OsmosisMsgRequest);

  if (!osmosis_signTxInit(node, msg)) {
    osmosis_signAbort();
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Failed to initialize transaction signing"));
    layoutHome();
    return;
  }

  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_OsmosisMsgRequest, resp);
  layoutHome();
}

void fsm_msgOsmosisMsgAck(const OsmosisMsgAck *msg) {
  // Confirm transaction basics
  // supports only 1 message ack
  CHECK_PARAM(osmosis_signingIsInited(), "Signing not in progress");
  if (msg->has_send && msg->send.has_to_address && msg->send.has_amount) {
    // pass
  } else if (msg->has_delegate && msg->delegate.has_delegator_address &&
             msg->delegate.has_validator_address && msg->delegate.has_amount) {
    // pass
  } else if (msg->has_undelegate && msg->undelegate.has_delegator_address &&
             msg->undelegate.has_validator_address &&
             msg->undelegate.has_amount) {
    // pass
  } else if (msg->has_claim && msg->claim.has_delegator_address &&
             msg->claim.has_validator_address && msg->claim.has_amount) {
    // pass
  } else {
    osmosis_signAbort();
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Invalid Osmosis Message Type"));
    layoutHome();
    return;
  }

  const CoinType *coin = fsm_getCoin(true, "Osmosis");
  if (!coin) {
    return;
  }

  const OsmosisSignTx *sign_tx = osmosis_getOsmosisSignTx();

  if (msg->has_send) {
    switch (msg->send.address_type) {
      case OutputAddressType_TRANSFER:
      default: {
        char amount_str[32];
        bn_format_uint64(msg->send.amount, NULL, " OSMO", 8, 0, false,
                         amount_str, sizeof(amount_str));
        if (!confirm_transaction_output(
                ButtonRequestType_ButtonRequest_ConfirmOutput, amount_str,
                msg->send.to_address)) {
          osmosis_signAbort();
          fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
          layoutHome();
          return;
        }

        break;
      }
    }
    if (!osmosis_signTxUpdateMsgSend(msg->send.amount,
                                       msg->send.to_address)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Failed to include send message in transaction");
      layoutHome();
      return;
    }

  } else if (msg->has_delegate) {
    char amount_str[32];
    bn_format_uint64(msg->delegate.amount, NULL, " OSMO", 8, 0, false,
                     amount_str, sizeof(amount_str));

    if(!confirm_with_custom_layout(
      &layout_standard_notification,
      ButtonRequestType_ButtonRequest_SignExchange, "Delegate",
      "Delegate %s to %s?", amount_str, msg->delegate.validator_address)){
          osmosis_signAbort();
          fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
          layoutHome();
          return;
      }

    if (!osmosis_signTxUpdateMsgDelegate(&(msg->delegate))) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Failed to include delegate message in transaction");
      layoutHome();
      return;
    }
  } else if (msg->has_undelegate) {
    char amount_str[32];
    bn_format_uint64(msg->undelegate.amount, NULL, " OSMO", 8, 0, false,
                     amount_str, sizeof(amount_str));

    if(!confirm_with_custom_layout(
      &layout_standard_notification,
      ButtonRequestType_ButtonRequest_SignExchange, "Undelegate",
      "Undelegate %s from %s?", amount_str, msg->undelegate.validator_address)){
          osmosis_signAbort();
          fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
          layoutHome();
          return;
      }

    if (!osmosis_signTxUpdateMsgUndelegate(&(msg->undelegate))) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Failed to include undelegate message in transaction");
      layoutHome();
      return;
    }
  } else if (msg->has_claim) {
    char amount_str[32];
    bn_format_uint64(msg->claim.amount, NULL, " OSMO", 8, 0, false, amount_str,
                     sizeof(amount_str));
    if(!confirm_with_custom_layout(
      &layout_standard_notification,
      ButtonRequestType_ButtonRequest_SignExchange, "Claim",
      "Claim %s from %s?", amount_str, msg->claim.validator_address)){
          osmosis_signAbort();
          fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
          layoutHome();
          return;
      }

    if (!osmosis_signTxUpdateMsgClaim(&(msg->claim))) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Failed to include claim message in transaction");
      layoutHome();
      return;
    }
  }

  if (!osmosis_signingIsFinished()) {
    RESP_INIT(OsmosisMsgRequest);
    msg_write(MessageType_MessageType_OsmosisMsgRequest, resp);
    return;
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

  RESP_INIT(OsmosisSignedTx);

  if (!osmosis_signTxFinalize(resp->public_key.bytes, resp->signature.bytes)) {
    osmosis_signAbort();
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    "Failed to finalize signature");
    layoutHome();
    return;
  }

  resp->public_key.size = 33;
  resp->has_public_key = true;
  resp->signature.size = 64;
  resp->has_signature = true;
  osmosis_signAbort();
  layoutHome();
  msg_write(MessageType_MessageType_OsmosisSignedTx, resp);
}