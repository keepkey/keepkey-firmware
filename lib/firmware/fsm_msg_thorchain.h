
void fsm_msgThorchainGetAddress(const ThorchainGetAddress *msg) {
  RESP_INIT(ThorchainAddress);

  CHECK_INITIALIZED

  CHECK_PIN

  const CoinType *coin = fsm_getCoin(true, "THORChain");
  if (!coin) {
    return;
  }
  HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  char mainnet[] = "thor";
  char testnet[] = "tthor";
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
  msg_write(MessageType_MessageType_ThorchainAddress, resp);
  layoutHome();
}

void fsm_msgThorchainSignTx(const ThorchainSignTx *msg) {
  CHECK_INITIALIZED
  CHECK_PIN

  if (!msg->has_account_number || !msg->has_chain_id || !msg->has_fee_amount ||
      !msg->has_gas || !msg->has_sequence) {
    thorchain_signAbort();
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

  RESP_INIT(ThorchainMsgRequest);

  if (!thorchain_signTxInit(node, msg)) {
    thorchain_signAbort();
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Failed to initialize transaction signing"));
    layoutHome();
    return;
  }

  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_ThorchainMsgRequest, resp);
  layoutHome();
}

void fsm_msgThorchainMsgAck(const ThorchainMsgAck *msg) {
  // Confirm transaction basics
  CHECK_PARAM(thorchain_signingIsInited(), "Signing not in progress");
  if (!msg->has_send || !msg->send.has_to_address || !msg->send.has_amount) {
    thorchain_signAbort();
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Invalid THORChain Message Type"));
    layoutHome();
    return;
  }

  const CoinType *coin = fsm_getCoin(true, "THORChain");
  if (!coin) {
    return;
  }

  const ThorchainSignTx *sign_tx = thorchain_getThorchainSignTx();

  switch (msg->send.address_type) {
    case OutputAddressType_EXCHANGE: {
      HDNode *root_node = fsm_getDerivedNode(SECP256K1_NAME, 0, 0, NULL);
      if (!root_node) {
        thorchain_signAbort();
        fsm_sendFailure(FailureType_Failure_FirmwareError, NULL);
        layoutHome();
        return;
      }

      int ret = run_policy_compile_output(coin, root_node, (void *)&msg->send,
                                          (void *)NULL, true);
      if (ret < TXOUT_OK) {
        memzero((void *)root_node, sizeof(*root_node));
        thorchain_signAbort();
        send_fsm_co_error_message(ret);
        layoutHome();
        return;
      }

      break;
    }
    case OutputAddressType_TRANSFER:
    default: {
      char amount_str[32];
      bn_format_uint64(msg->send.amount, NULL, " RUNE", 8, 0, false, amount_str,
                       sizeof(amount_str));
      if (!confirm_transaction_output(
              ButtonRequestType_ButtonRequest_ConfirmOutput, amount_str,
              msg->send.to_address)) {
        thorchain_signAbort();
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        layoutHome();
        return;
      }

      break;
    }
  }

  if (!thorchain_signTxUpdateMsgSend(msg->send.amount, msg->send.to_address)) {
    thorchain_signAbort();
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    "Failed to include send message in transaction");
    layoutHome();
    return;
  }

  if (!thorchain_signingIsFinished()) {
    RESP_INIT(ThorchainMsgRequest);
    msg_write(MessageType_MessageType_ThorchainMsgRequest, resp);
    return;
  }

  if (sign_tx->has_memo) {
    // See if we can parse the memo
    if (!thorchain_parseConfirmMemo(sign_tx->memo, sizeof(sign_tx->memo))) {
      // Memo not recognizable, ask to confirm it
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmMemo, _("Memo"), "%s", sign_tx->memo)) {
        thorchain_signAbort();
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        layoutHome();
        return;
      }
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
               "Sign this THORChain transaction on %s? "
               "It includes a fee of %" PRIu32 " RUNE and %" PRIu32 " gas.",
               sign_tx->chain_id, sign_tx->fee_amount, sign_tx->gas)) {
    thorchain_signAbort();
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  RESP_INIT(ThorchainSignedTx);

  if (!thorchain_signTxFinalize(resp->public_key.bytes, resp->signature.bytes)) {
    thorchain_signAbort();
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    "Failed to finalize signature");
    layoutHome();
    return;
  }

  resp->public_key.size = 33;
  resp->has_public_key = true;
  resp->signature.size = 64;
  resp->has_signature = true;
  thorchain_signAbort();
  layoutHome();
  msg_write(MessageType_MessageType_ThorchainSignedTx, resp);
}
